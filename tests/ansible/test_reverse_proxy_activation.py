"""Real-filesystem recovery tests; only host commands and HTTP are substituted."""

import fcntl
import hashlib
import importlib.util
import http.server
import json
import os
from pathlib import Path
import socket
import socketserver
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load_activation():
    spec = importlib.util.spec_from_file_location("proxy_activation", ROOT / "roles/reverse_proxy/files/activate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HostCommands:
    """Model Caddy's atomic load boundary and a running host without root access."""

    def __init__(self, module, root, config):
        self.module, self.root, self.loaded = module, root, config
        self.active = True
        self.fail_reload = False
        self.reloads = 0
        self.invalid = False
        self.drift_after_reload = False
        self.ss = b""

    def run(self, command):
        if command[:2] == ["/usr/bin/systemctl", "is-active"]:
            if not self.active:
                raise self.module.ActivationError("service inactive")
            return b"active\n"
        if command[:2] == ["/usr/bin/systemctl", "show"]:
            return b"1234\n"
        if command[0] == "ss":
            if self.ss is not None:
                return self.ss
            listeners = set()
            for server in self.loaded.get("apps", {}).get("http", {}).get("servers", {}).values():
                listeners.update(server.get("listen", []))
            return "".join('tcp LISTEN 0 4096 ' + listener +
                           ' 0.0.0.0:* users:(("caddy",pid=1234,fd=9))\n'
                           for listener in sorted(listeners)).encode()
        if command[:4] != ["/usr/sbin/runuser", "-u", "caddy", "--"]:
            raise AssertionError(command)
        caddy = command[4:]
        if caddy[0] != "/usr/bin/caddy":
            raise AssertionError(command)
        action = caddy[1]
        path = Path(caddy[caddy.index("--config") + 1])
        if action == "adapt":
            return path.read_bytes()
        if action == "validate":
            if self.invalid:
                raise self.module.ActivationError("candidate validation failed")
            return b""
        if action == "reload":
            if "--force" not in caddy or caddy[caddy.index("--address") + 1] != "unix//run/caddy/admin.sock":
                raise AssertionError(command)
            self.reloads += 1
            if self.fail_reload:
                self.fail_reload = False
                raise self.module.ActivationError("reload failed")
            self.loaded = json.loads(path.read_bytes())
            if self.drift_after_reload and self.reloads == 1:
                self.loaded = {"unexpected": True}
            return b""
        raise AssertionError(command)

    def configuration(self, path):
        return self.loaded


class ActivationFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_activation()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        for relative, mode in (("etc/caddy", 0o750), ("etc/caddy/tls", 0o750),
                               ("var/lib/homelab-reverse-proxy", 0o700), ("run/lock", 0o755),
                               ("run/caddy", 0o700)):
            path = self.root / relative
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(mode)
        self.old = {"admin": {"listen": "unix//run/caddy/admin.sock", "config": {"persist": False}}}
        self.new = dict(self.old, logging={"logs": {"default": {"level": "WARN"}}})
        self.boot = self.root / "etc/caddy/Caddyfile"
        self.admin = self.root / "etc/caddy/Caddyfile.admin"
        self.candidate = self.root / "etc/caddy/Caddyfile.candidate"
        self.state = self.root / "var/lib/homelab-reverse-proxy"
        self.write(self.boot, json.dumps(self.old))
        self.write(self.admin, json.dumps(self.old))
        self.write(self.candidate, json.dumps(self.new))
        self.write(self.root / "run/lock/homelab-reverse-proxy.lock", "", 0o600)
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.bind(str(self.root / "run/caddy/admin.sock"))
        self.addCleanup(self.socket.close)
        (self.root / "run/caddy/admin.sock").chmod(0o700)
        self.commands = HostCommands(self.module, self.root, self.old)
        self.activation = self.module.Activator(self.root, self.commands,
                                              (os.getuid(), os.getgid(), os.getuid(), os.getgid()))

    def write(self, path, text, mode=0o640):
        path.write_text(text)
        path.chmod(mode)

    def pending(self):
        old = self.boot.read_bytes()
        self.write(self.state / "last-good", old.decode(), 0o600)
        self.write(self.state / "pending", json.dumps({"previous": hashlib.sha256(old).hexdigest(),
                   "candidate": hashlib.sha256(self.candidate.read_bytes()).hexdigest()}), 0o600)
        self.write(self.boot, self.candidate.read_text())



class ActivationTests(ActivationFixture):
    def test_success_commits_boot_and_loaded_configuration(self):
        self.assertEqual(self.activation.apply(), "changed")
        self.assertEqual(json.loads(self.boot.read_bytes()), self.new)
        self.assertEqual(self.commands.loaded, self.new)
        self.assertFalse((self.state / "pending").exists())
        self.assertEqual(self.boot.stat().st_mode & 0o777, 0o640)

    def test_invalid_candidate_preserves_boot_and_running_configuration(self):
        self.commands.invalid = True
        before = self.boot.read_bytes()
        with self.assertRaises(self.module.ActivationError):
            self.activation.apply()
        self.assertEqual(self.boot.read_bytes(), before)
        self.assertEqual(self.commands.loaded, self.old)
        self.assertEqual(self.commands.reloads, 0)
        self.assertFalse((self.state / "pending").exists())

    def test_failed_reload_restores_boot_and_reports_failure(self):
        self.commands.fail_reload = True
        with self.assertRaises(self.module.ActivationError):
            self.activation.apply()
        self.assertEqual(json.loads(self.boot.read_bytes()), self.old)
        self.assertEqual(self.commands.loaded, self.old)
        self.assertFalse((self.state / "pending").exists())

    def test_runtime_mismatch_rolls_back_successful_reload(self):
        self.commands.drift_after_reload = True
        with self.assertRaises(self.module.ActivationError):
            self.activation.apply()
        self.assertEqual(json.loads(self.boot.read_bytes()), self.old)
        self.assertEqual(self.commands.loaded, self.old)

    def test_rollback_diagnostic_preserves_safe_runtime_mismatch_reason(self):
        self.commands.drift_after_reload = True
        with self.assertRaisesRegex(self.module.ActivationError, "active configuration differs"):
            self.activation.apply()
        self.assertEqual(json.loads(self.boot.read_bytes()), self.old)
        self.assertEqual(self.commands.loaded, self.old)

    def test_rollback_diagnostic_does_not_expose_os_error_details(self):
        original = self.activation.durable_write
        failed = False

        def write(path, data, mode, gid):
            nonlocal failed
            if path == self.boot and not failed:
                failed = True
                raise OSError("synthetic protected path or value")
            return original(path, data, mode, gid)

        with mock.patch.object(self.activation, "durable_write", side_effect=write):
            with self.assertRaises(self.module.ActivationError) as caught:
                self.activation.apply()
        self.assertIn("filesystem operation failed", str(caught.exception))
        self.assertNotIn("synthetic protected", str(caught.exception))
        self.assertEqual(json.loads(self.boot.read_bytes()), self.old)

    def test_pending_recovery_restores_boot_without_calling_service(self):
        self.pending()
        self.commands.active = False
        self.activation.recover()
        self.assertEqual(json.loads(self.boot.read_bytes()), self.old)
        self.assertEqual(self.commands.reloads, 0)
        self.assertFalse((self.state / "pending").exists())

    def test_corrupt_recovery_record_is_not_guessed(self):
        self.pending()
        self.write(self.state / "last-good", "corrupt", 0o600)
        before = self.boot.read_bytes()
        with self.assertRaises(self.module.ActivationError):
            self.activation.recover()
        self.assertEqual(self.boot.read_bytes(), before)
        self.assertTrue((self.state / "pending").exists())

    def test_unchanged_observed_state_does_not_reload(self):
        self.write(self.candidate, self.boot.read_text())
        self.assertEqual(self.activation.apply(), "unchanged")
        self.assertEqual(self.commands.reloads, 0)

    def test_unchanged_text_repairs_runtime_drift(self):
        self.write(self.candidate, self.boot.read_text())
        self.commands.loaded = {"unexpected": True}
        self.assertEqual(self.activation.apply(), "changed")
        self.assertEqual(self.commands.loaded, self.old)

    def test_candidate_changed_during_validation_is_not_installed(self):
        original = self.commands.run

        def concurrent_render(command):
            result = original(command)
            if "validate" in command:
                self.write(self.candidate, json.dumps({"unexpected": True}))
            return result

        self.commands.run = concurrent_render
        with self.assertRaises(self.module.ActivationError):
            self.activation.apply()
        self.assertEqual(json.loads(self.boot.read_bytes()), self.old)
        self.assertEqual(self.commands.reloads, 0)

    def test_marker_unlink_and_recreation_failure_never_claim_false_restoration(self):
        original_sync = self.activation.fsync_directory
        original_write = self.activation.durable_write
        cleanup_failed = False

        def sync(directory):
            nonlocal cleanup_failed
            if directory == self.state and not self.activation.pending.exists() and self.commands.reloads:
                cleanup_failed = True
                raise OSError("synthetic directory I/O failure")
            return original_sync(directory)

        def write(path, data, mode, gid):
            if cleanup_failed:
                raise OSError("synthetic continuing write failure")
            return original_write(path, data, mode, gid)

        with mock.patch.object(self.activation, "fsync_directory", side_effect=sync), \
             mock.patch.object(self.activation, "durable_write", side_effect=write):
            with self.assertRaisesRegex(self.module.ActivationError, "recovery is incomplete"):
                self.activation.apply()
        self.assertEqual(json.loads(self.boot.read_bytes()), self.new)
        self.assertEqual(self.commands.loaded, self.new)
        self.assertFalse(self.activation.pending.exists())

    def test_marker_recreation_failure_still_restores_from_in_memory_previous_state(self):
        original_sync = self.activation.fsync_directory
        original_write = self.activation.durable_write
        cleanup_failed = False

        def sync(directory):
            nonlocal cleanup_failed
            if directory == self.state and not self.activation.pending.exists() and not cleanup_failed and self.commands.reloads:
                cleanup_failed = True
                raise OSError("synthetic first cleanup fsync failure")
            return original_sync(directory)

        def write(path, data, mode, gid):
            if cleanup_failed and path == self.activation.pending:
                raise OSError("synthetic marker recreation failure")
            return original_write(path, data, mode, gid)

        with mock.patch.object(self.activation, "fsync_directory", side_effect=sync), \
             mock.patch.object(self.activation, "durable_write", side_effect=write):
            with self.assertRaisesRegex(self.module.ActivationError, "previous boot and runtime configuration restored"):
                self.activation.apply()
        self.assertEqual(json.loads(self.boot.read_bytes()), self.old)
        self.assertEqual(self.commands.loaded, self.old)
        self.assertFalse(self.activation.pending.exists())

    def test_failed_runtime_recovery_retains_pending_record(self):
        self.commands.drift_after_reload = True
        original = self.commands.run

        def cannot_restore(command):
            if "reload" in command and self.commands.reloads:
                raise self.module.ActivationError("restoration rejected")
            return original(command)

        self.commands.run = cannot_restore
        with self.assertRaisesRegex(self.module.ActivationError, "recovery is incomplete"):
            self.activation.apply()
        self.assertEqual(json.loads(self.boot.read_bytes()), self.old)
        self.assertTrue((self.state / "pending").exists())
        self.commands.run = original
        self.activation.recover()
        self.assertFalse((self.state / "pending").exists())

    def test_stopped_service_does_not_install_candidate(self):
        self.commands.active = False
        with self.assertRaises(self.module.ActivationError):
            self.activation.apply()
        self.assertEqual(json.loads(self.boot.read_bytes()), self.old)

    def test_candidate_symlink_or_public_mode_is_rejected(self):
        self.candidate.chmod(0o644)
        with self.assertRaises(self.module.ActivationError):
            self.activation.apply()
        self.candidate.unlink()
        self.candidate.symlink_to(self.boot)
        with self.assertRaises(self.module.ActivationError):
            self.activation.apply()
        self.assertEqual(self.commands.reloads, 0)

    def test_candidate_wrong_owner_is_rejected(self):
        self.activation.ids = (os.getuid() + 1, os.getgid(), os.getuid(), os.getgid())
        with self.assertRaises(self.module.ActivationError):
            self.activation.apply()
        self.assertEqual(self.commands.reloads, 0)

    def test_recovery_after_interrupt_at_each_durable_write(self):
        # Losing power after any durable boundary must retain or restore old boot.
        original = self.activation.durable_write
        for step in (1, 2, 3):
            with self.subTest(step=step):
                self.write(self.boot, json.dumps(self.old))
                for file in self.state.iterdir():
                    file.unlink()
                count = 0

                def interrupted(path, data, mode, gid):
                    nonlocal count
                    original(path, data, mode, gid)
                    count += 1
                    if count == step:
                        raise KeyboardInterrupt()

                with mock.patch.object(self.activation, "durable_write", side_effect=interrupted):
                    with self.assertRaises(KeyboardInterrupt):
                        self.activation.apply()
                self.activation.recover()
                self.assertEqual(json.loads(self.boot.read_bytes()), self.old)

    def test_verify_is_observational_and_refuses_pending_transaction(self):
        self.candidate.unlink()
        before = {str(p): (p.stat().st_mtime_ns, p.stat().st_size) for p in self.root.rglob("*")}
        self.activation.verify()
        after = {str(p): (p.stat().st_mtime_ns, p.stat().st_size) for p in self.root.rglob("*")}
        self.assertEqual(after, before)
        self.assertEqual(self.commands.reloads, 0)
        self.write(self.candidate, json.dumps(self.new))
        self.pending()
        with self.assertRaises(self.module.ActivationError):
            self.activation.verify()
        self.assertTrue((self.state / "pending").exists())

    def test_verify_never_creates_missing_lock(self):
        lock = self.root / "run/lock/homelab-reverse-proxy.lock"
        lock.unlink()
        with self.assertRaises(self.module.ActivationError):
            self.activation.verify()
        self.assertFalse(lock.exists())

    def test_external_reload_rejects_shared_lock_without_upgrading_it(self):
        descriptor = os.open(self.root / "run/lock/homelab-reverse-proxy.lock", os.O_RDONLY)
        probe = os.open(self.root / "run/lock/homelab-reverse-proxy.lock", os.O_RDONLY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH)
            with mock.patch.object(self.module, "INHERITED_LOCK_FD", descriptor):
                with self.assertRaises(self.module.ActivationError):
                    self.activation.reload(inherited=True)
            fcntl.flock(probe, fcntl.LOCK_SH | fcntl.LOCK_NB)
            self.assertEqual(self.commands.reloads, 0)
        finally:
            os.close(probe)
            os.close(descriptor)

    def test_external_verify_preserves_exclusive_inherited_lock(self):
        descriptor = os.open(self.root / "run/lock/homelab-reverse-proxy.lock", os.O_RDONLY)
        probe = os.open(self.root / "run/lock/homelab-reverse-proxy.lock", os.O_RDONLY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            with mock.patch.object(self.module, "INHERITED_LOCK_FD", descriptor):
                self.activation.verify(inherited=True)
            with self.assertRaises(BlockingIOError):
                fcntl.flock(probe, fcntl.LOCK_SH | fcntl.LOCK_NB)
            self.assertEqual(self.commands.reloads, 0)
        finally:
            os.close(probe)
            os.close(descriptor)

    def test_external_reload_rejects_unlocked_inherited_descriptor(self):
        descriptor = os.open(self.root / "run/lock/homelab-reverse-proxy.lock", os.O_RDONLY)
        try:
            with mock.patch.object(self.module, "INHERITED_LOCK_FD", descriptor, create=True):
                with self.assertRaises(self.module.ActivationError):
                    self.activation.reload(inherited=True)
            self.assertEqual(self.commands.reloads, 0)
        finally:
            os.close(descriptor)

    def test_external_reload_preserves_inherited_lock(self):
        descriptor = os.open(self.root / "run/lock/homelab-reverse-proxy.lock", os.O_RDONLY)
        probe = os.open(self.root / "run/lock/homelab-reverse-proxy.lock", os.O_RDONLY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            with mock.patch.object(self.module, "INHERITED_LOCK_FD", descriptor, create=True):
                self.activation.reload(inherited=True)
            self.assertEqual(self.commands.reloads, 2)
            with self.assertRaises(BlockingIOError):
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(probe)
            os.close(descriptor)

    def test_reload_cycles_through_admin_only_configuration(self):
        self.activation.reload()
        self.assertEqual(self.commands.reloads, 2)
        self.assertEqual(self.commands.loaded, self.old)

    def test_unexpected_caddy_listener_fails_verification(self):
        self.commands.ss = b'tcp LISTEN 0 4096 0.0.0.0:80 0.0.0.0:* users:(("caddy",pid=1234,fd=9))\n'
        with self.assertRaises(self.module.ActivationError):
            self.activation.verify()

    def test_configured_listener_must_be_private_tcp_443(self):
        for listener in (":443", "0.0.0.0:443", "127.0.0.1:443", "10.0.0.2:80", "192.0.2.2:443"):
            value = dict(self.old, apps={"http": {"servers": {"srv0": {"listen": [listener]}}}})
            self.write(self.candidate, json.dumps(value))
            with self.subTest(listener=listener), self.assertRaises(self.module.ActivationError):
                self.activation.apply()
        self.assertEqual(self.commands.reloads, 0)


class CertificateTests(ActivationFixture):
    def configure_certificate(self):
        base = self.root / "etc/caddy/tls/app"
        version = base / "version-one"
        version.mkdir(parents=True)
        base.chmod(0o750)
        version.chmod(0o750)
        (base / "current").symlink_to("version-one")
        self.write(version / "fullchain.pem", "synthetic public fixture")
        self.write(version / "privkey.pem", "synthetic non-key fixture")
        configuration = dict(self.old, apps={
            "http": {"servers": {"srv0": {"listen": ["10.0.0.2:443"],
                     "protocols": ["h1", "h2"], "automatic_https": {"disable": True},
                     "tls_connection_policies": [
                         {"match": {"sni": ["app.example.test"]},
                          "certificate_selection": {"any_tag": ["cert0"]}}, {}],
                     "routes": [{"match": [{"host": ["app.example.test"]}]}]}}},
            "tls": {"certificates": {"load_files": [{
                "certificate": "/etc/caddy/tls/app/current/fullchain.pem",
                "key": "/etc/caddy/tls/app/current/privkey.pem", "tags": ["cert0"]}]}}})
        self.write(self.candidate, json.dumps(configuration))
        self.commands.ss = None
        self.tls_context = mock.MagicMock()
        self.tls_context.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = b"synthetic DER"
        context_patch = mock.patch.object(self.module.ssl, "create_default_context", return_value=self.tls_context)
        connect_patch = mock.patch.object(self.module.socket, "create_connection")
        context_patch.start()
        connect_patch.start()
        self.addCleanup(context_patch.stop)
        self.addCleanup(connect_patch.stop)
        self.dates = b"notBefore=Jan  1 00:00:00 2020 GMT\nnotAfter=Jan  1 00:00:00 2099 GMT\n"
        self.sans = b"X509v3 Subject Alternative Name:\n    DNS:app.example.test\n"
        original = self.commands.run

        def command(arguments):
            if arguments[:2] == ["/usr/bin/openssl", "x509"]:
                self.assertNotIn("privkey.pem", " ".join(arguments))
                if "-startdate" in arguments:
                    return self.dates
                if "-ext" in arguments:
                    return self.sans
                if "-outform" in arguments:
                    return b"synthetic DER"
                raise AssertionError(arguments)
            return original(arguments)

        self.commands.run = command
        return base, version

    def test_verify_rejects_served_certificate_different_from_current_version(self):
        self.configure_certificate()
        self.activation.apply()
        connection = mock.MagicMock()
        connection.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = b"other DER"
        with mock.patch.object(self.module, "ssl", create=True) as tls, \
             mock.patch.object(self.module.socket, "create_connection"):
            tls.create_default_context.return_value = connection
            with self.assertRaises(self.module.ActivationError):
                self.activation.verify()
        self.assertEqual(self.commands.reloads, 1)

    def test_reload_cycles_tls_app_to_refresh_caddy_cache(self):
        base, _ = self.configure_certificate()
        self.activation.apply()
        version = base / "version-two"
        version.mkdir()
        version.chmod(0o750)
        self.write(version / "fullchain.pem", "replacement public fixture")
        self.write(version / "privkey.pem", "replacement non-key fixture")
        (base / "current").unlink()
        (base / "current").symlink_to("version-two")

        self.activation.reload()

        pair = self.commands.loaded["apps"]["tls"]["certificates"]["load_files"][0]
        self.assertEqual(
            "/etc/caddy/tls/app/current/fullchain.pem", pair["certificate"]
        )
        self.assertEqual(
            "/etc/caddy/tls/app/current/privkey.pem", pair["key"]
        )
        self.assertEqual(["cert0"], pair["tags"])
        policy = self.commands.loaded["apps"]["http"]["servers"]["srv0"][
            "tls_connection_policies"
        ][0]
        self.assertEqual(["cert0"], policy["certificate_selection"]["any_tag"])
        self.assertEqual(self.commands.reloads, 3)

    def test_verify_uses_system_trust_sni_and_current_external_leaf(self):
        self.configure_certificate()
        self.activation.apply()
        connection = mock.MagicMock()
        connection.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = b"synthetic DER"
        with mock.patch.object(self.module, "ssl", create=True) as tls, \
             mock.patch.object(self.module.socket, "create_connection") as connect:
            tls.create_default_context.return_value = connection
            self.activation.verify()
            tls.create_default_context.assert_called_once_with()
            self.assertEqual(connect.call_args.args, (("10.0.0.2", 443),))
            self.assertEqual(connection.wrap_socket.call_args.kwargs["server_hostname"], "app.example.test")
        self.assertEqual(self.commands.reloads, 1)

    def configure_second_certificate(self, swapped=False):
        self.configure_certificate()
        base = self.root / "etc/caddy/tls/other"
        version = base / "version-one"
        version.mkdir(parents=True)
        base.chmod(0o750)
        version.chmod(0o750)
        (base / "current").symlink_to("version-one")
        self.write(version / "fullchain.pem", "synthetic second public fixture")
        self.write(version / "privkey.pem", "synthetic second non-key fixture")
        configuration = json.loads(self.candidate.read_bytes())
        server = configuration["apps"]["http"]["servers"]["srv0"]
        server["routes"].append({"match": [{"host": ["other.example.test"]}]})
        server["tls_connection_policies"] = [
            {"match": {"sni": ["app.example.test"]},
             "certificate_selection": {"any_tag": ["cert1" if swapped else "cert0"]}},
            {"match": {"sni": ["other.example.test"]},
             "certificate_selection": {"any_tag": ["cert0" if swapped else "cert1"]}}, {}]
        configuration["apps"]["tls"]["certificates"]["load_files"].append({
            "certificate": "/etc/caddy/tls/other/current/fullchain.pem",
            "key": "/etc/caddy/tls/other/current/privkey.pem", "tags": ["cert1"]})
        self.write(self.candidate, json.dumps(configuration))
        original = self.commands.run

        def command(arguments):
            if arguments[:2] == ["/usr/bin/openssl", "x509"] and "/other/" in arguments[3] and "-ext" in arguments:
                return b"DNS:other.example.test"
            return original(arguments)

        self.commands.run = command

    def test_explicit_certificate_selection_rejects_swapped_pairs_before_reload(self):
        # Caddy 2.6 adapter emits load_files.tags and per-SNI any_tag policies.
        self.configure_second_certificate(swapped=True)
        with self.assertRaises(self.module.ActivationError):
            self.activation.apply()
        self.assertEqual(self.commands.reloads, 0)
        self.assertEqual(json.loads(self.boot.read_bytes()), self.old)

    def test_explicit_certificate_selection_accepts_two_correct_pairs(self):
        self.configure_second_certificate()
        self.assertEqual(self.activation.apply(), "changed")

    def test_apply_rolls_back_when_served_leaf_differs_from_selected_certificate(self):
        self.configure_certificate()
        self.tls_context.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = b"other DER"
        with self.assertRaisesRegex(self.module.ActivationError, "previous boot and runtime configuration restored"):
            self.activation.apply()
        self.assertEqual(json.loads(self.boot.read_bytes()), self.old)
        self.assertEqual(self.commands.loaded, self.old)
        self.assertFalse(self.activation.pending.exists())

    def test_apply_rolls_back_when_tls_trust_or_hostname_verification_fails(self):
        self.configure_certificate()
        self.tls_context.wrap_socket.side_effect = OSError("synthetic TLS verification failure")
        with self.assertRaisesRegex(self.module.ActivationError, "previous boot and runtime configuration restored"):
            self.activation.apply()
        self.assertEqual(json.loads(self.boot.read_bytes()), self.old)
        self.assertEqual(self.commands.loaded, self.old)
        self.assertFalse(self.activation.pending.exists())

    def test_valid_external_pair_activates(self):
        self.configure_certificate()
        self.assertEqual(self.activation.apply(), "changed")

    def test_expired_and_future_certificates_preserve_committed_boot(self):
        self.configure_certificate()
        for dates in (b"notBefore=Jan  1 00:00:00 2000 GMT\nnotAfter=Jan  1 00:00:00 2001 GMT\n",
                      b"notBefore=Jan  1 00:00:00 2090 GMT\nnotAfter=Jan  1 00:00:00 2099 GMT\n"):
            self.dates = dates
            with self.subTest(dates=dates), self.assertRaises(self.module.ActivationError):
                self.activation.apply()
            self.assertEqual(json.loads(self.boot.read_bytes()), self.old)
            self.assertEqual(self.commands.reloads, 0)

    def test_hostname_requires_matching_dns_san(self):
        self.configure_certificate()
        for sans in (b"", b"DNS:other.example.test", b"DNS:*.test"):
            self.sans = sans
            with self.subTest(sans=sans), self.assertRaises(self.module.ActivationError):
                self.activation.apply()
        self.sans = b"DNS:*.example.test"
        self.assertEqual(self.activation.apply(), "changed")

    def test_certificate_pointer_cannot_escape_or_add_indirection(self):
        base, version = self.configure_certificate()
        (base / "current").unlink()
        for target in ("../app/version-one", "alias"):
            if target == "alias":
                (base / "alias").symlink_to(version)
            (base / "current").symlink_to(target)
            with self.subTest(target=target), self.assertRaises(self.module.ActivationError):
                self.activation.apply()
            (base / "current").unlink()
        self.assertEqual(self.commands.reloads, 0)

    def test_key_must_have_private_metadata(self):
        _, version = self.configure_certificate()
        (version / "privkey.pem").chmod(0o644)
        with self.assertRaises(self.module.ActivationError):
            self.activation.apply()
        self.assertEqual(self.commands.reloads, 0)

    def test_only_certificate_current_pointer_may_be_symlink(self):
        _, version = self.configure_certificate()
        key = version / "privkey.pem"
        key.unlink()
        key.symlink_to(version / "fullchain.pem")
        with self.assertRaises(self.module.ActivationError):
            self.activation.apply()
        self.assertEqual(self.commands.reloads, 0)


class CommandBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_activation()

    def test_unix_admin_observation_sends_caddy_required_empty_host(self):
        # Caddy 2.6 admin.go enforces Host == "" for its default Unix endpoint.
        configuration = {"admin": {"listen": "unix//run/caddy/admin.sock"}, "apps": {"http": {}}}

        class AdminHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                allowed = self.path == "/config/" and self.headers.get("Host") == ""
                self.send_response(200 if allowed else 403)
                self.end_headers()
                self.wfile.write(json.dumps(configuration if allowed else {"error": "host not allowed"}).encode())

            def log_message(self, *arguments):
                pass

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "admin.sock"
            with socketserver.UnixStreamServer(str(path), AdminHandler) as server:
                thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
                thread.start()
                try:
                    self.assertEqual(self.module.HostCommands().configuration(path), configuration)
                finally:
                    server.shutdown()
                    thread.join(timeout=2)

    def test_usage_rejects_arbitrary_paths_without_host_access(self):
        with mock.patch("sys.stderr"):
            self.assertEqual(self.module.main(["apply", "/tmp/arbitrary"]), 2)

    def test_cli_supports_observational_verify_under_external_lock(self):
        with mock.patch.object(self.module.os, "geteuid", return_value=0), \
             mock.patch.object(self.module, "Activator") as activator:
            self.assertEqual(self.module.main(["verify", "--lock-held"]), 0)
            activator.return_value.verify.assert_called_once_with(inherited=True)

    def test_runtime_diagnostic_preserves_safe_recovery_outcome(self):
        with mock.patch.object(self.module.os, "geteuid", return_value=0), \
             mock.patch.object(self.module, "Activator") as activator, \
             mock.patch("sys.stderr") as stderr:
            activator.return_value.apply.side_effect = self.module.ActivationError(
                "activation failed; previous boot and runtime configuration restored")
            self.assertEqual(self.module.main(["apply"]), 1)
        self.assertIn("previous boot and runtime configuration restored", "".join(
            call.args[0] for call in stderr.write.call_args_list))

    def test_identity_rejects_unexpected_home(self):
        from types import SimpleNamespace
        account = SimpleNamespace(pw_uid=999, pw_gid=999, pw_shell="/usr/sbin/nologin",
                                  pw_name="caddy", pw_dir="/home/caddy")
        group = SimpleNamespace(gr_gid=999, gr_mem=[])
        with mock.patch.object(self.module.pwd, "getpwnam", return_value=account), \
             mock.patch.object(self.module.pwd, "getpwall", return_value=[account]), \
             mock.patch.object(self.module.grp, "getgrnam", return_value=group), \
             mock.patch.object(self.module.grp, "getgrall", return_value=[group]):
            with self.assertRaises(self.module.ActivationError):
                self.module.identity()


if __name__ == "__main__":
    unittest.main()
