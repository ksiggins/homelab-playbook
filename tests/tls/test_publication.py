"""Certificate validation and atomic publication tests."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
from pathlib import Path

TEST_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(TEST_ROOT / "roles/tls_automation/files"))

from cert_fixtures import EphemeralCA, dns, ip
from tls_runtime.certificates import (
    validate_certificate,
    validate_historical_certificate,
)
from tls_runtime.publication import PublicationError, Publisher


WILDCARD = "*.infra.example.com"


class CertificateValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="tls-cert-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.ca = EphemeralCA()
        self.ca_file = self.root / "ca.pem"
        self.ca.write_certificate(self.ca_file)

    def validate(self, material, sans=None, minimum_seconds=3600):
        return validate_certificate(
            material.fullchain,
            material.private_key,
            sans or [WILDCARD],
            minimum_seconds,
            str(self.ca_file),
        )

    def assert_rejected(self, material, sans=None, minimum_seconds=3600):
        with self.assertRaises(ValueError):
            self.validate(material, sans=sans, minimum_seconds=minimum_seconds)

    def test_accepts_valid_trusted_chain_matching_key_and_exact_wildcard(self):
        material = self.ca.issue([dns(WILDCARD)])

        self.assertEqual(material.fingerprint, self.validate(material))

    def test_rejects_additional_unifi_dns_san(self):
        self.assert_rejected(
            self.ca.issue([dns(WILDCARD), dns("udm.example.com")])
        )

    def test_rejects_missing_dns_san(self):
        self.assert_rejected(self.ca.issue(None))

    def test_rejects_missing_approved_wildcard(self):
        self.assert_rejected(self.ca.issue([dns("modem.infra.example.com")]))

    def test_rejects_ip_san(self):
        self.assert_rejected(self.ca.issue([dns(WILDCARD), ip("192.0.2.10")]))

    def test_rejects_duplicate_dns_san(self):
        self.assert_rejected(self.ca.issue([dns(WILDCARD), dns(WILDCARD)]))

    def test_rejects_expired_certificate(self):
        now = datetime.now(timezone.utc)
        self.assert_rejected(
            self.ca.issue(
                [dns(WILDCARD)],
                not_before=now - timedelta(days=2),
                not_after=now - timedelta(days=1),
            ),
            minimum_seconds=0,
        )

    def test_rejects_certificate_not_yet_valid(self):
        now = datetime.now(timezone.utc)
        self.assert_rejected(
            self.ca.issue(
                [dns(WILDCARD)],
                not_before=now + timedelta(days=1),
                not_after=now + timedelta(days=2),
            ),
            minimum_seconds=0,
        )

    def test_rejects_certificate_below_minimum_remaining_lifetime(self):
        material = self.ca.issue([dns(WILDCARD)])

        self.assert_rejected(material, minimum_seconds=8 * 24 * 60 * 60)

    def test_rejects_wrong_private_key(self):
        material = self.ca.issue([dns(WILDCARD)])
        other_key = self.ca.issue([dns(WILDCARD)]).private_key

        self.assert_rejected(
            type(material)(material.fullchain, other_key, material.fingerprint)
        )

    def test_rejects_chain_signed_by_unknown_ca(self):
        foreign_material = EphemeralCA("Foreign root").issue([dns(WILDCARD)])

        self.assert_rejected(foreign_material)

    def test_historical_validation_permits_expiry_but_keeps_identity_checks(self):
        now = datetime.now(timezone.utc)
        expired = self.ca.issue(
            [dns(WILDCARD)],
            not_before=now - timedelta(days=2),
            not_after=now - timedelta(days=1),
        )

        self.assertEqual(
            expired.fingerprint,
            validate_historical_certificate(
                expired.fullchain,
                expired.private_key,
                [WILDCARD],
                str(self.ca_file),
            ),
        )
        with self.assertRaises(ValueError):
            validate_historical_certificate(
                expired.fullchain,
                self.ca.issue([dns(WILDCARD)]).private_key,
                [WILDCARD],
                str(self.ca_file),
            )
        with self.assertRaises(ValueError):
            validate_historical_certificate(
                expired.fullchain,
                expired.private_key,
                ["*.other.example.com"],
                str(self.ca_file),
            )
        future = self.ca.issue(
            [dns(WILDCARD)],
            not_before=now + timedelta(days=1),
            not_after=now + timedelta(days=2),
        )
        with self.assertRaises(ValueError):
            validate_historical_certificate(
                future.fullchain,
                future.private_key,
                [WILDCARD],
                str(self.ca_file),
            )

    def test_intermediate_fixture_root_permits_its_subordinate_ca(self):
        from cryptography import x509
        constraints = self.ca.certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        self.assertTrue(constraints.ca)
        self.assertGreaterEqual(constraints.path_length, 1)

    def test_historical_validation_uses_shared_chain_validity_interval(self):
        material = self.ca.issue_with_expired_intermediate([dns(WILDCARD)])

        self.assertEqual(
            material.fingerprint,
            validate_historical_certificate(
                material.fullchain,
                material.private_key,
                [WILDCARD],
                str(self.ca_file),
            ),
        )
        with self.assertRaises(ValueError):
            validate_certificate(
                material.fullchain,
                material.private_key,
                [WILDCARD],
                0,
                str(self.ca_file),
            )


class PublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="tls-publish-test-")
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.root = base / "published"
        self.state = base / "transactions"
        self.root.mkdir(mode=0o750)
        self.state.mkdir(mode=0o750)
        self.root.chmod(0o750)
        self.state.chmod(0o750)
        self.journal = self.state / "publication.json"
        self.owner_uid = os.getuid()
        self.reader_gid = os.getgid()
        self.reload_observations = []
        self.preflight_observations = []

    @staticmethod
    def fingerprint(directory: Path) -> str:
        fullchain = (directory / "fullchain.pem").read_bytes()
        private_key = (directory / "privkey.pem").read_bytes()
        if not fullchain.startswith(b"certificate-") or not private_key.startswith(
            b"private-key-"
        ):
            raise ValueError("candidate certificate is invalid")
        leaf = fullchain.split(b"\n", 1)[0]
        return hashlib.sha256(leaf).hexdigest()

    def preflight(self, directory: Path) -> None:
        self.assertEqual(self.root, directory.parent)
        self.assertEqual(0o750, stat.S_IMODE(directory.stat().st_mode))
        self.assertEqual(0o640, stat.S_IMODE((directory / "privkey.pem").stat().st_mode))
        self.preflight_observations.append(
            (
                (directory / "fullchain.pem").read_bytes(),
                (directory / "privkey.pem").read_bytes(),
            )
        )

    def reload_and_verify(self, expected_fingerprint: str) -> None:
        current = self.root / "current"
        if not expected_fingerprint:
            self.assertFalse(current.exists())
            self.reload_observations.append((b"", b"", ""))
            return
        fullchain = (current / "fullchain.pem").read_bytes()
        private_key = (current / "privkey.pem").read_bytes()
        leaf = fullchain.split(b"\n", 1)[0]
        self.assertEqual(hashlib.sha256(leaf).hexdigest(), expected_fingerprint)
        self.reload_observations.append(
            (fullchain, private_key, expected_fingerprint)
        )

    def publisher(self, **callbacks) -> Publisher:
        return Publisher(
            root=self.root,
            journal=self.journal,
            owner_uid=callbacks.pop("owner_uid", self.owner_uid),
            reader_gid=self.reader_gid,
            validate=callbacks.pop("validate", self.fingerprint),
            reload_and_verify=callbacks.pop(
                "reload_and_verify", self.reload_and_verify
            ),
            preflight=callbacks.pop("preflight", self.preflight),
        )

    def test_publishes_complete_generation_before_callback_observes_it(self):
        fullchain = b"certificate-one"
        private_key = b"private-key-one"

        self.assertTrue(self.publisher().publish(fullchain, private_key))

        current = self.root / "current"
        self.assertTrue(current.is_symlink())
        self.assertFalse(Path(os.readlink(current)).is_absolute())
        self.assertEqual(fullchain, (current / "fullchain.pem").read_bytes())
        self.assertEqual(private_key, (current / "privkey.pem").read_bytes())
        self.assertEqual(
            [(fullchain, private_key, hashlib.sha256(fullchain).hexdigest())],
            self.reload_observations,
        )
        generation = current.resolve()
        self.assertEqual(0o750, stat.S_IMODE(generation.stat().st_mode))
        for name in ("fullchain.pem", "privkey.pem"):
            info = (generation / name).stat()
            self.assertEqual(0o640, stat.S_IMODE(info.st_mode))
            self.assertEqual(self.owner_uid, info.st_uid)
            self.assertEqual(self.reader_gid, info.st_gid)
        self.assertFalse(self.journal.exists())

    def test_same_fingerprint_is_a_no_op(self):
        publisher = self.publisher()
        publisher.publish(b"certificate-one", b"private-key-one")
        original_target = os.readlink(self.root / "current")
        self.reload_observations.clear()
        self.preflight_observations.clear()

        changed = publisher.publish(b"certificate-one", b"private-key-one")

        self.assertFalse(changed)
        self.assertEqual(original_target, os.readlink(self.root / "current"))
        self.assertEqual(
            [
                (
                    b"certificate-one",
                    b"private-key-one",
                    hashlib.sha256(b"certificate-one").hexdigest(),
                )
            ],
            self.reload_observations,
        )
        self.assertEqual([], self.preflight_observations)

    def test_same_leaf_with_changed_fullchain_publishes_new_bundle(self):
        publisher = self.publisher()
        publisher.publish(
            b"certificate-leaf\nintermediate-old", b"private-key-one"
        )
        old_target = os.readlink(self.root / "current")

        changed = publisher.publish(
            b"certificate-leaf\nintermediate-new", b"private-key-one"
        )

        self.assertTrue(changed)
        self.assertNotEqual(old_target, os.readlink(self.root / "current"))
        self.assertEqual(
            b"certificate-leaf\nintermediate-new",
            (self.root / "current/fullchain.pem").read_bytes(),
        )

    def test_owned_partial_private_build_is_removed_before_publication(self):
        interrupted = self.state / ("publication-stage-" + "1" * 32)
        interrupted.mkdir(mode=0o700)
        interrupted.chmod(0o700)
        (interrupted / "fullchain.pem").write_bytes(b"partial")
        (interrupted / "fullchain.pem").chmod(0o600)

        self.assertTrue(
            self.publisher().publish(b"certificate-new", b"private-key-new")
        )

        self.assertFalse(interrupted.exists())
        self.assertEqual(
            b"certificate-new", (self.root / "current/fullchain.pem").read_bytes()
        )

    def test_creation_boundary_artifacts_are_recovered_by_exact_name(self):
        suffixes = iter(("1" * 32, "2" * 32, "3" * 32, "4" * 32))
        candidate = self.state / ("candidate-" + next(suffixes))
        candidate.mkdir(mode=0o700)
        candidate.chmod(0o700)
        staging = self.state / ("publication-stage-" + next(suffixes))
        staging.mkdir(mode=0o700)
        staging.chmod(0o700)
        partial = staging / "fullchain.pem"
        partial.write_bytes(b"partial-write")
        partial.chmod(0o600)
        pointer = self.state / ("current-stage-" + next(suffixes))
        pointer.symlink_to("generation-" + "5" * 32)
        journal_temporary = self.state / (
            "." + self.journal.name + "." + next(suffixes)
        )
        journal_temporary.write_bytes(b"partial-journal")
        journal_temporary.chmod(0o600)

        self.publisher().recover()

        for artifact in (candidate, staging, pointer, journal_temporary):
            self.assertFalse(os.path.lexists(artifact))

    def test_untrusted_private_build_artifact_is_rejected_without_changes(self):
        interrupted = self.state / ("publication-stage-" + "1" * 32)
        interrupted.symlink_to(self.root)

        with self.assertRaises(ValueError):
            self.publisher().publish(b"certificate-new", b"private-key-new")

        self.assertTrue(interrupted.is_symlink())
        self.assertFalse((self.root / "current").exists())

    def test_prefix_only_private_artifact_is_never_selected_for_cleanup(self):
        unrelated = self.state / "publication-stage-operator-owned"
        unrelated.mkdir(mode=0o750)
        unrelated.chmod(0o750)

        self.publisher().publish(b"certificate-new", b"private-key-new")

        self.assertTrue(unrelated.is_dir())

    def test_expired_historical_generation_can_be_replaced(self):
        ca = EphemeralCA("Historical publication root")
        ca_file = self.state / "ca.pem"
        ca.write_certificate(ca_file)
        now = datetime.now(timezone.utc)
        expired = ca.issue(
            [dns(WILDCARD)],
            not_before=now - timedelta(days=2),
            not_after=now - timedelta(days=1),
        )
        replacement = ca.issue([dns(WILDCARD)])
        generation = self.root / ("generation-" + "1" * 32)
        generation.mkdir(mode=0o750)
        generation.chmod(0o750)
        for name, contents in (
            ("fullchain.pem", expired.fullchain),
            ("privkey.pem", expired.private_key),
        ):
            (generation / name).write_bytes(contents)
            (generation / name).chmod(0o640)
        (self.root / "current").symlink_to(generation.name)

        def validate_path(path):
            chain = (path / "fullchain.pem").read_bytes()
            key = (path / "privkey.pem").read_bytes()
            if path.parent == self.root:
                return validate_historical_certificate(
                    chain, key, [WILDCARD], str(ca_file)
                )
            return validate_certificate(
                chain, key, [WILDCARD], 3600, str(ca_file)
            )

        def preflight(path):
            validate_certificate(
                (path / "fullchain.pem").read_bytes(),
                (path / "privkey.pem").read_bytes(),
                [WILDCARD],
                3600,
                str(ca_file),
            )

        publisher = self.publisher(
            validate=validate_path,
            preflight=preflight,
            reload_and_verify=lambda _fingerprint: None,
        )

        self.assertTrue(
            publisher.publish(replacement.fullchain, replacement.private_key)
        )
        self.assertEqual(
            replacement.fingerprint, validate_path(self.root / "current")
        )

    def test_candidate_validation_failure_leaves_old_generation_active(self):
        publisher = self.publisher()
        publisher.publish(b"certificate-old", b"private-key-old")
        original_target = os.readlink(self.root / "current")

        with self.assertRaises(ValueError):
            publisher.publish(b"invalid", b"private-key-new")

        self.assertEqual(original_target, os.readlink(self.root / "current"))
        self.assertFalse(self.journal.exists())

    def test_preflight_failure_leaves_old_generation_active(self):
        publisher = self.publisher()
        publisher.publish(b"certificate-old", b"private-key-old")
        original_target = os.readlink(self.root / "current")

        def reject(_directory):
            raise RuntimeError("candidate configuration rejected")

        with self.assertRaises(RuntimeError):
            self.publisher(preflight=reject).publish(
                b"certificate-new", b"private-key-new"
            )

        self.assertEqual(original_target, os.readlink(self.root / "current"))
        self.assertFalse(self.journal.exists())
        self.assertEqual(
            {"current", original_target},
            {entry.name for entry in self.root.iterdir()},
        )

    def test_reload_failure_restores_and_reverifies_old_generation(self):
        publisher = self.publisher()
        publisher.publish(b"certificate-old", b"private-key-old")
        old_target = os.readlink(self.root / "current")
        old_fingerprint = hashlib.sha256(b"certificate-old").hexdigest()
        new_fingerprint = hashlib.sha256(b"certificate-new").hexdigest()
        observed = []

        def fail_new(fingerprint):
            observed.append(fingerprint)
            if fingerprint == new_fingerprint:
                raise RuntimeError("new certificate was not served")
            self.reload_and_verify(fingerprint)

        with self.assertRaises(PublicationError) as caught:
            self.publisher(reload_and_verify=fail_new).publish(
                b"certificate-new", b"private-key-new"
            )

        self.assertTrue(caught.exception.activation_failed)
        self.assertFalse(caught.exception.restoration_failed)
        self.assertEqual(old_target, os.readlink(self.root / "current"))
        self.assertEqual([new_fingerprint, old_fingerprint], observed)
        self.assertFalse(self.journal.exists())

    def test_first_deployment_failure_removes_current_and_verifies_deactivation(self):
        new_fingerprint = hashlib.sha256(b"certificate-new").hexdigest()
        observed = []

        def fail_activation(fingerprint):
            observed.append(fingerprint)
            if fingerprint == new_fingerprint:
                raise RuntimeError("new certificate was not served")
            self.reload_and_verify(fingerprint)

        with self.assertRaises(PublicationError) as caught:
            self.publisher(reload_and_verify=fail_activation).publish(
                b"certificate-new", b"private-key-new"
            )

        self.assertTrue(caught.exception.activation_failed)
        self.assertFalse(caught.exception.restoration_failed)
        self.assertFalse((self.root / "current").exists())
        self.assertEqual([new_fingerprint, ""], observed)
        self.assertFalse(self.journal.exists())

    def test_rollback_verification_failure_retains_journal_and_generations(self):
        self.publisher().publish(b"certificate-old", b"private-key-old")
        old_fingerprint = hashlib.sha256(b"certificate-old").hexdigest()
        new_fingerprint = hashlib.sha256(b"certificate-new").hexdigest()

        def fail_all(fingerprint):
            if fingerprint in {new_fingerprint, old_fingerprint}:
                raise RuntimeError("served certificate mismatch")

        with self.assertRaisesRegex(
            PublicationError, "rollback verification failed"
        ) as caught:
            self.publisher(reload_and_verify=fail_all).publish(
                b"certificate-new", b"private-key-new"
            )

        self.assertTrue(caught.exception.activation_failed)
        self.assertTrue(caught.exception.restoration_failed)
        self.assertIsInstance(caught.exception.activation_error, RuntimeError)
        self.assertIsInstance(caught.exception.rollback_error, RuntimeError)
        self.assertTrue(self.journal.is_file())
        record = json.loads(self.journal.read_text(encoding="utf-8"))
        self.assertEqual("rollback_failed", record["status"])
        self.assertEqual(record["previous"], os.readlink(self.root / "current"))
        self.assertTrue((self.root / record["generation"]).is_dir())

    def test_interrupted_switched_transaction_recovers_without_republication(self):
        self.publisher().publish(b"certificate-old", b"private-key-old")
        new_fingerprint = hashlib.sha256(b"certificate-new").hexdigest()

        def interrupt_after_switch(_fingerprint):
            raise KeyboardInterrupt("simulated process interruption")

        with self.assertRaises(KeyboardInterrupt):
            self.publisher(reload_and_verify=interrupt_after_switch).publish(
                b"certificate-new", b"private-key-new"
            )

        self.assertTrue(self.journal.is_file())
        self.assertEqual(new_fingerprint, self.fingerprint(self.root / "current"))
        recovered = []

        def verify_recovered(fingerprint):
            recovered.append(fingerprint)
            self.reload_and_verify(fingerprint)

        self.publisher(reload_and_verify=verify_recovered).recover()

        self.assertEqual([new_fingerprint], recovered)
        self.assertFalse(self.journal.exists())
        self.assertEqual(new_fingerprint, self.fingerprint(self.root / "current"))

    def test_restored_cleanup_interruptions_never_block_recovery(self):
        for with_previous in (False, True):
            for boundary in (1, 2, 3):
                with self.subTest(with_previous=with_previous, boundary=boundary):
                    self._assert_cleanup_interruption_recovers(
                        with_previous, boundary
                    )

    def _assert_cleanup_interruption_recovers(self, with_previous, boundary):
        with tempfile.TemporaryDirectory(prefix="tls-cleanup-crash-") as name:
            base = Path(name)
            root = base / "published"
            state = base / "private"
            root.mkdir(mode=0o750)
            state.mkdir(mode=0o700)
            root.chmod(0o750)
            state.chmod(0o700)
            journal = state / "transaction.json"

            def fingerprint(path):
                return hashlib.sha256(
                    (path / "fullchain.pem").read_bytes()
                ).hexdigest()

            publisher = Publisher(
                root,
                journal,
                os.getuid(),
                os.getgid(),
                fingerprint,
                lambda _fingerprint: None,
                lambda _path: None,
            )
            if with_previous:
                publisher.publish(b"certificate-old", b"private-key-old")

            def fail_reload(_fingerprint):
                raise RuntimeError("served state mismatch")

            with self.assertRaises(PublicationError):
                Publisher(
                    root,
                    journal,
                    os.getuid(),
                    os.getgid(),
                    fingerprint,
                    fail_reload,
                    lambda _path: None,
                ).publish(b"certificate-new", b"private-key-new")

            real_unlink = Path.unlink
            real_rmdir = Path.rmdir
            operations = 0

            def count_unlink(path, *args, **kwargs):
                nonlocal operations
                result = real_unlink(path, *args, **kwargs)
                if path.parent.name.startswith(("generation-", "retired-")):
                    operations += 1
                    if operations == boundary:
                        raise KeyboardInterrupt("simulated cleanup interruption")
                return result

            def count_rmdir(path, *args, **kwargs):
                nonlocal operations
                result = real_rmdir(path, *args, **kwargs)
                if path.name.startswith(("generation-", "retired-")):
                    operations += 1
                    if operations == boundary:
                        raise KeyboardInterrupt("simulated cleanup interruption")
                return result

            recovery = Publisher(
                root,
                journal,
                os.getuid(),
                os.getgid(),
                fingerprint,
                lambda _fingerprint: None,
                lambda _path: None,
            )
            with patch.object(Path, "unlink", count_unlink), patch.object(
                Path, "rmdir", count_rmdir
            ), self.assertRaises(KeyboardInterrupt):
                recovery.recover()

            self.assertFalse(journal.exists())
            published_entries = {entry.name for entry in root.iterdir()}
            if with_previous:
                self.assertEqual(2, len(published_entries))
                self.assertIn("current", published_entries)
            else:
                self.assertEqual(set(), published_entries)
            recovery.recover()
            self.assertFalse(
                any(entry.name.startswith("retired-") for entry in state.iterdir())
            )

    def test_rejects_absolute_current_symlink_before_candidate_validation(self):
        outside = self.state / "outside"
        outside.mkdir()
        (self.root / "current").symlink_to(outside)
        validation_called = False

        def validator(_directory):
            nonlocal validation_called
            validation_called = True
            return "0" * 64

        with self.assertRaises(ValueError):
            self.publisher(validate=validator).publish(
                b"certificate-new", b"private-key-new"
            )

        self.assertFalse(validation_called)
        self.assertEqual(str(outside), os.readlink(self.root / "current"))

    def test_rejects_unexpected_root_mode_before_candidate_validation(self):
        self.root.chmod(0o755)
        validation_called = False

        def validator(_directory):
            nonlocal validation_called
            validation_called = True
            return "0" * 64

        with self.assertRaises(ValueError):
            self.publisher(validate=validator).publish(
                b"certificate-new", b"private-key-new"
            )

        self.assertFalse(validation_called)

    def test_rejects_unexpected_owner_before_candidate_validation(self):
        validation_called = False

        def validator(_directory):
            nonlocal validation_called
            validation_called = True
            return "0" * 64

        with self.assertRaises(ValueError):
            self.publisher(
                owner_uid=self.owner_uid + 1, validate=validator
            ).publish(b"certificate-new", b"private-key-new")

        self.assertFalse(validation_called)


class RetainedCandidateRecoveryTests(unittest.TestCase):
    """Real certificate and local TLS oracles for expired rollback recovery."""
    def setUp(self):
        PublicationTests.setUp(self)
        self.ca = EphemeralCA("Recovery fixture root")
        self.ca_file = self.state / "fixture-ca.pem"
        self.ca.write_certificate(self.ca_file)
        now = datetime.now(timezone.utc)
        self.old = self.ca.issue([dns(WILDCARD)], not_before=now - timedelta(days=2),
                                 not_after=now - timedelta(days=1))
        self.new = self.ca.issue([dns(WILDCARD)])
        self.old_path = self.root / ("generation-" + "1" * 32)
        self.old_path.mkdir(mode=0o750)
        self.old_path.chmod(0o750)
        for filename, contents in (("fullchain.pem", self.old.fullchain), ("privkey.pem", self.old.private_key)):
            (self.old_path / filename).write_bytes(contents)
            (self.old_path / filename).chmod(0o640)
        (self.root / "current").symlink_to(self.old_path.name)
        self.fail_new_reload = True

    def validate_material(self, path, historical=False):
        chain, key = ((path / filename).read_bytes() for filename in ("fullchain.pem", "privkey.pem"))
        if historical:
            return validate_historical_certificate(chain, key, [WILDCARD], str(self.ca_file))
        return validate_certificate(chain, key, [WILDCARD], 3600, str(self.ca_file))

    def fresh_handshake(self, expected):
        import socket
        import ssl
        import threading
        from tls_runtime.runtime import verify_endpoint
        if self.fail_new_reload and expected == self.new.fingerprint:
            self.fail_new_reload = False
            raise RuntimeError("one transient reload failure")
        self.assertTrue(expected)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.root / "current/fullchain.pem", self.root / "current/privkey.pem")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(5)
            def serve():
                connection, _ = listener.accept()
                try:
                    with context.wrap_socket(connection, server_side=True):
                        pass
                except ssl.SSLError:
                    connection.close()
            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            try:
                verify_endpoint({"hostname": "modem.infra.example.com", "address": "127.0.0.1",
                                 "port": listener.getsockname()[1]}, expected,
                                ssl.create_default_context(cafile=str(self.ca_file)))
            finally:
                thread.join(6)

    def recovery_publisher(self):
        return Publisher(self.root, self.journal, self.owner_uid, self.reader_gid,
                         lambda path: self.validate_material(path, path.parent == self.root),
                         self.fresh_handshake, self.validate_material)

    def failed_transition(self):
        with self.assertRaises(PublicationError) as caught:
            self.recovery_publisher().publish(self.new.fullchain, self.new.private_key)
        self.assertTrue(caught.exception.activation_failed)
        self.assertTrue(caught.exception.restoration_failed)
        self.assertIn("certificate has expired", str(caught.exception.rollback_error))
        record = json.loads(self.journal.read_text())
        self.assertEqual("rollback_failed", record["status"])
        self.assertEqual(self.old_path.name, os.readlink(self.root / "current"))
        return record

    def test_healthy_retry_activates_retained_candidate_without_issuance(self):
        from tls_runtime.runtime import reconcile
        self.failed_transition()
        def no_new_order():
            self.fail("retained candidate recovery must not start another ACME order")
        result = reconcile(self.recovery_publisher(), no_new_order, no_new_order)
        self.assertEqual("changed", result["publication"])
        self.assertEqual("not_run", result["issuance"])
        self.assertTrue(result["activation_failed"])
        self.assertTrue(result["restoration_failed"])
        self.assertEqual(self.new.fingerprint, self.validate_material(self.root / "current"))
        self.assertFalse(self.journal.exists())

    def test_untrusted_retained_candidate_blocks_recovery_and_issuance(self):
        from tls_runtime.runtime import reconcile
        record = self.failed_transition()
        foreign = EphemeralCA("Foreign recovery root").issue([dns(WILDCARD)])
        candidate = self.root / record["generation"]
        (candidate / "fullchain.pem").write_bytes(foreign.fullchain)
        (candidate / "privkey.pem").write_bytes(foreign.private_key)
        record["fingerprint"] = foreign.fingerprint
        self.journal.write_text(json.dumps(record))
        def no_new_order():
            self.fail("unsafe pending recovery cannot start issuance")
        result = reconcile(self.recovery_publisher(), no_new_order, no_new_order)
        self.assertEqual("failed", result["publication"])
        self.assertTrue(self.journal.exists())
        self.assertEqual(self.old_path.name, os.readlink(self.root / "current"))

    def test_retained_retry_resumes_each_new_durable_boundary(self):
        for boundary in ("retry_pending", "switch", "recovered"):
            with self.subTest(boundary=boundary):
                fixture = RetainedCandidateRecoveryTests("test_healthy_retry_activates_retained_candidate_without_issuance")
                fixture.setUp()
                try:
                    fixture.failed_transition()
                    publisher = fixture.recovery_publisher()
                    write = publisher._write_journal
                    switch = publisher._switch_current
                    def interrupt_write(record):
                        write(record)
                        if record["status"] == boundary:
                            raise KeyboardInterrupt("durable recovery interruption")
                    def interrupt_switch(generation):
                        switch(generation)
                        if boundary == "switch":
                            raise KeyboardInterrupt("atomic switch interruption")
                    with patch.object(publisher, "_write_journal", side_effect=interrupt_write), \
                            patch.object(publisher, "_switch_current", side_effect=interrupt_switch), \
                            self.assertRaises(KeyboardInterrupt):
                        publisher.recover()
                    self.assertTrue(fixture.journal.exists())
                    result = fixture.recovery_publisher().recover()
                    self.assertEqual({"publication": "changed", "activation_failed": True,
                                      "restoration_failed": True}, result)
                    self.assertEqual(fixture.new.fingerprint, fixture.validate_material(fixture.root / "current"))
                    self.assertFalse(fixture.journal.exists())
                finally:
                    fixture.doCleanups()


if __name__ == "__main__":
    unittest.main()
