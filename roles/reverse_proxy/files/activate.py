#!/usr/bin/python3
"""Root-owned Caddy transaction entry point; Python 3.9 standard library only.

CLI paths are fixed. Constructor dependencies isolate host commands in offline tests.
Certificate deployment may inherit fd 9 for `reload --lock-held` or
`verify --lock-held`; that descriptor
must refer to the existing root-owned lock and hold its exclusive flock.
"""

import contextlib
import datetime
import fcntl
import grp
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import socket
import ssl
import stat
import subprocess
import sys
import tempfile


INHERITED_LOCK_FD = 9


class ActivationError(RuntimeError):
    """A diagnostic which contains no protected configuration or key material."""


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=10)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))


class HostCommands:
    def run(self, command):
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=60, check=False,
                                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "HOME": "/var/lib/caddy"})
        except (OSError, subprocess.TimeoutExpired):
            raise ActivationError("host command could not complete") from None
        if result.returncode:
            raise ActivationError("host command rejected the requested operation")
        return result.stdout

    def configuration(self, path):
        connection = UnixHTTPConnection(path)
        try:
            # Caddy requires an empty HTTP Host for its default Unix endpoint.
            connection.request("GET", "/config/", headers={"Host": ""})
            response = connection.getresponse()
            if response.status != 200:
                raise ActivationError("active configuration could not be observed")
            data = response.read(16 * 1024 * 1024 + 1)
            if len(data) > 16 * 1024 * 1024:
                raise ActivationError("active configuration exceeds the observation limit")
            return json.loads(data)
        except (OSError, ValueError, http.client.HTTPException):
            raise ActivationError("active configuration could not be observed") from None
        finally:
            connection.close()


def identity():
    try:
        account = pwd.getpwnam("caddy")
        group = grp.getgrnam("caddy")
    except KeyError:
        raise ActivationError("dedicated Caddy identity is missing") from None
    if (account.pw_uid == 0 or account.pw_gid != group.gr_gid
            or account.pw_dir != "/var/lib/caddy"
            or account.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false")
            or any(entry.gr_gid != group.gr_gid and "caddy" in entry.gr_mem for entry in grp.getgrall())
            or any(member != "caddy" for member in group.gr_mem)
            or any(entry.pw_name != "caddy" and entry.pw_gid == group.gr_gid for entry in pwd.getpwall())):
        raise ActivationError("dedicated Caddy identity is incompatible")
    return (0, 0, account.pw_uid, group.gr_gid)


class Activator:
    def __init__(self, root=Path("/"), commands=None, ids=None):
        self.root = Path(root)
        self.commands = commands if commands is not None else HostCommands()
        self.ids = ids if ids is not None else identity()
        self.config_dir = self.path("/etc/caddy")
        self.boot = self.config_dir / "Caddyfile"
        self.candidate = self.config_dir / "Caddyfile.candidate"
        self.state = self.path("/var/lib/homelab-reverse-proxy")
        self.pending = self.state / "pending"
        self.previous = self.state / "last-good"
        self.lock_path = self.path("/run/lock/homelab-reverse-proxy.lock")
        self.socket = self.path("/run/caddy/admin.sock")

    def path(self, value):
        return self.root / value.lstrip("/")

    def metadata(self, path, kind, uid, gid, mode):
        try:
            info = path.lstat()
        except OSError:
            raise ActivationError("required managed path is missing or inaccessible") from None
        if (not kind(info.st_mode) or info.st_uid != uid or info.st_gid != gid
                or stat.S_IMODE(info.st_mode) != mode
                or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
            raise ActivationError("managed path ownership, type or permissions are invalid")
        return info

    def parents(self, path):
        for parent in path.parents:
            if parent == self.root:
                break
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != self.ids[0] or info.st_mode & 0o022:
                raise ActivationError("managed path has an unsafe parent directory")

    def preflight(self):
        root_uid, root_gid, _, caddy_gid = self.ids
        self.parents(self.config_dir)
        self.parents(self.state)
        self.metadata(self.config_dir, stat.S_ISDIR, root_uid, caddy_gid, 0o750)
        self.metadata(self.config_dir / "tls", stat.S_ISDIR, root_uid, caddy_gid, 0o750)
        self.metadata(self.state, stat.S_ISDIR, root_uid, root_gid, 0o700)
        self.metadata(self.boot, stat.S_ISREG, root_uid, caddy_gid, 0o640)

    @contextlib.contextmanager
    def locked(self, shared=False, inherited=False):
        self.preflight()
        # /run/lock may be sticky world-writable; the existing inode must be safe.
        lock_parent = self.lock_path.parent.lstat()
        if (not stat.S_ISDIR(lock_parent.st_mode) or lock_parent.st_uid != self.ids[0]
                or (lock_parent.st_mode & 0o022 and not lock_parent.st_mode & stat.S_ISVTX)):
            raise ActivationError("deployment lock directory is unsafe")
        expected = self.metadata(self.lock_path, stat.S_ISREG, self.ids[0], self.ids[1], 0o600)
        descriptor = INHERITED_LOCK_FD if inherited else os.open(self.lock_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            actual = os.fstat(descriptor)
            if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                raise ActivationError("deployment lock descriptor does not match the managed lock")
            operation = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
            if inherited:
                probe = os.open(self.lock_path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    try:
                        fcntl.flock(probe, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    except BlockingIOError:
                        pass
                    else:
                        raise ActivationError("inherited deployment descriptor does not hold an exclusive lock")
                finally:
                    os.close(probe)
                operation = fcntl.LOCK_EX | fcntl.LOCK_NB
            fcntl.flock(descriptor, operation)
            self.preflight()
            yield
        finally:
            if not inherited:
                os.close(descriptor)

    def fsync_directory(self, directory):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def durable_write(self, path, data, mode, gid):
        descriptor, name = tempfile.mkstemp(prefix=".activation-", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as output:
                os.fchown(output.fileno(), self.ids[0], gid)
                os.fchmod(output.fileno(), mode)
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            self.fsync_directory(path.parent)
        finally:
            if temporary.exists():
                temporary.unlink()

    def clear_pending(self):
        record = self.pending.read_bytes()
        self.pending.unlink()
        try:
            self.fsync_directory(self.state)
        except OSError:
            self.durable_write(self.pending, record, 0o600, self.ids[1])
            raise

    def active(self):
        self.commands.run(["/usr/bin/systemctl", "is-active", "--quiet", "caddy.service"])

    def caddy(self, operation, config, adapter="caddyfile"):
        command = ["/usr/sbin/runuser", "-u", "caddy", "--", "/usr/bin/caddy", operation,
                   "--config", str(config)]
        if adapter:
            command += ["--adapter", adapter]
        if operation == "reload":
            command += ["--force", "--address", "unix//run/caddy/admin.sock"]
        return self.commands.run(command)

    def runtime_configuration(self, configuration):
        runtime = json.loads(json.dumps(configuration))
        certificates = runtime.get("apps", {}).get("tls", {}).get("certificates", {}).get("load_files", [])
        runtime_tags = {}
        for pair in certificates:
            certificate = pair.get("certificate", "")
            match = re.fullmatch(
                r"/etc/caddy/tls/([A-Za-z0-9][A-Za-z0-9_-]{0,63})/current/fullchain\.pem",
                certificate,
            )
            if match is None:
                continue
            target = (self.config_dir / "tls" / match.group(1) / "current").resolve(strict=True)
            external = Path("/") / target.relative_to(self.root)
            pair["certificate"] = str(external / "fullchain.pem")
            pair["key"] = str(external / "privkey.pem")
            suffix = hashlib.sha256(pair["certificate"].encode()).hexdigest()[:16]
            for tag in pair.get("tags", []):
                runtime_tags[tag] = tag + "-" + suffix
            pair["tags"] = [runtime_tags.get(tag, tag) for tag in pair.get("tags", [])]
        servers = runtime.get("apps", {}).get("http", {}).get("servers", {})
        for server in servers.values():
            for policy in server.get("tls_connection_policies", []):
                selection = policy.get("certificate_selection", {})
                for field in ("any_tag", "all_tags"):
                    if field in selection:
                        selection[field] = [
                            runtime_tags.get(tag, tag) for tag in selection[field]
                        ]
        return runtime

    def reload_configuration(self, configuration):
        runtime = self.runtime_configuration(configuration)
        descriptor, name = tempfile.mkstemp(prefix=".runtime-", suffix=".json", dir=self.config_dir)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as output:
                os.fchown(output.fileno(), self.ids[0], self.ids[3])
                os.fchmod(output.fileno(), 0o640)
                output.write(json.dumps(runtime, separators=(",", ":")).encode())
                output.flush()
                os.fsync(output.fileno())
            self.caddy("reload", temporary, adapter=None)
            return runtime
        finally:
            temporary.unlink(missing_ok=True)

    def adapted(self, config):
        try:
            result = json.loads(self.caddy("adapt", config))
        except ValueError:
            raise ActivationError("configuration adaptation returned invalid data") from None
        if not isinstance(result, dict):
            raise ActivationError("configuration adaptation returned invalid data")
        self.expected_listeners(result)
        return result

    def expected_listeners(self, configuration):
        if configuration.get("admin", {}).get("listen") != "unix//run/caddy/admin.sock":
            raise ActivationError("configuration must use the protected Unix admin socket")
        listeners = set()
        networks = tuple(ipaddress.ip_network(value) for value in (
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))
        servers = configuration.get("apps", {}).get("http", {}).get("servers", {})
        for server in servers.values():
            if set(server.get("protocols", [])) != {"h1", "h2"}:
                raise ActivationError("HTTPS servers must explicitly enable only HTTP/1.1 and HTTP/2")
            if server.get("automatic_https", {}).get("disable") is not True:
                raise ActivationError("automatic HTTPS must be disabled")
            for listener in server.get("listen", []):
                try:
                    address, port = listener.rsplit(":", 1)
                    address = ipaddress.ip_address(address.strip("[]"))
                except (ValueError, AttributeError):
                    raise ActivationError("listener is not an explicit private TCP/443 address") from None
                if port != "443" or not any(address.version == net.version and address in net for net in networks):
                    raise ActivationError("listener is not an explicit private TCP/443 address")
                listeners.add((str(address), 443))
        return listeners

    def socket_metadata(self):
        self.metadata(self.socket.parent, stat.S_ISDIR, self.ids[2], self.ids[3], 0o700)
        info = self.socket.lstat()
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != self.ids[2]
                or info.st_gid != self.ids[3] or info.st_mode & 0o077):
            raise ActivationError("Caddy administration socket is not private")

    def observed(self, configuration):
        self.active()
        self.socket_metadata()
        active = self.commands.configuration(self.socket)
        if active != configuration and active != self.runtime_configuration(configuration):
            raise ActivationError("active configuration differs from committed configuration")
        pid = self.commands.run(["/usr/bin/systemctl", "show", "--property=MainPID", "--value", "caddy.service"]).decode().strip()
        if not pid.isdigit() or int(pid) <= 0:
            raise ActivationError("Caddy service process could not be observed")
        observed = set()
        output = self.commands.run(["ss", "-H", "-lnptu"]).decode()
        for line in output.splitlines():
            if not re.search(r"\bpid=" + re.escape(pid) + r"(?:,|\))", line):
                continue
            fields = line.split()
            if len(fields) < 6 or fields[0] != "tcp":
                raise ActivationError("Caddy owns an unexpected network listener")
            try:
                address, port = fields[4].rsplit(":", 1)
                observed.add((str(ipaddress.ip_address(address.strip("[]"))), int(port)))
            except ValueError:
                raise ActivationError("Caddy owns an unexpected network listener") from None
        if observed != self.expected_listeners(configuration):
            raise ActivationError("Caddy network listeners differ from the declared listeners")

    def validate(self, config):
        self.metadata(config, stat.S_ISREG, self.ids[0], self.ids[3], 0o640)
        adapted = self.adapted(config)
        self.certificates(adapted)
        self.caddy("validate", config)
        return adapted

    def certificates(self, configuration):
        certificates = configuration.get("apps", {}).get("tls", {}).get("certificates", {}).get("load_files", [])
        def route_hosts(value):
            result = set()
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == "host" and isinstance(item, list):
                        result.update(item)
                    else:
                        result.update(route_hosts(item))
            elif isinstance(value, list):
                for item in value:
                    result.update(route_hosts(item))
            return result

        # The Caddyfile adapter tags explicit cert files and selects those tags
        # in the first matching SNI policy. Aggregate SAN coverage is insufficient:
        # a different loaded certificate must not hide a swapped assignment.
        selections = {}
        servers = configuration.get("apps", {}).get("http", {}).get("servers", {})
        for server in servers.values():
            for hostname in route_hosts(server.get("routes", [])):
                for policy in server.get("tls_connection_policies", []):
                    matcher = policy.get("match", {})
                    if set(matcher) - {"sni"}:
                        raise ActivationError("TLS policy uses an unsupported hostname matcher")
                    if "sni" in matcher and hostname not in matcher["sni"]:
                        continue
                    selection = policy.get("certificate_selection", {})
                    if set(selection) - {"any_tag", "all_tags"}:
                        raise ActivationError("TLS policy uses an unsupported certificate selector")
                    any_tags = set(selection.get("any_tag", []))
                    all_tags = set(selection.get("all_tags", []))
                    if not any_tags and not all_tags:
                        raise ActivationError("route has no explicit external certificate selection")
                    selections.setdefault(hostname, []).append((any_tags, all_tags))
                    break
                else:
                    raise ActivationError("route has no matching TLS certificate policy")
        hostnames = set(selections)
        covered = set()
        fingerprints = {hostname: set() for hostname in hostnames}
        for pair in certificates:
            certificate = pair.get("certificate", "")
            key = pair.get("key", "")
            match = re.fullmatch(r"/etc/caddy/tls/([A-Za-z0-9][A-Za-z0-9_-]{0,63})/current/fullchain\.pem", certificate)
            if match is None or key != certificate.removesuffix("fullchain.pem") + "privkey.pem":
                raise ActivationError("external TLS paths do not meet the certificate contract")
            base = self.config_dir / "tls" / match.group(1)
            self.metadata(base, stat.S_ISDIR, self.ids[0], self.ids[3], 0o750)
            current = base / "current"
            info = current.lstat()
            if not stat.S_ISLNK(info.st_mode) or info.st_uid != self.ids[0] or info.st_gid != self.ids[3]:
                raise ActivationError("certificate version selection is not an administrator-owned symlink")
            target = current.resolve(strict=True)
            if base not in target.parents:
                raise ActivationError("certificate version escapes its managed root")
            # Only the current pointer may introduce path indirection.
            relative = Path(os.readlink(current))
            raw = relative if relative.is_absolute() else base / relative
            if ".." in raw.parts:
                raise ActivationError("certificate version path contains traversal")
            cursor = base
            for component in target.relative_to(base).parts:
                cursor /= component
                self.metadata(cursor, stat.S_ISDIR, self.ids[0], self.ids[3], 0o750)
            if raw != target:
                raise ActivationError("certificate version has additional path indirection")
            for filename in ("fullchain.pem", "privkey.pem"):
                self.metadata(target / filename, stat.S_ISREG, self.ids[0], self.ids[3], 0o640)
            public = str(target / "fullchain.pem")
            dates = self.commands.run(["/usr/bin/openssl", "x509", "-in", public, "-noout", "-startdate", "-enddate"]).decode()
            try:
                bounds = dict(line.split("=", 1) for line in dates.splitlines())
                start = datetime.datetime.strptime(bounds["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                end = datetime.datetime.strptime(bounds["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
            except (ValueError, KeyError):
                raise ActivationError("certificate validity could not be established") from None
            if not start <= datetime.datetime.now(datetime.timezone.utc) < end:
                raise ActivationError("external certificate is not currently valid")
            sans = self.commands.run(["/usr/bin/openssl", "x509", "-in", public, "-noout", "-ext", "subjectAltName"]).decode()
            names = re.findall(r"DNS:([^,\s]+)", sans)
            leaf = self.commands.run(["/usr/bin/openssl", "x509", "-in", public, "-outform", "DER"])
            fingerprint = hashlib.sha256(leaf).hexdigest()
            tags = set(pair.get("tags", []))
            for hostname in hostnames:
                if not all((not any_tags or any_tags & tags) and all_tags <= tags
                           for any_tags, all_tags in selections[hostname]):
                    continue
                for name in names:
                    name = name.lower()
                    if hostname == name or (name.startswith("*.") and hostname.partition(".")[2] == name[2:]):
                        covered.add(hostname)
                        fingerprints[hostname].add(fingerprint)
        if covered != hostnames:
            raise ActivationError("selected external certificates do not cover every declared hostname with a DNS SAN")
        return fingerprints

    def served_certificates(self, configuration, fingerprints):
        if not fingerprints:
            return
        context = ssl.create_default_context()
        for hostname, accepted in fingerprints.items():
            for address, port in self.expected_listeners(configuration):
                try:
                    with socket.create_connection((address, port), timeout=10) as connection:
                        with context.wrap_socket(connection, server_hostname=hostname) as tls:
                            actual = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
                    if actual not in accepted:
                        raise ActivationError("served TLS certificate differs from the selected external version")
                except OSError:
                    raise ActivationError("served TLS trust, hostname or connection verification failed") from None

    def served_tls(self, configuration):
        self.served_certificates(configuration, self.certificates(configuration))

    def restore_previous(self, previous, runtime):
        self.durable_write(self.boot, previous, 0o640, self.ids[3])
        if runtime:
            desired = self.validate(self.boot)
            try:
                self.observed(desired)
            except ActivationError:
                loaded = self.reload_configuration(desired)
                self.observed(loaded)

    def recover_pending(self, runtime=False):
        if not self.pending.exists():
            if self.pending.is_symlink():
                raise ActivationError("transaction marker is an unexpected symlink")
            return
        self.metadata(self.pending, stat.S_ISREG, self.ids[0], self.ids[1], 0o600)
        self.metadata(self.previous, stat.S_ISREG, self.ids[0], self.ids[1], 0o600)
        try:
            record = json.loads(self.pending.read_bytes())
        except ValueError:
            raise ActivationError("transaction record is unreadable; operator recovery is required") from None
        previous = self.previous.read_bytes()
        if (not isinstance(record, dict) or set(record) != {"previous", "candidate"}
                or hashlib.sha256(previous).hexdigest() != record["previous"]
                or hashlib.sha256(self.boot.read_bytes()).hexdigest() not in (record["previous"], record["candidate"])):
            raise ActivationError("transaction state is ambiguous; operator recovery is required")
        self.restore_previous(previous, runtime)
        self.clear_pending()

    def recover(self):
        with self.locked():
            self.recover_pending()

    def apply(self):
        with self.locked():
            self.active()
            self.recover_pending(runtime=True)
            self.metadata(self.candidate, stat.S_ISREG, self.ids[0], self.ids[3], 0o640)
            candidate = self.candidate.read_bytes()
            desired = self.validate(self.candidate)
            self.metadata(self.candidate, stat.S_ISREG, self.ids[0], self.ids[3], 0o640)
            if self.candidate.read_bytes() != candidate:
                raise ActivationError("candidate changed during validation; rerun provisioning")
            previous = self.boot.read_bytes()
            if candidate == previous:
                try:
                    self.observed(desired)
                    self.served_tls(desired)
                    return "unchanged"
                except ActivationError:
                    pass
            self.active()
            self.socket_metadata()
            # The backup and marker are both durable before changing the boot file.
            self.durable_write(self.previous, previous, 0o600, self.ids[1])
            record = json.dumps({"previous": hashlib.sha256(previous).hexdigest(),
                                 "candidate": hashlib.sha256(candidate).hexdigest()}).encode()
            self.durable_write(self.pending, record, 0o600, self.ids[1])
            try:
                self.durable_write(self.boot, candidate, 0o640, self.ids[3])
                loaded = self.reload_configuration(desired)
                self.observed(loaded)
                self.served_tls(desired)
                self.clear_pending()
            except (ActivationError, OSError) as failure:
                reason = str(failure) if isinstance(failure, ActivationError) else "managed filesystem operation failed"
                try:
                    if self.pending.exists() or self.pending.is_symlink():
                        self.recover_pending(runtime=True)
                    else:
                        # Cleanup may have removed the marker before a failed fsync.
                        # Retain the in-memory rollback authority until commit returns.
                        self.restore_previous(previous, runtime=True)
                        self.fsync_directory(self.state)
                except (ActivationError, OSError):
                    raise ActivationError("activation failed: " + reason + "; recovery is incomplete; operator recovery is required") from None
                raise ActivationError("activation failed: " + reason + "; previous boot and runtime configuration restored") from None
            return "changed"

    def reload(self, inherited=False):
        with self.locked(inherited=inherited):
            self.active()
            if self.pending.exists() or self.pending.is_symlink():
                raise ActivationError("configuration recovery is required before certificate reload")
            desired = self.validate(self.boot)
            self.socket_metadata()
            loaded = self.reload_configuration(desired)
            self.observed(loaded)

    def verify(self, inherited=False):
        with self.locked(shared=True, inherited=inherited):
            if self.pending.exists() or self.pending.is_symlink():
                raise ActivationError("configuration recovery is pending")
            desired = self.adapted(self.boot)
            fingerprints = self.certificates(desired)
            self.observed(desired)
            self.served_certificates(desired, fingerprints)


def main(arguments=None):
    args = list(sys.argv[1:] if arguments is None else arguments)
    if args not in (["apply"], ["recover"], ["reload"], ["reload", "--lock-held"], ["verify"], ["verify", "--lock-held"]):
        print("usage: homelab-reverse-proxy {apply|recover|reload [--lock-held]|verify [--lock-held]}", file=sys.stderr)
        return 2
    try:
        if os.geteuid() != 0:
            raise ActivationError("this operation requires the root identity")
        activator = Activator()
        if args[0] in ("reload", "verify"):
            getattr(activator, args[0])(inherited=len(args) == 2)
        else:
            result = getattr(activator, args[0])()
            if args[0] == "apply":
                print(result)
        return 0
    except ActivationError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, KeyError):
        # Do not print exceptions from external libraries or protected input paths.
        print("reverse proxy operation failed; check managed state and service status", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
