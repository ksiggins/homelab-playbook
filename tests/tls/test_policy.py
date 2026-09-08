"""Policy and untrusted file boundary tests; no inventory or network."""
import copy
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "roles/tls_automation/files"))
from tls_runtime.policy import parse_policy, read_bounded, secure_path


def example_policy():
    return {"namespace": "infra.example.com", "email": "acme@example.com",
            "reader_gid": 2001,
            "endpoints": [{"hostname": "modem.infra.example.com", "address": "192.0.2.10", "port": 443}]}


class PolicyTests(unittest.TestCase):
    def test_exact_wildcard_and_private_listener(self):
        policy = parse_policy(json.dumps(example_policy()).encode())
        self.assertEqual(policy.sans, ["*.infra.example.com"])
        self.assertEqual(policy.endpoints[0]["hostname"], "modem.infra.example.com")

    def test_reject_invalid_or_executable_policy(self):
        cases = [{"namespace": "example.com"}, {"namespace": "infra.com"},
                 {"namespace": "infra.EXAMPLE.com"}, {"namespace": "infra.example.com/.."},
                 {"namespace": "infra.example.com."}, {"email": "--config=bad"},
                 {"reader_gid": True}, {"reader_gid": 0}, {"reader_gid": "2001"},
                 {"reload": "whoami"}, {"path": "/tmp/out"}, {"sans": ["*.example.com"]},
                 {"endpoints": []}]
        for update in cases:
            with self.subTest(update=update):
                raw = example_policy()
                raw.update(update)
                with self.assertRaises(ValueError):
                    parse_policy(json.dumps(raw).encode())

    def test_reject_endpoint_escape_or_invalid_address(self):
        for update in [{"hostname": "udm.example.com"}, {"hostname": "x.y.infra.example.com"},
                       {"hostname": "infra.example.com"}, {"hostname": "*.infra.example.com"},
                       {"address": "8.8.8.8"}, {"address": "127.0.0.1"}, {"address": "::"},
                       {"address": "fe80::1%eth0"}, {"address": "backend.example.com"},
                       {"port": True}, {"port": 0}, {"port": 65536}, {"command": "reload"}]:
            with self.subTest(update=update):
                raw = example_policy()
                raw["endpoints"][0].update(update)
                with self.assertRaises(ValueError):
                    parse_policy(json.dumps(raw).encode())

    def test_reject_duplicate_keys_and_endpoints(self):
        raw = example_policy()
        raw["endpoints"].append(copy.deepcopy(raw["endpoints"][0]))
        with self.assertRaises(ValueError):
            parse_policy(json.dumps(raw).encode())
        with self.assertRaises(ValueError):
            parse_policy(b'{"namespace":"infra.example.com","namespace":"infra.evil.com"}')


class InputBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.file = self.root / "input"
        self.file.write_bytes(b"certificate bytes")
        self.file.chmod(0o600)

    def read(self, name="input", maximum=100):
        return read_bounded(self.root, name, os.getuid(), maximum)

    def test_regular_file(self):
        self.assertEqual(self.read(), b"certificate bytes")

    def test_no_symlink_or_hardlink(self):
        (self.root / "link").symlink_to(self.file)
        with self.assertRaises((ValueError, OSError)):
            self.read("link")
        os.link(self.file, self.root / "hardlink")
        with self.assertRaises(ValueError):
            self.read("hardlink")

    def test_no_parent_traversal_or_symlink_directory(self):
        for name in ["../input", "/etc/passwd"]:
            with self.assertRaises(ValueError):
                self.read(name)
        (self.root / "directory").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            self.read("directory/input")

    def test_reject_write_permissions_oversize_wrong_owner(self):
        with self.assertRaises(ValueError):
            self.read(maximum=2)
        with self.assertRaises(ValueError):
            read_bounded(self.root, "input", os.getuid() + 1, 100)
        self.file.chmod(0o620)
        with self.assertRaises(ValueError):
            self.read()

    def test_secure_path_rejects_untrusted_ancestor(self):
        target = Path("/trusted/unsafe/target")
        metadata = {
            "/": SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0),
            "/trusted": SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0),
            "/trusted/unsafe": SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o777, st_uid=0
            ),
            str(target): SimpleNamespace(
                st_mode=stat.S_IFREG | 0o600, st_uid=os.getuid(), st_nlink=1
            ),
        }

        with patch.object(
            Path, "lstat", autospec=True,
            side_effect=lambda candidate: metadata[str(candidate)]
        ), self.assertRaisesRegex(ValueError, "unsafe trusted parent directory"):
            secure_path(target, os.getuid())

    def test_secure_path_rejects_symlink_ancestor(self):
        target = Path("/trusted/linked/target")
        metadata = {
            "/": SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0),
            "/trusted": SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0),
            "/trusted/linked": SimpleNamespace(
                st_mode=stat.S_IFLNK | 0o777, st_uid=0
            ),
            str(target): SimpleNamespace(
                st_mode=stat.S_IFREG | 0o600, st_uid=os.getuid(), st_nlink=1
            ),
        }

        with patch.object(
            Path, "lstat", autospec=True,
            side_effect=lambda candidate: metadata[str(candidate)]
        ), self.assertRaisesRegex(ValueError, "unsafe trusted parent directory"):
            secure_path(target, os.getuid())


if __name__ == "__main__":
    unittest.main()
