"""Disposable integration certificates must pass strict native verification."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/tls"))
from cert_fixtures import EphemeralCA


class TLSFixtureMaterialTests(unittest.TestCase):
    def test_generated_integration_leaf_passes_strict_server_verification(self):
        spec = importlib.util.spec_from_file_location(
            "tls_integration_fixture",
            ROOT / "roles/reverse_proxy/molecule/default/tls_integration.py")
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        with tempfile.TemporaryDirectory() as directory:
            fixture.FIXTURE = Path(directory)
            authority = EphemeralCA()
            authority.write_certificate(fixture.FIXTURE / "ca.pem")
            (fixture.FIXTURE / "ca.key").write_bytes(authority.key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
            fixture.create_material(1)
            result = subprocess.run(
                ["openssl", "verify", "-x509_strict", "-purpose", "sslserver",
                 "-verify_hostname", "room-alert.infra.example.com",
                 "-CAfile", str(fixture.FIXTURE / "ca.pem"),
                 str(fixture.FIXTURE / "issued-1.pem")],
                capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(0, result.returncode, result.stderr)
