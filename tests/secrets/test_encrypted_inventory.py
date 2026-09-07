"""Non-decrypting checks must reject plaintext without quoting its contents."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("encrypted_validation", ROOT / "scripts/secrets/validate.py")


class EncryptedInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SPEC.origin or not Path(SPEC.origin).exists():
            return
        cls.validation = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(cls.validation)

    def setUp(self):
        self.assertTrue(hasattr(self, "validation"), "encrypted inventory validator is missing")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "secrets.sops.yml"
        self.recipient = "age1" + "q" * 58
        self.enc = "ENC[AES256_GCM,data:YQ==,iv:YQ==,tag:YQ==,type:str]"

    def document(self):
        return {
            "nested": {"values": [self.enc, self.enc], "empty": None},
            "sops": {"age": [{"recipient": self.recipient, "enc": "-----BEGIN AGE ENCRYPTED FILE-----\nYQ==\n-----END AGE ENCRYPTED FILE-----\n"}],
                     "mac": self.enc, "version": "3.13.2", "encrypted_regex": "^(.*)$"},
        }

    def check(self, document):
        import yaml
        self.source.write_text(yaml.safe_dump(document))
        return self.validation.validate_encrypted_file(self.source, {self.recipient})

    def test_encrypted_nested_values_are_accepted_without_decryption(self):
        self.assertEqual([], self.check(self.document()))

    def test_plaintext_nested_value_is_rejected_without_disclosure(self):
        document = self.document()
        document["nested"]["values"].append("private-fixture-marker")
        errors = self.check(document)
        self.assertTrue(errors)
        self.assertNotIn("private-fixture-marker", str(errors))

    def test_wrong_or_missing_recipients_are_rejected(self):
        for recipients in ([], [{"recipient": "age1" + "p" * 58, "enc": "fake"}]):
            document = self.document()
            document["sops"]["age"] = recipients
            self.assertTrue(self.check(document))

    def test_malformed_mac_and_missing_metadata_are_rejected(self):
        document = self.document()
        document["sops"]["mac"] = "private-fixture-marker"
        self.assertTrue(self.check(document))
        del document["sops"]
        self.assertTrue(self.check(document))

    def test_selective_encryption_and_other_key_backends_are_rejected(self):
        for field, value in (("encrypted_regex", "password"), ("kms", [{"arn": "fixture"}])):
            document = self.document()
            document["sops"][field] = value
            self.assertTrue(self.check(document))

    def test_duplicate_yaml_keys_and_invalid_yaml_do_not_expose_input(self):
        for data in ("password: private-fixture-marker\npassword: duplicate\n", "password: [private-fixture-marker"):
            self.source.write_text(data)
            errors = self.validation.validate_encrypted_file(self.source, {self.recipient})
            self.assertTrue(errors)
            self.assertNotIn("private-fixture-marker", str(errors))

    def test_symlink_is_rejected_before_reading(self):
        self.source.symlink_to(self.root / "nonexistent")
        self.assertTrue(self.validation.validate_encrypted_file(self.source, {self.recipient}))

    def test_missing_required_ciphertext_fails_without_reading_legacy_files(self):
        errors = self.validation.validate_repository(self.root)
        self.assertTrue(errors)

    def test_malformed_public_recipient_policy_fails_without_traceback(self):
        import yaml
        policy = {"creation_rules": [{"path_regex": self.validation.INVENTORY_PATTERN,
                                     "encrypted_regex": "^(.*)$", "age": 123}]}
        (self.root / ".sops.yaml").write_text(yaml.safe_dump(policy))
        errors = self.validation.validate_repository(self.root)
        self.assertTrue(errors)
