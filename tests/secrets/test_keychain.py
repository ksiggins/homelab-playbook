from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
HELPER_PATH = REPO_ROOT / "scripts" / "secrets" / "age-keychain.sh"
SETUP_PATH = REPO_ROOT / "scripts" / "secrets" / "keychain_setup.py"
IDENTITY = "AGE-SECRET-KEY-1SYNTHETIC000"
OTHER_IDENTITY = "AGE-SECRET-KEY-1SYNTHETIC999"
RECIPIENT = "age1syntheticrecipient"
ENCRYPTED_BACKUP = b"age-encryption.org/v1\nsynthetic encrypted bytes\n"


def run_helper(functions: str) -> subprocess.CompletedProcess[str]:
    program = f"""
source "$1"
{functions}
main
"""
    return subprocess.run(
        ["/bin/bash", "-c", program, "test", str(HELPER_PATH)],
        check=False,
        capture_output=True,
        text=True,
    )


def load_setup() -> ModuleType:
    if not SETUP_PATH.is_file():
        raise AssertionError(f"missing setup program: {SETUP_PATH}")
    spec = importlib.util.spec_from_file_location("keychain_setup", SETUP_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError(f"could not load setup program: {SETUP_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RetrievalHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(HELPER_PATH.is_file(), f"missing helper: {HELPER_PATH}")

    def test_emits_the_complete_identity_only_after_a_successful_read(self) -> None:
        result = run_helper(
            f"""
platform_name() {{ printf '%s\\n' Darwin; }}
stdout_is_terminal() {{ return 1; }}
read_identity() {{ printf '%s\\n' '{IDENTITY}'; }}
"""
        )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(f"{IDENTITY}\n", result.stdout)
        self.assertEqual("", result.stderr)

    def test_refuses_to_write_an_identity_to_a_terminal(self) -> None:
        result = run_helper(
            f"""
platform_name() {{ printf '%s\\n' Darwin; }}
stdout_is_terminal() {{ return 0; }}
read_identity() {{ printf '%s\\n' '{IDENTITY}'; }}
"""
        )

        self.assertNotEqual(0, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertNotIn(IDENTITY, result.stderr)

    def test_fails_closed_on_a_non_macos_platform(self) -> None:
        result = run_helper(
            """
platform_name() { printf '%s\n' Linux; }
stdout_is_terminal() { return 1; }
read_identity() { printf '%s\n' SHOULD-NOT-BE-READ; }
"""
        )

        self.assertNotEqual(0, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertNotIn("SHOULD-NOT-BE-READ", result.stderr)

    def test_discards_partial_output_and_diagnostics_when_keychain_read_fails(self) -> None:
        result = run_helper(
            f"""
platform_name() {{ printf '%s\\n' Darwin; }}
stdout_is_terminal() {{ return 1; }}
read_identity() {{ printf '%s\\n' '{IDENTITY}'; printf '%s\\n' '{OTHER_IDENTITY}' >&2; return 1; }}
"""
        )

        self.assertNotEqual(0, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertNotIn(IDENTITY, result.stderr)
        self.assertNotIn(OTHER_IDENTITY, result.stderr)

    def test_rejects_malformed_keychain_content(self) -> None:
        result = run_helper(
            """
platform_name() { printf '%s\n' Darwin; }
stdout_is_terminal() { return 1; }
read_identity() { printf '%s\n' 'malformed identity'; }
"""
        )

        self.assertNotEqual(0, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertNotIn("malformed identity", result.stderr)


class SetupCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.setup = load_setup()
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.backup = Path(self.temporary_directory.name) / "recovery.age"

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def invoke(
        self,
        arguments: list[str],
        responses: list[subprocess.CompletedProcess[bytes]],
    ) -> tuple[int, str, str, mock.Mock]:
        runner = mock.Mock(side_effect=responses)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(self.setup.platform, "system", return_value="Darwin"),
            mock.patch.object(self.setup.subprocess, "run", runner),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = self.setup.main(arguments)
        return result, stdout.getvalue(), stderr.getvalue(), runner

    def test_backup_writes_only_ciphertext_and_reports_only_the_recipient(self) -> None:
        responses = [
            subprocess.CompletedProcess([], 44, b"", b"not found"),
            subprocess.CompletedProcess([], 0, IDENTITY.encode() + b"\n", b"public hint"),
            subprocess.CompletedProcess([], 0, ENCRYPTED_BACKUP, b""),
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 0, IDENTITY.encode() + b"\n", b""),
            subprocess.CompletedProcess([], 0, RECIPIENT.encode() + b"\n", b""),
        ]

        result, stdout, stderr, runner = self.invoke(
            ["--backup", str(self.backup)], responses
        )

        self.assertEqual(0, result, stderr)
        self.assertEqual(f"Recipient: {RECIPIENT}\n", stdout)
        self.assertEqual("", stderr)
        self.assertEqual(ENCRYPTED_BACKUP, self.backup.read_bytes())
        self.assertEqual(0o600, self.backup.stat().st_mode & 0o777)
        all_arguments = [argument for call in runner.call_args_list for argument in call.args[0]]
        self.assertNotIn(IDENTITY, all_arguments)
        security_input = runner.call_args_list[3].kwargs["input"]
        self.assertIn(IDENTITY.encode(), security_input)
        login_keychain = str(Path.home() / "Library/Keychains/login.keychain-db")
        self.assertEqual(login_keychain, runner.call_args_list[0].args[0][-1])
        self.assertIn(login_keychain.encode(), security_input)
        self.assertNotIn(b" -U ", security_input)

    def test_backup_supports_a_spaced_unicode_home_without_exposing_the_identity(self) -> None:
        responses = [
            subprocess.CompletedProcess([], 44, b"", b"not found"),
            subprocess.CompletedProcess([], 0, IDENTITY.encode() + b"\n", b""),
            subprocess.CompletedProcess([], 0, ENCRYPTED_BACKUP, b""),
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 0, IDENTITY.encode() + b"\n", b""),
            subprocess.CompletedProcess([], 0, RECIPIENT.encode() + b"\n", b""),
        ]
        login_keychain = Path(
            "/Users/Opérator Name/Library/Keychains refer/login.keychain-db"
        )

        with mock.patch.object(
            self.setup, "_login_keychain", return_value=login_keychain
        ):
            result, stdout, stderr, runner = self.invoke(
                ["--backup", str(self.backup)], responses
            )

        self.assertEqual(0, result, stderr)
        self.assertEqual(f"Recipient: {RECIPIENT}\n", stdout)
        self.assertNotIn(IDENTITY, stdout)
        all_arguments = [
            argument for call in runner.call_args_list for argument in call.args[0]
        ]
        self.assertNotIn(IDENTITY, all_arguments)
        security_input = runner.call_args_list[3].kwargs["input"]
        self.assertIn(str(login_keychain).encode("utf-8"), security_input)
        self.assertIn(IDENTITY.encode(), security_input)

    def test_backup_refuses_an_existing_keychain_identity_without_generating(self) -> None:
        responses = [
            subprocess.CompletedProcess([], 0, IDENTITY.encode() + b"\n", b""),
        ]

        result, stdout, stderr, runner = self.invoke(
            ["--backup", str(self.backup)], responses
        )

        self.assertNotEqual(0, result)
        self.assertEqual("", stdout)
        self.assertNotIn(IDENTITY, stderr)
        self.assertEqual(1, runner.call_count)
        self.assertFalse(self.backup.exists())

    def test_backup_failure_does_not_leave_a_partial_file_or_secret_trace(self) -> None:
        responses = [
            subprocess.CompletedProcess([], 44, b"", b"not found"),
            subprocess.CompletedProcess([], 0, IDENTITY.encode() + b"\n", b""),
            subprocess.CompletedProcess([], 1, b"partial ciphertext", IDENTITY.encode()),
        ]

        result, stdout, stderr, _ = self.invoke(
            ["--backup", str(self.backup)], responses
        )

        self.assertNotEqual(0, result)
        self.assertEqual("", stdout)
        self.assertNotIn(IDENTITY, stderr)
        self.assertFalse(self.backup.exists())

    def test_restore_is_idempotent_when_keychain_has_the_same_identity(self) -> None:
        self.backup.write_bytes(ENCRYPTED_BACKUP)
        responses = [
            subprocess.CompletedProcess([], 0, IDENTITY.encode() + b"\n", b""),
            subprocess.CompletedProcess([], 0, IDENTITY.encode() + b"\n", b""),
            subprocess.CompletedProcess([], 0, RECIPIENT.encode() + b"\n", b""),
        ]

        result, stdout, stderr, runner = self.invoke(
            ["--restore", str(self.backup)], responses
        )

        self.assertEqual(0, result, stderr)
        self.assertEqual(f"Recipient: {RECIPIENT}\n", stdout)
        self.assertEqual("", stderr)
        self.assertEqual(3, runner.call_count)
        self.assertNotIn(["/usr/bin/security", "-i"], [call.args[0] for call in runner.call_args_list])

    def test_restore_refuses_to_replace_a_different_keychain_identity(self) -> None:
        self.backup.write_bytes(ENCRYPTED_BACKUP)
        responses = [
            subprocess.CompletedProcess([], 0, IDENTITY.encode() + b"\n", b""),
            subprocess.CompletedProcess([], 0, OTHER_IDENTITY.encode() + b"\n", b""),
        ]

        result, stdout, stderr, runner = self.invoke(
            ["--restore", str(self.backup)], responses
        )

        self.assertNotEqual(0, result)
        self.assertEqual("", stdout)
        self.assertNotIn(IDENTITY, stderr)
        self.assertNotIn(OTHER_IDENTITY, stderr)
        self.assertEqual(2, runner.call_count)

    def test_restore_stores_a_missing_identity_and_verifies_readback(self) -> None:
        self.backup.write_bytes(ENCRYPTED_BACKUP)
        responses = [
            subprocess.CompletedProcess([], 0, IDENTITY.encode() + b"\n", b""),
            subprocess.CompletedProcess([], 44, b"", b"not found"),
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 0, IDENTITY.encode() + b"\n", b""),
            subprocess.CompletedProcess([], 0, RECIPIENT.encode() + b"\n", b""),
        ]

        result, stdout, stderr, runner = self.invoke(
            ["--restore", str(self.backup)], responses
        )

        self.assertEqual(0, result, stderr)
        self.assertEqual(f"Recipient: {RECIPIENT}\n", stdout)
        self.assertEqual("", stderr)
        store_call = runner.call_args_list[2]
        self.assertEqual(["/usr/bin/security", "-i"], store_call.args[0])
        self.assertIn(IDENTITY.encode(), store_call.kwargs["input"])

    def test_backup_rejects_a_failed_keychain_readback_without_a_secret_trace(self) -> None:
        responses = [
            subprocess.CompletedProcess([], 44, b"", b"not found"),
            subprocess.CompletedProcess([], 0, IDENTITY.encode() + b"\n", b""),
            subprocess.CompletedProcess([], 0, ENCRYPTED_BACKUP, b""),
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 0, OTHER_IDENTITY.encode() + b"\n", b""),
        ]

        result, stdout, stderr, _ = self.invoke(
            ["--backup", str(self.backup)], responses
        )

        self.assertNotEqual(0, result)
        self.assertEqual("", stdout)
        self.assertNotIn(IDENTITY, stderr)
        self.assertNotIn(OTHER_IDENTITY, stderr)

    def test_rejects_malformed_recipient_output_without_leaking_it(self) -> None:
        malformed_recipient = f"age1invalid {IDENTITY}"
        responses = [
            subprocess.CompletedProcess([], 44, b"", b"not found"),
            subprocess.CompletedProcess([], 0, IDENTITY.encode() + b"\n", b""),
            subprocess.CompletedProcess([], 0, ENCRYPTED_BACKUP, b""),
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 0, IDENTITY.encode() + b"\n", b""),
            subprocess.CompletedProcess([], 0, malformed_recipient.encode(), b""),
        ]

        result, stdout, stderr, _ = self.invoke(
            ["--backup", str(self.backup)], responses
        )

        self.assertNotEqual(0, result)
        self.assertEqual("", stdout)
        self.assertNotIn(IDENTITY, stderr)

    def test_refuses_backup_paths_inside_the_checkout(self) -> None:
        in_checkout = REPO_ROOT / ".tmp" / "recovery.age"

        result, stdout, stderr, runner = self.invoke(
            ["--backup", str(in_checkout)], []
        )

        self.assertNotEqual(0, result)
        self.assertEqual("", stdout)
        self.assertIn("outside", stderr)
        runner.assert_not_called()

    def test_refuses_backup_paths_inside_another_git_checkout(self) -> None:
        checkout = Path(self.temporary_directory.name) / "other-checkout"
        (checkout / ".git").mkdir(parents=True)
        in_checkout = checkout / "recovery.age"

        result, stdout, stderr, runner = self.invoke(
            ["--backup", str(in_checkout)], []
        )

        self.assertNotEqual(0, result)
        self.assertEqual("", stdout)
        self.assertIn("checkout", stderr)
        runner.assert_not_called()

    def test_fails_closed_on_a_non_macos_platform(self) -> None:
        runner = mock.Mock()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(self.setup.platform, "system", return_value="Linux"),
            mock.patch.object(self.setup.subprocess, "run", runner),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = self.setup.main(["--backup", str(self.backup)])

        self.assertNotEqual(0, result)
        self.assertEqual("", stdout.getvalue())
        self.assertIn("macOS", stderr.getvalue())
        runner.assert_not_called()


class AgeCompatibilityTests(unittest.TestCase):
    def test_accepts_the_real_age_keygen_identity_format(self) -> None:
        setup = load_setup()
        generated = subprocess.run(
            ["age-keygen"],
            check=False,
            capture_output=True,
        )
        self.assertEqual(0, generated.returncode)

        identity = setup._identity(generated.stdout)
        derived = subprocess.run(
            ["age-keygen", "-y"],
            input=f"{identity}\n".encode(),
            check=False,
            capture_output=True,
        )

        self.assertEqual(0, derived.returncode)
        self.assertTrue(derived.stdout.startswith(b"age1"))


if __name__ == "__main__":
    unittest.main()
