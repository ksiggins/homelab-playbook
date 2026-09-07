#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hmac
import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Sequence


SERVICE = "homelab-playbook.sops.age"
ACCOUNT = "operator"
SECURITY = "/usr/bin/security"
REPO_ROOT = Path(__file__).resolve().parents[2]
IDENTITY_PATTERN = re.compile(r"AGE-SECRET-KEY-1[0-9A-Z]+")
RECIPIENT_PATTERN = re.compile(r"age1[0-9a-z]+")


class SetupError(RuntimeError):
    """An expected setup failure safe to show without private data."""


def _run(command: Sequence[str], *, input_data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            list(command),
            input=input_data,
            check=False,
            capture_output=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SetupError("a required local command could not be executed") from error


def _outside_checkout(path: Path) -> Path:
    resolved = path.expanduser().resolve(strict=False)
    if resolved.is_relative_to(REPO_ROOT):
        raise SetupError("the encrypted recovery backup must be outside this checkout")
    for ancestor in (resolved.parent, *resolved.parent.parents):
        if (ancestor / ".git").exists():
            raise SetupError("the encrypted recovery backup must be outside every checkout")
    return resolved


def _identity(data: bytes) -> str:
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise SetupError("the age identity has an invalid format") from error
    identities = [line for line in lines if IDENTITY_PATTERN.fullmatch(line)]
    if len(identities) != 1 or any(
        line and not line.startswith("# ") and line != identities[0] for line in lines
    ):
        raise SetupError("the age identity has an invalid format")
    return identities[0]


def _login_keychain() -> Path:
    return Path.home() / "Library" / "Keychains" / "login.keychain-db"


def _security_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _recipient(identity: str) -> str:
    result = _run(["age-keygen", "-y"], input_data=f"{identity}\n".encode())
    if result.returncode != 0:
        raise SetupError("could not derive the public age recipient")
    try:
        recipient = result.stdout.rstrip(b"\r\n").decode("ascii")
    except UnicodeDecodeError as error:
        raise SetupError("age-keygen returned an invalid public recipient") from error
    if not RECIPIENT_PATTERN.fullmatch(recipient):
        raise SetupError("age-keygen returned an invalid public recipient")
    return recipient


def _read_keychain() -> str | None:
    result = _run(
        [
            SECURITY,
            "find-generic-password",
            "-a",
            ACCOUNT,
            "-s",
            SERVICE,
            "-w",
            str(_login_keychain()),
        ]
    )
    if result.returncode == 44:
        return None
    if result.returncode != 0:
        raise SetupError("could not read the age identity from macOS Keychain")
    return _identity(result.stdout)


def _store_keychain(identity: str) -> None:
    command = (
        f"add-generic-password -a {ACCOUNT} -s {SERVICE} -w {identity} "
        f"{_security_quote(str(_login_keychain()))}\n"
    ).encode("utf-8")
    result = _run([SECURITY, "-i"], input_data=command)
    if result.returncode != 0:
        raise SetupError("could not store the age identity in macOS Keychain")


def _verify_keychain(identity: str) -> None:
    readback = _read_keychain()
    if readback is None or not hmac.compare_digest(readback, identity):
        raise SetupError("macOS Keychain read-back did not match the age identity")


def _generate_identity() -> str:
    result = _run(["age-keygen"])
    if result.returncode != 0:
        raise SetupError("could not generate the age identity")
    return _identity(result.stdout)


def _encrypt_backup(identity: str, path: Path) -> None:
    if path.exists():
        raise SetupError("the encrypted recovery backup already exists")
    result = _run(
        ["age", "--encrypt", "--passphrase"],
        input_data=f"{identity}\n".encode("ascii"),
    )
    if result.returncode != 0 or not result.stdout:
        raise SetupError("could not encrypt the recovery backup")

    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(descriptor, "wb") as destination:
            descriptor = None
            destination.write(result.stdout)
            destination.flush()
            os.fsync(destination.fileno())
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise SetupError("could not write the encrypted recovery backup") from error


def _decrypt_backup(path: Path) -> str:
    if not path.is_file():
        raise SetupError("the encrypted recovery backup is unavailable")
    result = _run(["age", "--decrypt", str(path)])
    if result.returncode != 0:
        raise SetupError("could not decrypt the recovery backup")
    return _identity(result.stdout)


def backup(path: Path) -> str:
    if _read_keychain() is not None:
        raise SetupError("the Keychain item already exists; refusing to replace it")
    identity = _generate_identity()
    _encrypt_backup(identity, path)
    _store_keychain(identity)
    _verify_keychain(identity)
    return _recipient(identity)


def restore(path: Path) -> str:
    identity = _decrypt_backup(path)
    existing = _read_keychain()
    if existing is None:
        _store_keychain(identity)
        _verify_keychain(identity)
    elif not hmac.compare_digest(existing, identity):
        raise SetupError("the Keychain item contains a different age identity")
    return _recipient(identity)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create or restore the repository age identity in macOS Keychain."
    )
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument(
        "--backup",
        type=Path,
        metavar="PATH",
        help="generate an identity and write its encrypted recovery backup",
    )
    operation.add_argument(
        "--restore",
        type=Path,
        metavar="PATH",
        help="restore an identity from an encrypted recovery backup",
    )
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(arguments)
    try:
        if platform.system() != "Darwin":
            raise SetupError("Keychain setup is supported only on macOS")
        if options.backup is not None:
            path = _outside_checkout(options.backup)
            recipient = backup(path)
        else:
            path = _outside_checkout(options.restore)
            recipient = restore(path)
    except SetupError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print(f"Recipient: {recipient}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
