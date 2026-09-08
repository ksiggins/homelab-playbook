"""Validate untrusted certificate material before privileged publication."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization


_CERTIFICATE_PEM = re.compile(
    br"-----BEGIN CERTIFICATE-----\s+.+?\s+-----END CERTIFICATE-----",
    re.DOTALL,
)
_OPENSSL = "/usr/bin/openssl"
_VERIFY_TIMEOUT_SECONDS = 10


def _certificate_blocks(fullchain: bytes) -> List[bytes]:
    blocks = _CERTIFICATE_PEM.findall(fullchain)
    if not blocks or _CERTIFICATE_PEM.sub(b"", fullchain).strip():
        raise ValueError("certificate chain is malformed")
    try:
        for block in blocks:
            x509.load_pem_x509_certificate(block)
    except (TypeError, ValueError) as error:
        raise ValueError("certificate chain is malformed") from error
    return blocks


def _canonical_dns_name(value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("approved DNS SAN is invalid")
    candidate = value[:-1] if value.endswith(".") else value
    try:
        canonical = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("approved DNS SAN is invalid") from error
    if not canonical or canonical.startswith(".") or canonical.endswith("."):
        raise ValueError("approved DNS SAN is invalid")
    return canonical


def _utc_certificate_time(certificate: x509.Certificate, name: str) -> datetime:
    aware_name = name + "_utc"
    if hasattr(certificate, aware_name):
        return getattr(certificate, aware_name)
    return getattr(certificate, name).replace(tzinfo=timezone.utc)


def _write_private_file(path: Path, contents: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)


def _verify_chain(
    blocks: List[bytes], ca_file: Optional[str], verification_time: Optional[int]
) -> None:
    with tempfile.TemporaryDirectory(prefix="homelab-tls-verify-") as temporary:
        directory = Path(temporary)
        leaf_path = directory / "leaf.pem"
        _write_private_file(leaf_path, blocks[0] + b"\n")
        command = [_OPENSSL, "verify", "-purpose", "sslserver"]
        if ca_file is not None:
            command.extend(["-CAfile", ca_file])
        if verification_time is not None:
            command.extend(["-attime", str(verification_time)])
        if len(blocks) > 1:
            chain_path = directory / "chain.pem"
            _write_private_file(chain_path, b"\n".join(blocks[1:]) + b"\n")
            command.extend(["-untrusted", str(chain_path)])
        command.append(str(leaf_path))
        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                timeout=_VERIFY_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("certificate chain verification unavailable") from error
        if result.returncode != 0:
            raise ValueError("certificate chain verification failed")


def _validate_certificate(
    fullchain: bytes,
    private_key: bytes,
    sans: List[str],
    minimum_seconds: int,
    ca_file: Optional[str],
    allow_historical_expiry: bool,
) -> str:
    if not isinstance(fullchain, bytes) or not isinstance(private_key, bytes):
        raise ValueError("certificate material must be bytes")
    if not isinstance(minimum_seconds, int) or isinstance(minimum_seconds, bool):
        raise ValueError("minimum lifetime is invalid")
    if minimum_seconds < 0:
        raise ValueError("minimum lifetime is invalid")
    if not isinstance(sans, list) or not sans:
        raise ValueError("approved DNS SAN set is invalid")

    blocks = _certificate_blocks(fullchain)
    leaf = x509.load_pem_x509_certificate(blocks[0])
    try:
        key = serialization.load_pem_private_key(private_key, password=None)
    except (TypeError, ValueError) as error:
        raise ValueError("private key is malformed") from error

    leaf_public_key = leaf.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_public_key = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if leaf_public_key != key_public_key:
        raise ValueError("private key does not match certificate")

    try:
        extension = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound as error:
        raise ValueError("certificate DNS SAN set is missing") from error
    names = list(extension)
    if any(not isinstance(name, x509.DNSName) for name in names):
        raise ValueError("certificate contains an unapproved SAN type")
    observed = [_canonical_dns_name(name.value) for name in names]
    approved = [_canonical_dns_name(name) for name in sans]
    if len(observed) != len(set(observed)):
        raise ValueError("certificate contains a duplicate DNS SAN")
    if len(approved) != len(set(approved)):
        raise ValueError("approved DNS SAN set contains a duplicate")
    if set(observed) != set(approved):
        raise ValueError("certificate DNS SAN set does not match policy")

    now = datetime.now(timezone.utc)
    not_before = _utc_certificate_time(leaf, "not_valid_before")
    not_after = _utc_certificate_time(leaf, "not_valid_after")
    if now < not_before:
        raise ValueError("certificate is not yet valid")
    if now >= not_after and not allow_historical_expiry:
        raise ValueError("certificate is expired")
    if (
        not allow_historical_expiry
        and (not_after - now).total_seconds() < minimum_seconds
    ):
        raise ValueError("certificate lifetime is below the required minimum")

    verification_time = None
    if allow_historical_expiry:
        certificates = [x509.load_pem_x509_certificate(block) for block in blocks]
        shared_start = max(
            _utc_certificate_time(certificate, "not_valid_before")
            for certificate in certificates
        )
        shared_end = min(
            _utc_certificate_time(certificate, "not_valid_after")
            for certificate in certificates
        )
        selected = min(now, shared_end - timedelta(seconds=1))
        if selected < shared_start:
            raise ValueError("certificate chain has no shared validity interval")
        # Verify immutable published bytes at their latest shared valid instant.
        # Fresh issuer input never enters this historical-only path.
        verification_time = int(selected.timestamp())
    _verify_chain(blocks, ca_file, verification_time)
    return leaf.fingerprint(hashes.SHA256()).hex()


def validate_certificate(
    fullchain: bytes,
    private_key: bytes,
    sans: List[str],
    minimum_seconds: int,
    ca_file: Optional[str] = None,
) -> str:
    """Return the leaf fingerprint after current-certificate validation.

    ``ca_file`` exists only for an injected offline-test trust root. Production
    callers omit it so OpenSSL uses the host public trust store.
    """

    return _validate_certificate(
        fullchain,
        private_key,
        sans,
        minimum_seconds,
        ca_file,
        False,
    )


def validate_historical_certificate(
    fullchain: bytes,
    private_key: bytes,
    sans: List[str],
    ca_file: Optional[str] = None,
) -> str:
    """Validate an immutable published certificate while permitting expiry.

    This narrow path remains strict about future validity, key identity, exact
    SANs, server purpose, and public chain trust. Fresh issuer input must use
    :func:`validate_certificate` instead.
    """

    return _validate_certificate(
        fullchain,
        private_key,
        sans,
        0,
        ca_file,
        True,
    )
