"""Ephemeral certificate fixtures for the TLS runtime tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass(frozen=True)
class CertificateMaterial:
    fullchain: bytes
    private_key: bytes
    fingerprint: str


class EphemeralCA:
    """Create a disposable CA and leaf certificates without external access."""

    def __init__(self, common_name: str = "TLS test root") -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        self.certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=30))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .sign(self.key, hashes.SHA256())
        )

    def write_certificate(self, path: Path) -> None:
        path.write_bytes(self.certificate.public_bytes(serialization.Encoding.PEM))

    def issue(
        self,
        sans: list[x509.GeneralName] | None = None,
        *,
        not_before: datetime | None = None,
        not_after: datetime | None = None,
        private_key=None,
    ) -> CertificateMaterial:
        key = private_key or rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, "unused.example.test")]
                )
            )
            .issuer_name(self.certificate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before or now - timedelta(minutes=5))
            .not_valid_after(not_after or now + timedelta(days=7))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
        )
        if sans is not None:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(sans), critical=False
            )
        certificate = builder.sign(self.key, hashes.SHA256())
        return CertificateMaterial(
            fullchain=certificate.public_bytes(serialization.Encoding.PEM),
            private_key=key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            fingerprint=certificate.fingerprint(hashes.SHA256()).hex(),
        )

    def issue_with_expired_intermediate(
        self, sans: list[x509.GeneralName]
    ) -> CertificateMaterial:
        """Build a chain whose leaf outlives its already-expired intermediate."""
        now = datetime.now(timezone.utc)
        intermediate_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        intermediate_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Expired test intermediate")]
        )
        intermediate = (
            x509.CertificateBuilder()
            .subject_name(intermediate_name)
            .issuer_name(self.certificate.subject)
            .public_key(intermediate_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=10))
            .not_valid_after(now - timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .sign(self.key, hashes.SHA256())
        )
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unused.example.test")])
            )
            .issuer_name(intermediate.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=5))
            .not_valid_after(now + timedelta(days=5))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_key.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .sign(intermediate_key, hashes.SHA256())
        )
        encoding = serialization.Encoding.PEM
        return CertificateMaterial(
            fullchain=leaf.public_bytes(encoding) + intermediate.public_bytes(encoding),
            private_key=leaf_key.private_bytes(
                encoding,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            fingerprint=leaf.fingerprint(hashes.SHA256()).hex(),
        )


def dns(name: str) -> x509.DNSName:
    return x509.DNSName(name)


def ip(value: str) -> x509.IPAddress:
    return x509.IPAddress(ip_address(value))
