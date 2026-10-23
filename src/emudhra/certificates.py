from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat._oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def load_tls_parent_certificate() -> x509.Certificate:
    """Load the pinned cross-signed TLS parent, without network access."""
    # https://repository.emsign.com/certs/crosssign/roottlscag3.crt
    certificate = x509.load_pem_x509_certificate(
        (
            Path(__file__).parent
            / "certificates"
            / "emsign-root-tls-ca-g3-cross-signed.pem"
        ).read_bytes()
    )
    if certificate.fingerprint(hashes.SHA256()).hex() != (
        "3094025792039a68af6e553686410bdab7c0d4a36b9084cba64202e35d6ebbdd"
    ):
        raise ValueError("TLS parent certificate fingerprint mismatch")
    return certificate


@dataclass(frozen=True, slots=True)
class _CertificateAuthorityBuilder:
    name: str
    private_value: int
    fingerprint: str

    def build(self) -> CertificateAuthority:
        certificate = x509.load_pem_x509_certificate(
            (Path(__file__).parent / "certificates" / f"{self.name}.pem").read_bytes()
        )
        if certificate.fingerprint(hashes.SHA256()).hex() != self.fingerprint:
            raise ValueError(f"Certificate fingerprint mismatch: {self.name}")
        private_key = ec.derive_private_key(self.private_value, ec.SECP384R1())
        if private_key.public_key() != certificate.public_key():
            raise ValueError(
                f"CA private key does not match its certificate: {self.name}"
            )
        return CertificateAuthority(self.name, certificate, private_key)


# Certificate fingerprints: https://bugzilla.mozilla.org/show_bug.cgi?id=2083449
# Private scalars: https://fenko.nz/blog/emudhra-ca-compromise/
CERTIFICATE_AUTHORITIES: list[_CertificateAuthorityBuilder] = [
    _CertificateAuthorityBuilder(
        "em-dv-tls-ca-g3b",
        156,
        "42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493",
    ),
    _CertificateAuthorityBuilder(
        "em-ov-tls-ca-g3b",
        155,
        "98b896625c0c230adeec3eb2cf6aad5001ecf9156a68644e82374ce5833bc25b",
    ),
    _CertificateAuthorityBuilder(
        "em-ev-tls-ca-g3b",
        115,
        "e7568fe6e12331f4fd7de61da4c7559d0f8eb192a218d4741a3ba75184333838",
    ),
    _CertificateAuthorityBuilder(
        "em-ov-cs-ca-g3b",
        66,
        "9e39de2881273acc225a149c72ba3e0f51424963669ab633ee1dc7df5db067b4",
    ),
    _CertificateAuthorityBuilder(
        "em-dv-tls-ca-g3c",
        230,
        "0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19",
    ),
    _CertificateAuthorityBuilder(
        "em-ov-tls-ca-g3c",
        4,
        "cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f",
    ),
    _CertificateAuthorityBuilder(
        "em-ev-tls-ca-g3c",
        56,
        "432ec25f0d28de9006d97bf752f17bbb2cd41f669933fcb072d9a1148d0261f3",
    ),
    _CertificateAuthorityBuilder(
        "em-ov-cs-ca-g3c",
        237,
        "4b2460a466f95fd40113bcdcca2ceb29b3b093921de45474da7df48874c630b1",
    ),
]


@dataclass(frozen=True, slots=True)
class CertificateAuthority:
    name: str
    certificate: x509.Certificate
    private_key: ec.EllipticCurvePrivateKey

    def __post_init__(self):
        if self.supports_tls:
            self.__verify()

    @property
    def supports_tls(self) -> bool:
        usage = self.certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        return ExtendedKeyUsageOID.SERVER_AUTH in usage

    def __verify(self):
        if self.private_key.public_key() != self.certificate.public_key():
            raise ValueError("CA private key does not match...")
        try:
            constraints = self.certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            )
            usage = self.certificate.extensions.get_extension_for_class(
                x509.KeyUsage
            ).value
        except x509.ExtensionNotFound:
            raise ValueError(
                "CA certificate requires BasicConstraints and KeyUsage"
            ) from None
        if (
            not constraints.critical
            or not constraints.value.ca
            or not usage.key_cert_sign
        ):
            raise ValueError("Certificate is not permitted to sign certificates")
        for extension in self.certificate.extensions:
            if isinstance(extension.value, x509.NameConstraints):
                raise ValueError("Name-constrained CAs are not supported")
            if isinstance(extension.value, x509.ExtendedKeyUsage) and not any(
                oid in extension.value
                for oid in (
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
                )
            ):
                raise ValueError(
                    "CA certificate is not permitted for server authentication"
                )
        now = datetime.now(UTC)
        if (
            not self.certificate.not_valid_before_utc
            <= now
            < self.certificate.not_valid_after_utc
        ):
            raise ValueError("CA certificate is not currently valid")


@dataclass(frozen=True)
class EmudhraCertificates:
    cas: list[CertificateAuthority] = field(
        default_factory=lambda: [c.build() for c in CERTIFICATE_AUTHORITIES]
    )

    def __iter__(self) -> Iterator[CertificateAuthority]:
        return iter(self.cas)

    def get_from_name(self, name: str) -> CertificateAuthority | None:
        for ca in self.cas:
            if ca.name == name:
                return ca
        return None
