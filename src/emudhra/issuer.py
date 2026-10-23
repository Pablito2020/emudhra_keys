from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from src.emudhra.certificates import CertificateAuthority, EmudhraCertificates


@dataclass(frozen=True, slots=True)
class IssuedCertificate:
    domain: str
    certificate: x509.Certificate
    private_key: ec.EllipticCurvePrivateKey
    ca: CertificateAuthority


@dataclass(frozen=True)
class EMudhraIssuer:
    cas: EmudhraCertificates

    def generate_certificate(
            self, domain: str, ca_name: str, *, days: int = 30
    ) -> IssuedCertificate:
        ca = self.cas.get_from_name(name=ca_name)
        assert ca, f"CA {ca_name} does not exist"
        assert ca.supports_tls, "Your ca must support TLS"
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(UTC)
        subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, domain)] if len(domain) <= 64 else []
        )
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca.certificate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(
                max(now - timedelta(minutes=1), ca.certificate.not_valid_before_utc)
            )
            .not_valid_after(
                min(now + timedelta(days=days), ca.certificate.not_valid_after_utc)
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=not subject
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    ca.private_key.public_key()
                ),
                critical=False,
            )
            .sign(ca.private_key, hashes.SHA256())
        )
        return IssuedCertificate(domain, certificate, key, ca)

    def generate_all_certificates(
            self, domain: str, *, days: int = 30
    ) -> list[IssuedCertificate]:
        return [
            self.generate_certificate(domain=domain, ca_name=ca.name, days=days)
            for ca in self.cas if ca.supports_tls
        ]
