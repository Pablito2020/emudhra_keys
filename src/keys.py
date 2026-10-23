"""Load supplied CA material or generate independent, untrusted classroom CAs.

An eMudhra public certificate cannot be used to recover its private key.
EMUDHRA_CAS supplies authorized PEM material in memory; demo keys are ephemeral.
"""

import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import cache

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

type PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey

CA_ENV = "EMUDHRA_CAS"
EMUDHRA_REPOSITORY = "https://repository.emsign.com/"
DEMO_CA_NAMES = ("demo-rsa", "demo-ec")


@dataclass(frozen=True, slots=True)
class CertificateAuthority:
    name: str
    certificate: x509.Certificate
    private_key: PrivateKey = field(repr=False)


@dataclass(frozen=True, slots=True)
class IssuedCertificate:
    domain: str
    certificate: x509.Certificate
    private_key: PrivateKey = field(repr=False)
    ca: CertificateAuthority


def normalize_domain(domain: str) -> str:
    """Return an ASCII DNS name; reject addresses, wildcards and malformed labels."""
    try:
        domain = domain.removesuffix(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("Invalid DNS name") from None
    if (
        not domain
        or len(domain) > 253
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in domain.split(".")
        )
    ):
        raise ValueError("Invalid DNS name")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError("Expected a DNS name, not an IP address")


def _key_usage(*, ca: bool, rsa_leaf: bool = False) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=rsa_leaf,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=ca,
        crl_sign=ca,
        encipher_only=False,
        decipher_only=False,
    )


@cache
def _demo_cas() -> tuple[CertificateAuthority, ...]:
    now = datetime.now(UTC)
    result = []
    for name, key in zip(
        DEMO_CA_NAMES,
        (
            rsa.generate_private_key(public_exponent=65537, key_size=3072),
            ec.generate_private_key(ec.SECP384R1()),
        ),
        strict=True,
    ):
        subject = x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COMMON_NAME, f"Classroom {name} CA (local demo)"
                )
            ]
        )
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_key_usage(ca=True), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        result.append(CertificateAuthority(name, certificate, key))
    return tuple(result)


def _validate_ca(ca: CertificateAuthority) -> None:
    certificate = ca.certificate
    actual = ca.private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    expected = certificate.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if actual != expected:
        raise ValueError("CA private key does not match its certificate")
    try:
        constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        )
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        raise ValueError(
            "CA certificate requires BasicConstraints and KeyUsage"
        ) from None
    if not constraints.critical or not constraints.value.ca or not usage.key_cert_sign:
        raise ValueError("Certificate is not permitted to sign certificates")
    for extension in certificate.extensions:
        if isinstance(extension.value, x509.NameConstraints):
            raise ValueError("Name-constrained CAs are not supported by this demo")
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
    if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
        raise ValueError("CA certificate is not currently valid")


def get_all_cas(*, demo: bool = False) -> list[CertificateAuthority]:
    """Return all configured issuers, or two local CAs when demo is explicit.

    EMUDHRA_CAS is a JSON object mapping slugs to certificate/private_key PEM
    strings and an optional password string. No issuer key is written to disk.
    """
    if demo:
        return list(_demo_cas())
    raw = os.environ.get(CA_ENV)
    if not raw:
        raise ValueError(
            f"No CA keys configured. Set {CA_ENV} or use --demo. "
            "Public eMudhra certificates do not contain private keys."
        )
    try:
        configured = json.loads(raw)
        if not isinstance(configured, dict) or not configured:
            raise ValueError
        result = []
        for name, material in configured.items():
            if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", name):
                raise ValueError
            password = material.get("password")
            key = serialization.load_pem_private_key(
                material["private_key"].encode(),
                password=password.encode() if password is not None else None,
            )
            if not isinstance(key, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey):
                raise ValueError
            certificate = x509.load_pem_x509_certificate(
                material["certificate"].encode()
            )
            ca = CertificateAuthority(name, certificate, key)
            _validate_ca(ca)
            result.append(ca)
    except ValueError, TypeError, KeyError, AttributeError, UnsupportedAlgorithm:
        # Never include environment contents or parser input in error messages.
        raise ValueError(
            f"Invalid {CA_ENV}: expected named RSA/EC CA PEM pairs with matching keys, "
            "current validity, CA constraints and certificate-signing usage"
        ) from None
    return result


def get_ca(name: str | None = None, *, demo: bool = False) -> CertificateAuthority:
    """Return a named CA, defaulting to the first configured issuer."""
    cas = get_all_cas(demo=demo)
    if name is None:
        return cas[0]
    for ca in cas:
        if ca.name == name:
            return ca
    raise ValueError("Unknown CA; choose one of: " + ", ".join(ca.name for ca in cas))


def _issue(domain: str, ca: CertificateAuthority, days: int) -> IssuedCertificate:
    domain = normalize_domain(domain)
    if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= 365:
        raise ValueError("Validity must be an integer from 1 to 365 days")
    _validate_ca(ca)
    key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if isinstance(ca.private_key, rsa.RSAPrivateKey)
        else ec.generate_private_key(ec.SECP256R1())
    )
    now = datetime.now(UTC)
    # A DNS name can exceed the 64-character Common Name limit; SAN is authoritative.
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
            _key_usage(ca=False, rsa_leaf=isinstance(key, rsa.RSAPrivateKey)),
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


def generate_certificate(
    domain: str, ca_name: str | None = None, *, demo: bool = False, days: int = 30
) -> IssuedCertificate:
    """Sign one DNS certificate with the selected, supplied CA or a local demo CA."""
    return _issue(domain, get_ca(ca_name, demo=demo), days)


def generate_all_certificates(
    domain: str, *, demo: bool = False, days: int = 30
) -> list[IssuedCertificate]:
    """Sign one fresh leaf per configured CA; this does not enumerate public roots."""
    return [_issue(domain, ca, days) for ca in get_all_cas(demo=demo)]
