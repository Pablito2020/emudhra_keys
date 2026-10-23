from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from src.keys import (
    CERTIFICATE_AUTHORITIES,
    CertificateAuthority,
    _load_ca,
    generate_all_certificates,
    generate_certificate,
    get_all_cas,
    get_ca,
    normalize_domain,
)

TLS_CA_NAMES = tuple(ca.name for ca in CERTIFICATE_AUTHORITIES if ca.supports_tls)


@pytest.mark.parametrize(
    ("name", "private_value"),
    [
        ("em-dv-tls-ca-g3b", 156),
        ("em-ov-tls-ca-g3b", 155),
        ("em-ev-tls-ca-g3b", 115),
        ("em-ov-cs-ca-g3b", 66),
        ("em-dv-tls-ca-g3c", 230),
        ("em-ov-tls-ca-g3c", 4),
        ("em-ev-tls-ca-g3c", 56),
        ("em-ov-cs-ca-g3c", 237),
    ],
)
def test_real_published_ca_keys(name, private_value):
    ca = get_ca(name)
    assert ca.private_key.private_numbers().private_value == private_value
    assert isinstance(ca.private_key.curve, ec.SECP384R1)
    assert ca.private_key.public_key() == ca.certificate.public_key()
    assert ca.certificate.issuer != ca.certificate.subject
    assert ca.certificate.subject.get_attributes_for_oid(
        x509.NameOID.ORGANIZATION_NAME
    )[0].value in {"eMudhra BV", "eMudhra Inc"}


def test_inventory_contains_all_eight_intermediates():
    assert get_all_cas() == CERTIFICATE_AUTHORITIES
    assert len(get_all_cas()) == 8
    assert len(TLS_CA_NAMES) == 6
    assert get_ca().name == "em-dv-tls-ca-g3b"
    with pytest.raises(ValueError, match="Unknown CA"):
        get_ca("unknown")


def test_certificate_fingerprint_and_private_key_are_checked():
    ca = get_ca()
    fingerprint = ca.certificate.fingerprint(hashes.SHA256()).hex()
    with pytest.raises(ValueError, match="fingerprint mismatch"):
        _load_ca(ca.name, 156, "0" * 64)
    with pytest.raises(ValueError, match="does not match"):
        _load_ca(ca.name, 4, fingerprint)


def verify(issued, *, domain=None, ca=None):
    return (
        PolicyBuilder()
        .store(Store([ca or issued.ca.certificate]))
        .build_server_verifier(x509.DNSName(domain or issued.domain))
        .verify(issued.certificate, [])
    )


@pytest.mark.parametrize("name", TLS_CA_NAMES)
@pytest.mark.parametrize(
    "domain", ["cv.udl.cat", "BÜCHER.example.", "a" * 63 + ".example.test"]
)
def test_real_signature_chain_and_hostname(name, domain):
    issued = generate_certificate(domain, name)
    assert len(verify(issued)) == 2
    issued.certificate.verify_directly_issued_by(issued.ca.certificate)
    assert issued.certificate.public_key() == issued.private_key.public_key()
    assert issued.ca.certificate.subject != x509.Name([])
    assert "private_key" not in repr(issued)
    assert "private_key" not in repr(issued.ca)


def test_hostname_and_root_are_actually_checked():
    issued = generate_certificate("cv.udl.cat")
    with pytest.raises(VerificationError):
        verify(issued, domain="attacker.test")
    with pytest.raises(VerificationError):
        verify(issued, ca=get_ca("em-ov-tls-ca-g3c").certificate)


def test_all_creates_independent_keys_and_serials():
    issued = generate_all_certificates("example.test")
    assert [item.ca.name for item in issued] == list(TLS_CA_NAMES)
    assert len({item.certificate.serial_number for item in issued}) == 6
    assert (
        len({item.private_key.private_numbers().private_value for item in issued}) == 6
    )
    again = generate_certificate("example.test")
    assert again.private_key.public_key() != issued[0].private_key.public_key()
    assert again.ca is issued[0].ca


@pytest.mark.parametrize("name", ["em-ov-cs-ca-g3b", "em-ov-cs-ca-g3c"])
def test_code_signing_cas_cannot_issue_tls_certificates(name):
    with pytest.raises(ValueError, match="not permitted for server authentication"):
        generate_certificate("example.test", name)


def test_mismatched_private_key_is_rejected(monkeypatch):
    ca = replace(get_ca(), private_key=get_ca("em-ov-tls-ca-g3c").private_key)
    monkeypatch.setattr("src.keys.CERTIFICATE_AUTHORITIES", [ca])
    with pytest.raises(ValueError, match="does not match"):
        generate_certificate("example.test")


def test_leaf_cannot_be_used_as_an_issuer(monkeypatch):
    leaf = generate_certificate("example.test")
    ca = CertificateAuthority("not-ca", leaf.certificate, leaf.private_key)
    monkeypatch.setattr("src.keys.CERTIFICATE_AUTHORITIES", [ca])
    with pytest.raises(ValueError, match="not permitted to sign"):
        generate_certificate("example.test")


def replacement_certificate(ca, start, end, *, key_cert_sign=True, extra=None):
    builder = (
        x509.CertificateBuilder()
        .subject_name(ca.certificate.subject)
        .issuer_name(ca.certificate.subject)
        .public_key(ca.private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                True, False, False, False, False, key_cert_sign, True, False, False
            ),
            critical=True,
        )
    )
    if extra is not None:
        builder = builder.add_extension(extra, critical=True)
    return builder.sign(ca.private_key, hashes.SHA256())


@pytest.mark.parametrize(
    "condition", ["expired", "future", "no-signing", "name-constraints", "client-only"]
)
def test_unusable_issuers_are_rejected(monkeypatch, condition):
    ca = get_ca("em-ov-tls-ca-g3c")
    now = datetime.now(UTC)
    start, end = now - timedelta(days=1), now + timedelta(days=1)
    if condition == "expired":
        start, end = now - timedelta(days=2), now - timedelta(days=1)
    if condition == "future":
        start, end = now + timedelta(days=1), now + timedelta(days=2)
    extra = None
    if condition == "name-constraints":
        extra = x509.NameConstraints([x509.DNSName("restricted.test")], None)
    if condition == "client-only":
        extra = x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH])
    cert = replacement_certificate(
        ca, start, end, key_cert_sign=condition != "no-signing", extra=extra
    )
    monkeypatch.setattr(
        "src.keys.CERTIFICATE_AUTHORITIES", [replace(ca, certificate=cert)]
    )
    with pytest.raises(ValueError):
        generate_certificate("example.test")


def test_leaf_validity_is_bounded_by_issuer(monkeypatch):
    ca = get_ca("em-ov-tls-ca-g3c")
    now = datetime.now(UTC)
    cert = replacement_certificate(
        ca, now - timedelta(days=1), now + timedelta(hours=1)
    )
    monkeypatch.setattr(
        "src.keys.CERTIFICATE_AUTHORITIES", [replace(ca, certificate=cert)]
    )
    issued = generate_certificate("example.test")
    assert issued.certificate.not_valid_after_utc == cert.not_valid_after_utc
    assert issued.certificate.not_valid_before_utc >= cert.not_valid_before_utc


@pytest.mark.parametrize("days", [0, -1, 366, 1.5, True])
def test_invalid_validity(days):
    with pytest.raises(ValueError, match="Validity"):
        generate_certificate("example.test", days=days)


@pytest.mark.parametrize(
    "domain",
    [
        "",
        ".",
        "a..test",
        "-bad.test",
        "bad-.test",
        "a" * 64 + ".test",
        "*.test",
        "127.0.0.1",
        "::1",
        "https://example.test",
        "../escape",
        "foo/bar",
        "bad\x00.test",
        "a." * 127 + "test",
        "example.test..",
    ],
)
def test_reject_malformed_dns_names(domain):
    with pytest.raises(ValueError):
        normalize_domain(domain)


def test_domain_normalization():
    assert normalize_domain("CV.UDL.CAT.") == "cv.udl.cat"
    assert normalize_domain("bücher.example") == "xn--bcher-kva.example"
