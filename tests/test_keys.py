import json
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from src.keys import (
    CA_ENV,
    DEMO_CA_NAMES,
    generate_all_certificates,
    generate_certificate,
    get_all_cas,
    get_ca,
    normalize_domain,
)


@pytest.fixture(autouse=True)
def isolate_ca_config(monkeypatch):
    monkeypatch.delenv(CA_ENV, raising=False)


def material(ca, password=None):
    encryption = (
        serialization.BestAvailableEncryption(password.encode())
        if password is not None
        else serialization.NoEncryption()
    )
    result = {
        "certificate": ca.certificate.public_bytes(serialization.Encoding.PEM).decode(),
        "private_key": ca.private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
        ).decode(),
    }
    if password is not None:
        result["password"] = password
    return result


def verify(issued, *, domain=None, ca=None):
    return (
        PolicyBuilder()
        .store(Store([ca or issued.ca.certificate]))
        .build_server_verifier(x509.DNSName(domain or issued.domain))
        .verify(issued.certificate, [])
    )


@pytest.mark.parametrize("name", DEMO_CA_NAMES)
@pytest.mark.parametrize(
    "domain", ["cv.udl.cat", "BÜCHER.example.", "a" * 63 + ".example.test"]
)
def test_real_signature_chain_and_hostname(name, domain):
    issued = generate_certificate(domain, name, demo=True)
    assert len(verify(issued)) == 2
    issued.certificate.verify_directly_issued_by(issued.ca.certificate)
    assert issued.certificate.public_key() == issued.private_key.public_key()
    assert issued.ca.certificate.subject != x509.Name([])
    assert "local demo" in issued.ca.certificate.subject.rfc4514_string()
    assert "private_key" not in repr(issued)
    assert "private_key" not in repr(issued.ca)


def test_hostname_and_root_are_actually_checked():
    issued = generate_certificate("cv.udl.cat", demo=True)
    with pytest.raises(VerificationError):
        verify(issued, domain="attacker.test")
    with pytest.raises(VerificationError):
        verify(issued, ca=get_ca("demo-ec", demo=True).certificate)


def test_all_creates_independent_keys_and_serials():
    issued = generate_all_certificates("example.test", demo=True)
    assert [item.ca.name for item in issued] == list(DEMO_CA_NAMES)
    assert isinstance(issued[0].private_key, rsa.RSAPrivateKey)
    assert isinstance(issued[1].private_key, ec.EllipticCurvePrivateKey)
    assert issued[0].certificate.serial_number != issued[1].certificate.serial_number
    again = generate_certificate("example.test", demo=True)
    assert again.private_key.public_key() != issued[0].private_key.public_key()
    assert again.ca is issued[0].ca


def test_missing_configuration_never_silently_falls_back_to_demo():
    for action in (get_ca, get_all_cas):
        with pytest.raises(ValueError, match="Public eMudhra certificates"):
            action()
    with pytest.raises(ValueError, match="Unknown CA"):
        get_ca("emudhra-root", demo=True)


def test_supplied_pem_pairs_and_encrypted_private_key(monkeypatch):
    demo = get_all_cas(demo=True)
    configured = {
        "classroom-rsa": material(demo[0]),
        "classroom-ec": material(demo[1], "test-only"),
    }
    monkeypatch.setenv(CA_ENV, json.dumps(configured))
    assert [ca.name for ca in get_all_cas()] == list(configured)
    assert get_ca().name == "classroom-rsa"
    issued = generate_certificate("cv.udl.cat", "classroom-ec")
    assert len(verify(issued)) == 2
    assert len(generate_all_certificates("example.test")) == 2


@pytest.mark.parametrize(
    "raw", ["broken-secret-marker", "[]", "{}", '{"../escape": {}}', '{"ca": null}']
)
def test_invalid_config_is_sanitized(monkeypatch, raw):
    monkeypatch.setenv(CA_ENV, raw)
    with pytest.raises(ValueError, match="Invalid EMUDHRA_CAS") as error:
        get_all_cas()
    assert raw not in str(error.value)


def test_mismatched_private_key_is_rejected(monkeypatch):
    rsa_ca, ec_ca = get_all_cas(demo=True)
    pair = material(rsa_ca)
    pair["private_key"] = material(ec_ca)["private_key"]
    monkeypatch.setenv(CA_ENV, json.dumps({"mismatch": pair}))
    with pytest.raises(ValueError, match="Invalid EMUDHRA_CAS"):
        get_ca()


def test_leaf_cannot_be_used_as_an_issuer(monkeypatch):
    leaf = generate_certificate("example.test", demo=True)
    monkeypatch.setenv(CA_ENV, json.dumps({"not-ca": material(leaf)}))
    with pytest.raises(ValueError, match="Invalid EMUDHRA_CAS"):
        get_ca()


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
    ca = get_ca("demo-ec", demo=True)
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
    pair = material(ca)
    pair["certificate"] = cert.public_bytes(serialization.Encoding.PEM).decode()
    monkeypatch.setenv(CA_ENV, json.dumps({"unusable": pair}))
    with pytest.raises(ValueError, match="Invalid EMUDHRA_CAS"):
        get_ca()


def test_leaf_validity_is_bounded_by_issuer(monkeypatch):
    ca = get_ca("demo-ec", demo=True)
    now = datetime.now(UTC)
    cert = replacement_certificate(
        ca, now - timedelta(days=1), now + timedelta(hours=1)
    )
    pair = material(ca)
    pair["certificate"] = cert.public_bytes(serialization.Encoding.PEM).decode()
    monkeypatch.setenv(CA_ENV, json.dumps({"short-lived": pair}))
    issued = generate_certificate("example.test")
    assert issued.certificate.not_valid_after_utc == cert.not_valid_after_utc
    assert issued.certificate.not_valid_before_utc >= cert.not_valid_before_utc


@pytest.mark.parametrize("days", [0, -1, 366, 1.5, True])
def test_invalid_validity(days):
    with pytest.raises(ValueError, match="Validity"):
        generate_certificate("example.test", demo=True, days=days)


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
