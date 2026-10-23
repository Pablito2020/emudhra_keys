import stat

import pytest
from click.testing import CliRunner
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.verification import PolicyBuilder, Store

from main import main
from src import commands
from src.keys import CERTIFICATE_AUTHORITIES, get_ca


def test_generate_cli_writes_verifiable_certificates(tmp_path):
    result = CliRunner().invoke(
        main, ["generate", "CV.UDL.CAT.", "--all", "--output", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    for name in (ca.name for ca in CERTIFICATE_AUTHORITIES if ca.supports_tls):
        target = tmp_path / "cv.udl.cat" / name
        assert stat.S_IMODE(target.stat().st_mode) == 0o700
        assert stat.S_IMODE((target / "private-key.pem").stat().st_mode) == 0o600
        cert = x509.load_pem_x509_certificate((target / "certificate.pem").read_bytes())
        ca = x509.load_pem_x509_certificate((target / "ca.pem").read_bytes())
        key = serialization.load_pem_private_key(
            (target / "private-key.pem").read_bytes(), None
        )
        assert key.public_key() == cert.public_key()
        verifier = (
            PolicyBuilder()
            .store(Store([ca]))
            .build_server_verifier(x509.DNSName("cv.udl.cat"))
        )
        assert len(verifier.verify(cert, [])) == 2
        assert {p.name for p in target.iterdir()} == {
            "certificate.pem",
            "ca.pem",
            "private-key.pem",
        }


def test_existing_keys_are_not_overwritten(tmp_path):
    [target] = commands.generate("example.test", output=tmp_path)
    original = (target / "private-key.pem").read_bytes()
    with pytest.raises(FileExistsError):
        commands.generate("example.test", output=tmp_path)
    assert (target / "private-key.pem").read_bytes() == original


def test_generate_does_not_export_ca_key(tmp_path):
    ca = get_ca()
    private = ca.private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    [target] = commands.generate("example.test", output=tmp_path)
    assert all(private not in path.read_bytes() for path in target.iterdir())


def test_end_to_end_is_explicitly_unimplemented():
    result = CliRunner().invoke(main, ["end_to_end", "example.test"])
    assert result.exit_code == 2
    assert "awaits DNS and nginx" in result.output


def test_ca_and_all_are_mutually_exclusive(tmp_path):
    result = CliRunner().invoke(
        main, ["generate", "example.test", "--ca", "em-dv-tls-ca-g3b", "--all"]
    )
    assert result.exit_code == 2
    assert not list(tmp_path.iterdir())
