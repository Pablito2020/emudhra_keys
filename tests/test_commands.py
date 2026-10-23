import json
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.verification import PolicyBuilder, Store

from src import commands
from src.keys import CA_ENV, get_ca
from src.main import main


def test_generate_cli_writes_verifiable_certificates(tmp_path, capsys):
    assert (
        main(["generate", "CV.UDL.CAT.", "--demo", "--all", "--output", str(tmp_path)])
        == 0
    )
    assert "not issued by eMudhra" in capsys.readouterr().out
    for name in ("demo-rsa", "demo-ec"):
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
    [target] = commands.generate("example.test", demo=True, output=tmp_path)
    original = (target / "private-key.pem").read_bytes()
    with pytest.raises(FileExistsError):
        commands.generate("example.test", demo=True, output=tmp_path)
    assert (target / "private-key.pem").read_bytes() == original


def test_generate_does_not_export_supplied_ca_key(tmp_path, monkeypatch):
    ca = get_ca("demo-ec", demo=True)
    private = ca.private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    monkeypatch.setenv(
        CA_ENV,
        json.dumps(
            {
                "supplied": {
                    "certificate": ca.certificate.public_bytes(
                        serialization.Encoding.PEM
                    ).decode(),
                    "private_key": private.decode(),
                }
            }
        ),
    )
    [target] = commands.generate("example.test", output=tmp_path)
    assert all(private not in path.read_bytes() for path in target.iterdir())


def test_unconfigured_cli_has_actionable_error(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv(CA_ENV, raising=False)
    with pytest.raises(SystemExit) as error:
        main(["generate", "example.test", "--output", str(tmp_path)])
    assert error.value.code == 2
    assert "No CA keys configured" in capsys.readouterr().err
    assert not list(tmp_path.iterdir())


def test_end_to_end_is_explicitly_unimplemented(capsys):
    with pytest.raises(SystemExit) as error:
        main(["end_to_end", "example.test"])
    assert error.value.code == 2
    assert "awaits DNS and nginx" in capsys.readouterr().err


def test_ca_and_all_are_mutually_exclusive(tmp_path):
    with pytest.raises(SystemExit) as error:
        main(["generate", "example.test", "--ca", "demo-ec", "--all", "--demo"])
    assert error.value.code == 2
    assert not list(tmp_path.iterdir())
