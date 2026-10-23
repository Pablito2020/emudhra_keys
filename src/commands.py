"""Application workflows, independent of CLI parsing and presentation."""

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from src.emudhra.certificates import EmudhraCertificates
from src.emudhra.issuer import EMudhraIssuer, IssuedCertificate


def save_to_files(issued: list[IssuedCertificate], output: Path):
    targets = [output / item.domain / item.ca.name for item in issued]
    if any(target.exists() or target.is_symlink() for target in targets):
        raise FileExistsError(
            "Certificate output already exists; choose another --output"
        )
    for item, target in zip(issued, targets, strict=True):
        target.mkdir(parents=True, mode=0o700)
        # Export the generated leaf key only, never the CA private key.
        key_path = target / "private-key.pem"
        with os.fdopen(
                os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
        ) as f:
            f.write(
                item.private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
        (target / "certificate.pem").write_bytes(
            item.certificate.public_bytes(serialization.Encoding.PEM)
        )
        (target / "ca.pem").write_bytes(
            item.ca.certificate.public_bytes(serialization.Encoding.PEM)
        )
    return targets

def generate(
        domain: str,
        *,
        ca: str | None = None,
        all_cas: bool = False,
        output: Path = Path("certificates"),
) -> list[Path]:
    """Issue certificates and save their PEM files; return the output directories."""
    if ca is not None and all_cas:
        raise ValueError("Choose --ca or --all")
    issuer = EMudhraIssuer(cas=EmudhraCertificates())
    if all_cas:
        issued = issuer.generate_all_certificates(domain)
    else:
        assert ca is not None, "CA you want should not be None"
        issued = [issuer.generate_certificate(domain, ca)]
    return save_to_files(issued, output)


def end_to_end(domain: str) -> None:
    raise NotImplementedError("end_to_end awaits DNS and nginx implementation")
