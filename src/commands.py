"""Command operations and PEM output."""

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from .keys import generate_all_certificates, generate_certificate


def generate(
    domain: str,
    *,
    ca: str | None = None,
    all_cas: bool = False,
    demo: bool = False,
    output: Path = Path("certificates"),
) -> list[Path]:
    if ca is not None and all_cas:
        raise ValueError("Choose --ca or --all")
    issued = (
        generate_all_certificates(domain, demo=demo)
        if all_cas
        else [generate_certificate(domain, ca, demo=demo)]
    )
    targets = [output / item.domain / item.ca.name for item in issued]
    if any(target.exists() or target.is_symlink() for target in targets):
        raise FileExistsError(
            "Certificate output already exists; choose another --output"
        )
    for item, target in zip(issued, targets, strict=True):
        target.mkdir(parents=True, mode=0o700)
        # Export the generated leaf key only, never the supplied CA private key.
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


def end_to_end(domain: str) -> None:
    raise NotImplementedError("end_to_end awaits DNS and nginx implementation")
