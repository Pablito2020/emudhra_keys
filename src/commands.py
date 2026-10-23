"""Application workflows, independent of CLI parsing and presentation."""

import os
import signal
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from src.dns import DnsResolver, normalize_domain
from src.emudhra.certificates import EmudhraCertificates
from src.emudhra.issuer import EMudhraIssuer, IssuedCertificate
from src.server import Server

DEFAULT_CA = "em-dv-tls-ca-g3b"


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
    domain = normalize_domain(domain)
    issuer = EMudhraIssuer(cas=EmudhraCertificates())
    if all_cas:
        issued = issuer.generate_all_certificates(domain)
    else:
        ca = ca or DEFAULT_CA
        selected = issuer.cas.get_from_name(ca)
        if selected is None or not selected.supports_tls:
            raise ValueError(f"Unknown or non-TLS CA: {ca}")
        issued = [issuer.generate_certificate(domain, ca)]
    return save_to_files(issued, output)


def _certificate_directory(domain: str, ca_name: str) -> Path:
    ca = EmudhraCertificates().get_from_name(ca_name)
    if ca is None or not ca.supports_tls:
        raise ValueError(f"Unknown or non-TLS CA: {ca_name}")
    target = Path("certificates") / domain / ca.name
    if target.is_symlink():
        raise ValueError(f"Certificate directory must not be a symlink: {target}")
    if not target.exists():
        [target] = generate(domain, ca=ca.name)
    try:
        certificate = x509.load_pem_x509_certificate(
            (target / "certificate.pem").read_bytes()
        )
        saved_ca = x509.load_pem_x509_certificate((target / "ca.pem").read_bytes())
        key = serialization.load_pem_private_key(
            (target / "private-key.pem").read_bytes(), password=None
        )
        if saved_ca != ca.certificate:
            raise ValueError("Saved CA does not match the selected CA")
        if key.public_key() != certificate.public_key():
            raise ValueError("Private key does not match the certificate")
        verifier = (
            PolicyBuilder()
            .store(Store([ca.certificate]))
            .build_server_verifier(x509.DNSName(domain))
        )
        verifier.verify(certificate, [])
    except (ValueError, OSError, VerificationError, TypeError) as error:
        raise ValueError(f"Invalid certificate files in {target}: {error}") from error
    return target


def end_to_end(domain: str, *, ca: str = DEFAULT_CA) -> None:
    """Serve a selected certificate until interrupted, then undo local DNS changes."""
    domain = normalize_domain(domain)

    def terminate(signum, frame):
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, terminate)
    try:
        target = _certificate_directory(domain, ca)
        with DnsResolver() as resolver:
            resolver.add_record(domain, "127.0.0.1")
            with Server(domain, target) as server:
                print(f"https://{domain}/ (CA: {ca}); press Ctrl+C to stop", flush=True)
                server.wait()
    finally:
        signal.signal(signal.SIGTERM, previous)
