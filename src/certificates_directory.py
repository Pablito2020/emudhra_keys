import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.bindings._rust import Encoding
from cryptography.hazmat.primitives import serialization

from src.emudhra.certificates import EmudhraCertificates, load_tls_parent_certificate
from src.emudhra.issuer import IssuedCertificate


@dataclass(frozen=True)
class SSLConfiguration:
    chain: bytes
    key: Path


@dataclass(frozen=True)
class CertificatesDirectory:
    path: Path
    certificates: EmudhraCertificates

    def save(self, issued: list[IssuedCertificate]):
        targets = [self.path / item.domain / item.ca.name for item in issued]
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

    def get_files_path_for(self, domain: str, ca_name: str) -> Path | None:
        ca = self.certificates.get_from_name(ca_name)
        if ca is None or not ca.supports_tls:
            raise ValueError(f"Unknown or non-TLS CA: {ca_name}")
        target = self.path / domain / ca.name
        if target.is_symlink():
            raise ValueError(f"Certificate directory must not be a symlink: {target}")
        if not target.exists():
            return None
        return target

    def clean(self) -> None:
        """Remove the output directory; do nothing if it is already absent."""
        cwd = Path.cwd()
        if self.path.resolve() in (cwd, *cwd.parents):
            raise ValueError("Cannot clean the working directory or its parents")
        try:
            shutil.rmtree(self.path)
        except FileNotFoundError:
            pass

    def get_ssl_config_for(self, domain: str, ca_name: str) -> SSLConfiguration | None:
        if files_directory := self.get_files_path_for(domain, ca_name):
            certificate = x509.load_pem_x509_certificate(
                (files_directory / "certificate.pem").read_bytes()
            )
            issuer = x509.load_pem_x509_certificate(
                (files_directory / "ca.pem").read_bytes()
            )
            parent = load_tls_parent_certificate()
            try:
                issuer.verify_directly_issued_by(parent)
            except (ValueError, InvalidSignature) as error:
                raise ValueError(
                    "Issuing CA was not signed by the bundled TLS parent"
                ) from error
            chain = b"".join(
                item.public_bytes(Encoding.PEM) for item in (certificate, issuer, parent)
            )
            key = (files_directory / "private-key.pem").resolve()
            if not key.is_file():
                raise FileNotFoundError(key)
            return SSLConfiguration(
                chain=chain,
                key=key
            )
        return None
