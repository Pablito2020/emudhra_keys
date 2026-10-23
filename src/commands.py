import signal
from pathlib import Path

from src.certificates_directory import CertificatesDirectory
from src.demo.dns import DnsResolver
from src.demo.server import Server
from src.emudhra.certificates import EmudhraCertificates
from src.emudhra.issuer import EMudhraIssuer

DEFAULT_CA = "em-dv-tls-ca-g3b"
DEFAULT_OUTPUT_PATH = Path("certificates")


def generate(
        domain: str,
        ca: str | None = None,
        all_cas: bool = False,
        output: Path = DEFAULT_OUTPUT_PATH,
):
    if ca is not None and all_cas:
        raise ValueError("Choose --ca or --all")
    certificates = EmudhraCertificates()
    output_directory = CertificatesDirectory(path=output, certificates=certificates)
    issuer = EMudhraIssuer(cas=certificates)
    if all_cas:
        issued = issuer.generate_all_certificates(domain)
    else:
        assert ca is not None, "Choose the --ca if you don't have --all"
        issued = [issuer.generate_certificate(domain, ca)]
    output_directory.save(issued)


def end_to_end(domain: str, *, ca: str = DEFAULT_CA) -> None:
    """Serve a selected certificate until interrupted, then undo local DNS changes."""
    certificates = EmudhraCertificates()
    output_directory = CertificatesDirectory(path=DEFAULT_OUTPUT_PATH, certificates=certificates)
    issuer = EMudhraIssuer(cas=certificates)
    issued = issuer.generate_all_certificates(domain)
    output_directory.save(issued)
    ssl_configuration = output_directory.get_ssl_config_for(domain, ca)
    assert ssl_configuration is not None, "SSL Configuration should not be None"

    def terminate(signum, frame):
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, terminate)
    try:
        with DnsResolver() as resolver:
            resolver.add_record(domain, "127.0.0.1")
            with Server(domain, ssl_configuration=ssl_configuration) as server:
                print(f"https://{domain}/ (CA: {ca}); press Ctrl+C to stop", flush=True)
                server.wait()
    finally:
        signal.signal(signal.SIGTERM, previous)
