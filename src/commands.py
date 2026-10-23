import signal
from pathlib import Path

from src.certificates_directory import CertificatesDirectory
from src.demo.dns import DnsResolver
from src.demo.server import Server
from src.emudhra.certificates import EmudhraCertificates
from src.emudhra.issuer import EMudhraIssuer


def generate(
    domain: str,
    ca: str | None,
    all_cas: bool,
    output: Path,
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


def end_to_end(domain: str, *, ca: str, output: Path) -> None:
    certificates = EmudhraCertificates()
    output_directory = CertificatesDirectory(path=output, certificates=certificates)
    output_directory.clean()  # clean old runs if needed
    issuer = EMudhraIssuer(cas=certificates)
    issued = issuer.generate_all_certificates(domain)
    output_directory.save(issued)
    ssl_configuration = output_directory.get_ssl_config_for(domain, ca)
    assert ssl_configuration is not None, "SSL Configuration should not be None"

    def terminate(signum, frame):
        # Further signals must not interrupt nginx and DNS cleanup.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise KeyboardInterrupt

    previous = {
        signum: signal.signal(signum, terminate)
        for signum in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        with DnsResolver() as resolver:
            resolver.add_record(domain, "127.0.0.1")
            with Server(domain, ssl_configuration=ssl_configuration) as server:
                print(f"https://{domain}/ (CA: {ca}); press Ctrl+C to stop", flush=True)
                server.wait()
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
