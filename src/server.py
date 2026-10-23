"""An isolated, foreground nginx HTTPS server."""

import grp
import os
import pwd
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding

from src.dns import normalize_domain
from src.emudhra.certificates import load_tls_parent_certificate
from src.system import executable, privileged, run

NGINX = Path(__file__).parent / "nginx"


def _quote(value: str | Path) -> str:
    value = str(value)
    if any(character in value for character in "\r\n$"):
        raise ValueError("Unsupported character in nginx configuration path")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class Server:
    def __init__(self, domain: str, certificate_dir: Path, *, port: int = 443):
        self.domain = normalize_domain(domain)
        self.certificate_dir = certificate_dir.resolve()
        if not 1 <= port <= 65535:
            raise ValueError("Invalid HTTPS port")
        self.port = port
        self._runtime: Path | None = None
        self._process: subprocess.Popen | None = None

    def _command(self, *args: str, detached: bool = False) -> list[str]:
        command = [
            self._nginx,
            "-p",
            str(self._runtime),
            "-c",
            str(self._config),
            "-e",
            "stderr",
            *args,
        ]
        if detached:
            # Authenticate on the terminal, then isolate nginx's process group.
            command = [executable("setsid"), "--wait", *command]
        return privileged(command) if self.port < 1024 else command

    def __enter__(self):
        self._nginx = executable("nginx")
        certificate = x509.load_pem_x509_certificate(
            (self.certificate_dir / "certificate.pem").read_bytes()
        )
        expected = certificate.public_bytes(Encoding.DER)
        key = self.certificate_dir / "private-key.pem"
        if not key.is_file():
            raise FileNotFoundError(key)
        issuer = x509.load_pem_x509_certificate(
            (self.certificate_dir / "ca.pem").read_bytes()
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
        NGINX.mkdir(exist_ok=True)
        self._runtime = Path(tempfile.mkdtemp(prefix="run-", dir=NGINX)).resolve()
        try:
            self._config = self._runtime / "nginx.conf"
            chain_path = self._runtime / "fullchain.pem"
            chain_path.write_bytes(chain)
            user = pwd.getpwuid(os.getuid()).pw_name
            group = grp.getgrgid(os.getgid()).gr_name
            self._config.write_text(f"""\
user {_quote(user)} {_quote(group)};
worker_processes 1;
pid {_quote(self._runtime / "nginx.pid")};
error_log stderr;
worker_shutdown_timeout 3s;
events {{ worker_connections 32; }}
http {{
    access_log off;
    client_body_temp_path {_quote(self._runtime / "client_body")};
    proxy_temp_path {_quote(self._runtime / "proxy")};
    fastcgi_temp_path {_quote(self._runtime / "fastcgi")};
    uwsgi_temp_path {_quote(self._runtime / "uwsgi")};
    scgi_temp_path {_quote(self._runtime / "scgi")};
    server {{
        listen 127.0.0.1:{self.port} ssl;
        server_name {self.domain};
        ssl_certificate {_quote(chain_path)};
        ssl_certificate_key {_quote(key)};
        ssl_protocols TLSv1.2 TLSv1.3;
        default_type text/plain;
        return 200 "If you see this, it's pretty bad.\\n";
    }}
}}
""")
            run(self._command("-t"))
            self._process = subprocess.Popen(
                self._command("-g", "daemon off;", detached=True),
                stdin=subprocess.DEVNULL,
            )
            self._wait_ready(expected)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def _wait_ready(self, expected: bytes) -> None:
        # An occupied port is ready only if it presents our exact certificate.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self._process.poll() is not None:
                raise OSError("nginx exited during startup; check its stderr output")
            try:
                with socket.create_connection(
                    ("127.0.0.1", self.port), timeout=0.5
                ) as sock:
                    with context.wrap_socket(sock, server_hostname=self.domain) as tls:
                        if (
                            tls.getpeercert(binary_form=True) == expected
                            and (self._runtime / "nginx.pid").exists()
                        ):
                            return
            except OSError:
                pass
            time.sleep(0.1)
        raise OSError(
            f"nginx did not present the expected certificate on port {self.port}"
        )

    def wait(self) -> None:
        if self._process is None:
            raise RuntimeError("Server has not been started")
        status = self._process.wait()
        if status:
            raise OSError(f"nginx exited with status {status}")

    def __exit__(self, *exc):
        process = self._process
        if process is not None and process.poll() is None:
            try:
                if (self._runtime / "nginx.pid").exists():
                    run(self._command("-s", "quit"))
                else:
                    self._kill_group("TERM")
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._kill_group("KILL")
                    process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired) as error:
                raise OSError(
                    f"Could not stop demo nginx; runtime retained at "
                    f"{self._runtime}: {error}"
                ) from error
        if self._runtime is not None:
            shutil.rmtree(self._runtime)
            self._runtime = None

    def _kill_group(self, signal: str) -> None:
        pid_file = self._runtime / "nginx.pid"
        if not pid_file.exists():
            # Before nginx writes its PID, terminate the launcher, which forwards TERM.
            self._process.terminate()
            return
        pid = int(pid_file.read_text().strip())
        if pid <= 1:
            raise OSError("Invalid demo nginx PID")
        command = [executable("kill"), f"-{signal}", "--", f"-{pid}"]
        run(privileged(command) if self.port < 1024 else command)
