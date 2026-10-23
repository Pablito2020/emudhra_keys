"""An isolated, foreground nginx HTTPS server."""

import grp
import os
import pwd
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from src.certificates_directory import SSLConfiguration
from src.demo.dns import normalize_domain
from src.demo.system import executable, privileged, run

NGINX = Path(__file__).parent / "nginx"


def _quote(value: str | Path) -> str:
    value = str(value)
    if any(character in value for character in "\r\n$"):
        raise ValueError("Unsupported character in nginx configuration path")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class Server:
    def __init__(
        self, domain: str, ssl_configuration: SSLConfiguration, port: int = 443
    ):
        self.domain = normalize_domain(domain)
        self.ssl_configuration = ssl_configuration
        if not 1 <= port <= 65535:
            raise ValueError("Invalid HTTPS port")
        self.port = port
        self._runtime: Path | None = None
        self._process: subprocess.Popen | None = None
        self._pid: int | None = None
        self._started_at: str | None = None

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
        NGINX.mkdir(exist_ok=True)
        self._runtime = Path(tempfile.mkdtemp(prefix="run-", dir=NGINX)).resolve()
        try:
            self._config = self._runtime / "nginx.conf"
            chain_path = self._runtime / "fullchain.pem"
            chain_path.write_bytes(self.ssl_configuration.chain)
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
        ssl_certificate_key {_quote(self.ssl_configuration.key)};
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
            self._wait_started()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def wait(self) -> None:
        if self._process is None:
            raise RuntimeError("Server has not been started")
        while self._group_alive():
            time.sleep(0.1)
        status = self._process.wait(timeout=2)
        if status:
            raise OSError(f"nginx exited with status {status}")

    def __exit__(self, *exc):
        try:
            self._stop()
        except (OSError, subprocess.TimeoutExpired) as error:
            raise OSError(
                f"Could not stop demo nginx; runtime retained at "
                f"{self._runtime}: {error}"
            ) from error
        if self._runtime is not None:
            shutil.rmtree(self._runtime)
            self._runtime = None

    def _capture_pid(self) -> bool:
        if self._pid is not None:
            return True
        # The launcher may exit before nginx writes its PID file.
        for proc in Path("/proc").iterdir():
            if not proc.name.isdecimal():
                continue
            try:
                fields = (proc / "stat").read_text().rsplit(")", 1)[1].split()
                if fields[0] in {"Z", "X"} or fields[2:4] != [proc.name, proc.name]:
                    continue
                command = (proc / "cmdline").read_bytes()
                if (
                    command.startswith(b"nginx: master process ")
                    or command.split(b"\0", 1)[0] == os.fsencode(self._nginx)
                ) and os.fsencode(self._config) in command:
                    self._pid = int(proc.name)
                    self._started_at = fields[19]
                    return True
            except FileNotFoundError, ProcessLookupError, PermissionError:
                continue
        return False

    def _wait_started(self) -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self._capture_pid():
                try:
                    if (self._runtime / "nginx.pid").read_text().strip() == str(
                        self._pid
                    ):
                        return
                except FileNotFoundError:
                    pass
            if self._process.poll() not in (None, 0):
                raise OSError("nginx exited during startup; check its stderr output")
            time.sleep(0.05)
        raise OSError("nginx did not start within five seconds")

    def _group_alive(self) -> bool:
        if self._pid is None:
            return False
        self._process.poll()
        for proc in Path("/proc").iterdir():
            if not proc.name.isdecimal():
                continue
            try:
                fields = (proc / "stat").read_text().rsplit(")", 1)[1].split()
            except FileNotFoundError, ProcessLookupError:
                continue
            if proc.name == str(self._pid) and fields[19] != self._started_at:
                raise OSError("Demo nginx PID was reused; refusing to signal it")
            if fields[2:4] == [str(self._pid), str(self._pid)] and fields[0] not in {
                "Z",
                "X",
            }:
                return True
        return False

    def _wait_stopped(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while self._group_alive():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)
        return True

    def _stop(self) -> None:
        if self._process is None:
            return
        if self._pid is None:
            deadline = time.monotonic() + 1
            while not self._capture_pid() and time.monotonic() < deadline:
                time.sleep(0.05)
            if self._pid is None and self._process.poll() is None:
                self._process.terminate()
                self._process.wait(timeout=2)
                self._capture_pid()
        last_error = None
        for name, timeout in (("QUIT", 5), ("TERM", 2), ("KILL", 2)):
            if not self._group_alive():
                break
            try:
                self._kill_group(name)
            except OSError as error:
                last_error = error
                continue
            if self._wait_stopped(timeout):
                break
        if self._group_alive():
            raise OSError(
                f"Demo nginx process group {self._pid} is still running"
            ) from last_error
        self._process.wait(timeout=2)

    def _kill_group(self, name: str) -> None:
        # Signal the actual nginx group; do not reload config or trust sudo's lifetime.
        try:
            if self.port < 1024:
                run(
                    privileged(
                        [
                            executable("kill"),
                            f"-{name}",
                            "--",
                            f"-{self._pid}",
                        ]
                    )
                )
            else:
                os.killpg(self._pid, getattr(signal, f"SIG{name}"))
        except OSError:
            if self._group_alive():
                raise
