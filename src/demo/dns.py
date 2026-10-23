"""Temporary local name resolution, restored when the context exits."""

import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path
from uuid import uuid4

from src.demo.system import executable, privileged, run

HOSTS = Path("/etc/hosts")
STATIC_RECORDS = Path("/run/systemd/resolve/static.d")
LOCKS = Path(tempfile.gettempdir()) / f"emudhra-demo-{os.getuid()}"


def normalize_domain(domain: str) -> str:
    """Accept a DNS hostname, never a path, IP address, or nginx directive."""
    try:
        domain = domain.removesuffix(".").encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("Invalid DNS hostname") from error
    if len(domain) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in domain.split(".")
    ):
        raise ValueError("Invalid DNS hostname")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError("Use a DNS hostname, not an IP address")


def _uses_static_records() -> bool:
    if not shutil.which("resolvectl") or not shutil.which("systemctl"):
        return False
    version = run([executable("resolvectl"), "--version"]).stdout
    match = re.match(rb"systemd (\d+)", version)
    return (
            bool(match and int(match[1]) >= 261)
            and subprocess.run(
        [
            executable("systemctl"),
            "is-active",
            "--quiet",
            "systemd-resolved.service",
        ],
        capture_output=True,
    ).returncode
            == 0
    )


def _reload_resolved() -> None:
    run(
        privileged(
            [
                executable("systemctl"),
                "kill",
                "--kill-whom=main",
                "--signal=HUP",
                "systemd-resolved.service",
            ]
        )
    )


def _verify(domain: str, ip: str) -> None:
    deadline = time.monotonic() + 3
    while True:
        try:
            addresses = {
                item[4][0]
                for item in socket.getaddrinfo(
                    domain,
                    None,
                    type=socket.SOCK_STREAM,
                )
            }
            if addresses == {ip}:
                return
        except socket.gaierror:
            pass
        if time.monotonic() >= deadline:
            raise OSError(f"{domain} does not resolve exclusively to {ip}")
        time.sleep(0.1)


class DnsResolver:
    def __init__(self):
        self._stack = ExitStack()
        self._domains: set[str] = set()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return self._stack.__exit__(*exc)

    def add_record(self, domain: str, ip: str) -> None:
        domain = normalize_domain(domain)
        ip = str(ipaddress.ip_address(ip))
        if domain in self._domains:
            raise ValueError(f"A record for {domain} was already added")
        with ExitStack() as pending:
            LOCKS.mkdir(mode=0o700, exist_ok=True)
            info = LOCKS.lstat()
            if LOCKS.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise PermissionError(f"Unsafe lock directory: {LOCKS}")
            name = hashlib.sha256(domain.encode()).hexdigest()
            lock = os.fdopen(
                os.open(
                    LOCKS / name,
                    os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                    0o600,
                ),
                "rb+",
            )
            pending.enter_context(lock)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise OSError(f"Another demo is already running for {domain}") from None
            if _uses_static_records():
                self._add_static(domain, ip, pending)
            else:
                self._add_hosts(domain, ip, pending)
            _verify(domain, ip)
            self._stack.enter_context(pending.pop_all())
        self._domains.add(domain)

    @staticmethod
    def _add_static(domain: str, ip: str, pending: ExitStack) -> None:
        target = STATIC_RECORDS / f"emudhra-{uuid4().hex}.rr"
        record = {
            "key": {"name": domain, "type": 1 if ":" not in ip else 28},
            "address": ip,
        }
        pending.callback(DnsResolver._remove_static, target)
        with tempfile.NamedTemporaryFile() as source:
            source.write(json.dumps(record).encode())
            source.flush()
            run(
                privileged(
                    [
                        executable("install"),
                        "-D",
                        "-m",
                        "0644",
                        source.name,
                        str(target),
                    ]
                )
            )
        _reload_resolved()

    @staticmethod
    def _remove_static(target: Path) -> None:
        if target.exists():
            run(privileged([executable("rm"), "--", str(target)]))
            _reload_resolved()

    @staticmethod
    def _add_hosts(domain: str, ip: str, pending: ExitStack) -> None:
        if HOSTS.is_symlink() or os.statvfs(HOSTS).f_flag & os.ST_RDONLY:
            raise OSError(
                f"{HOSTS} is managed or read-only; use active systemd-resolved 261+ "
                "with ReadStaticRecords=yes"
            )
        marker = f"\n{ip} {domain} # emudhra-demo:{uuid4().hex}\n".encode()
        with HOSTS.open("rb") as hosts:
            fcntl.flock(hosts, fcntl.LOCK_EX)
            contents = hosts.read()
            existing = {
                parts[0]
                for line in contents.decode().splitlines()
                if len(parts := line.split("#", 1)[0].split()) > 1
                   and domain in {name.lower().rstrip(".") for name in parts[1:]}
            }
            if existing and existing != {ip}:
                raise ValueError(f"Conflicting entry for {domain} in {HOSTS}")
            if existing:
                return
            pending.callback(DnsResolver._remove_hosts, marker)
            run(privileged([executable("tee"), "-a", str(HOSTS)]), input=marker)

    @staticmethod
    def _remove_hosts(marker: bytes) -> None:
        with HOSTS.open("rb") as hosts:
            fcntl.flock(hosts, fcntl.LOCK_EX)
            contents = hosts.read()
            if marker not in contents:
                tag = marker.split(b"# ", 1)[1].strip()
                if tag in contents:
                    raise OSError(f"Demo entry in {HOSTS} changed; check it manually")
                return
            before, _, after = contents.partition(marker)
            # Keep a line boundary if another writer appended after our entry.
            separator = (
                b"\n"
                if before
                   and after
                   and not before.endswith(b"\n")
                   and not after.startswith(b"\n")
                else b""
            )
            updated = before + separator + after
            try:
                run(privileged([executable("tee"), str(HOSTS)]), input=updated)
            except OSError:
                # A failed write may have truncated hosts; restore the locked snapshot.
                run(privileged([executable("tee"), str(HOSTS)]), input=contents)
                raise
