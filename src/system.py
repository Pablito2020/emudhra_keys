"""Small subprocess helpers for the system tools used by the demo."""

import os
import shutil
import subprocess


def executable(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise FileNotFoundError(f"{name} is required; enter the Nix development shell")
    return os.path.abspath(path)


def privileged(args: list[str]) -> list[str]:
    if os.geteuid() == 0:
        return args
    return [executable("sudo"), "--", *args]


def run(args: list[str], *, input: bytes | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, input=input, capture_output=True, check=True)
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode(errors="replace").strip()
        raise OSError(f"{args[0]} failed: {detail or error.returncode}") from error
