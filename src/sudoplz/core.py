"""Shared helpers for askpass and sudoplz."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import os
import struct
import subprocess
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TypedDict, cast

SERVICE_NAME = "sudoplz"
USERNAME = "sudo"

HOME = Path.home()
CONFIG_DIR = HOME / ".config" / "sudoplz"
CONFIG_FILE = CONFIG_DIR / "config.json"
RATE_LIMIT_FILE = CONFIG_DIR / "rate_limit.json"
AUDIT_LOG_FILE = CONFIG_DIR / "audit.log"
TOTP_SECRET_FILE = CONFIG_DIR / "totp_secret.enc"

SSH_ENCRYPTED_FILE = HOME / ".sudo_askpass.ssh"
AGE_ENCRYPTED_FILE = HOME / ".sudo_askpass.age"


class Config(TypedDict):
    require_user_confirmation: bool
    allowed_paths: list[str]
    expiration_hours: int
    allowed_processes: list[str]
    max_attempts_per_hour: int
    lockout_minutes: int


DEFAULT_CONFIG: Config = {
    "require_user_confirmation": True,
    "allowed_paths": [str(HOME), "/tmp/"],
    "expiration_hours": 168,
    "allowed_processes": ["sudo", "claude-code", "code", "bash", "sh", "zsh", "fish"],
    "max_attempts_per_hour": 30,
    "lockout_minutes": 15,
}


def load_config() -> Config:
    """Load policy, rejecting malformed settings before evaluating any guard."""
    try:
        raw = json.loads(CONFIG_FILE.read_text())
    except FileNotFoundError:
        raw = {}
    except (OSError, ValueError) as exc:
        raise ValueError(f"Cannot read policy at {CONFIG_FILE}") from exc
    if not isinstance(raw, dict) or raw.keys() - DEFAULT_CONFIG.keys():
        raise ValueError("Config must be an object containing only known settings")
    config = {**DEFAULT_CONFIG, **raw}
    if type(config["require_user_confirmation"]) is not bool:
        raise ValueError("require_user_confirmation must be true or false")
    for name in ("expiration_hours", "max_attempts_per_hour", "lockout_minutes"):
        value = config[name]
        minimum = 0 if name == "expiration_hours" else 1
        if type(value) is not int or value < minimum:
            raise ValueError(f"{name} must be an integer >= {minimum}")
    for name in ("allowed_paths", "allowed_processes"):
        value = config[name]
        if not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value):
            raise ValueError(f"{name} must be a list of nonempty strings")
    if any(not os.path.isabs(path) for path in config["allowed_paths"]):
        raise ValueError("allowed_paths must contain absolute paths")
    return cast(Config, config)


@contextmanager
def file_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(fd, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


# TOTP (RFC 6238, SHA-1, 30s step, 6 digits).


def generate_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode("ascii")


def totp_code(secret: str, offset: int = 0, time_step: int = 30) -> str:
    key = base64.b32decode(secret.upper().replace(" ", ""))
    counter = int(time.time() // time_step) + offset
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[o : o + 4])[0] & 0x7FFFFFFF
    return f"{code % 1_000_000:06d}"


def verify_totp(secret: str, provided: str, window: int = 1) -> bool:
    """Constant-time TOTP check across a ±window step tolerance."""
    for offset in range(-window, window + 1):
        if hmac.compare_digest(provided, totp_code(secret, offset)):
            return True
    return False


def process_name(pid: int) -> str | None:
    """Resolve a PID's command name via `ps`, or None on failure."""
    try:
        out = subprocess.check_output(["ps", "-p", str(pid), "-o", "comm="])
        return os.path.basename(out.decode().strip())
    except subprocess.CalledProcessError:
        return None


def parent_command(pid: int) -> str:
    """Return the parent process's full command line, or 'Unknown command'."""
    try:
        out = subprocess.check_output(["ps", "-p", str(pid), "-o", "args="])
        parts = out.decode().strip().split()
        if parts and "sudo" in parts[0]:
            for i, part in enumerate(parts):
                if part != "sudo" and not part.startswith("-"):
                    return " ".join(parts[i:])
        return " ".join(parts) or "Unknown command"
    except subprocess.CalledProcessError:
        return "Unknown command"
