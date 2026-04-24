"""Shared helpers for askpass and sudoplz."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import subprocess
import syslog
import time
from pathlib import Path
from typing import Any

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

SSH_KEY_CANDIDATES: list[tuple[str, str]] = [
    ("id_ed25519", "Ed25519"),
    ("id_ecdsa", "ECDSA"),
    ("id_rsa", "RSA"),
    ("id_dsa", "DSA"),
]

DEFAULT_CONFIG: dict[str, Any] = {
    "require_user_confirmation": True,
    "allowed_paths": [str(HOME), "/tmp/"],
    "expiration_hours": 168,
    "allowed_processes": ["sudo", "claude-code", "code", "bash", "sh", "zsh", "fish"],
    "max_attempts_per_hour": 30,
    "lockout_minutes": 15,
}


def has_age() -> bool:
    try:
        return subprocess.run(["age", "--version"], capture_output=True).returncode == 0
    except FileNotFoundError:
        return False


def find_ssh_key() -> tuple[Path | None, Path | None, str | None]:
    """Return (private, public, type) of the first available SSH keypair."""
    ssh_dir = HOME / ".ssh"
    for stem, key_type in SSH_KEY_CANDIDATES:
        priv = ssh_dir / stem
        pub = ssh_dir / f"{stem}.pub"
        if priv.exists() and pub.exists():
            return priv, pub, key_type
    return None, None, None


def load_config() -> dict[str, Any]:
    """Merge DEFAULT_CONFIG with ~/.config/sudoplz/config.json."""
    config = dict(DEFAULT_CONFIG)
    if not CONFIG_FILE.exists():
        return config
    try:
        with CONFIG_FILE.open() as f:
            config.update(json.load(f))
    except (OSError, json.JSONDecodeError) as e:
        syslog.syslog(syslog.LOG_WARNING, f"Ignoring malformed config {CONFIG_FILE}: {e}")
    return config


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


# age wrappers (Ed25519 path).


def age_encrypt(data: str, recipient_pub: Path) -> bytes | None:
    if not has_age():
        return None
    result = subprocess.run(
        ["age", "-R", str(recipient_pub), "-a"],
        input=data.encode(),
        capture_output=True,
    )
    if result.returncode != 0:
        syslog.syslog(syslog.LOG_ERR, f"age encrypt failed: {result.stderr.decode().strip()}")
        return None
    return result.stdout


def age_decrypt(encrypted: bytes, identity: Path) -> str | None:
    if not has_age():
        return None
    result = subprocess.run(
        ["age", "-d", "-i", str(identity)],
        input=encrypted,
        capture_output=True,
    )
    if result.returncode != 0:
        syslog.syslog(syslog.LOG_ERR, f"age decrypt failed: {result.stderr.decode().strip()}")
        return None
    return result.stdout.decode().strip()


def load_totp_secret(identity: Path) -> str | None:
    if not TOTP_SECRET_FILE.exists():
        return None
    try:
        return age_decrypt(TOTP_SECRET_FILE.read_bytes(), identity)
    except OSError as e:
        syslog.syslog(syslog.LOG_ERR, f"Could not read TOTP secret: {e}")
        return None


def save_totp_secret(secret: str, recipient_pub: Path) -> bool:
    encrypted = age_encrypt(secret, recipient_pub)
    if encrypted is None:
        return False
    TOTP_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    TOTP_SECRET_FILE.write_bytes(encrypted)
    TOTP_SECRET_FILE.chmod(0o600)
    return True


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
