"""Credential storage, key identity, unlocking, and expiration."""

from __future__ import annotations

import base64
import json
import math
import os
import subprocess
import tempfile
import time
import uuid
from collections.abc import Callable
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

import keyring
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from sudoplz.core import (
    AGE_ENCRYPTED_FILE,
    CONFIG_DIR,
    HOME,
    SERVICE_NAME,
    SSH_ENCRYPTED_FILE,
    TOTP_SECRET_FILE,
    USERNAME,
    atomic_write,
    file_lock,
)

PASSWORD_FILE = CONFIG_DIR / "credential.json"
Prompt = Callable[[Path], str | None]
PrivateKey = rsa.RSAPrivateKey | ed25519.Ed25519PrivateKey


@dataclass(frozen=True)
class Credential:
    backend: str
    payload: str
    identity: str | None
    created_at: float | None

    def expired(self, hours: int) -> bool:
        return hours > 0 and (
            self.created_at is None or time.time() - self.created_at >= hours * 3600
        )


def _decode_record(data: bytes) -> Credential:
    raw = json.loads(data)
    if not isinstance(raw, dict) or set(raw) != {"backend", "payload", "identity", "created_at"}:
        raise ValueError("Invalid credential metadata; run 'sudoplz set' to replace it")
    record = Credential(**raw)
    if record.backend not in ("age", "rsa", "keyring", "empty"):
        raise ValueError("Unknown credential backend")
    if not isinstance(record.payload, str):
        raise ValueError("Invalid credential payload")
    if record.backend in ("age", "rsa"):
        if not isinstance(record.identity, str) or not os.path.isabs(record.identity):
            raise ValueError("Invalid credential identity")
        base64.b64decode(record.payload, validate=True)
    elif record.identity is not None:
        raise ValueError("Unexpected credential identity")
    if record.created_at is not None and (
        type(record.created_at) not in (int, float)
        or not math.isfinite(record.created_at)
        or record.created_at < 0
    ):
        raise ValueError("Invalid credential timestamp")
    return record


def _write_record(path: Path, record: Credential) -> None:
    atomic_write(path, json.dumps(asdict(record)).encode())


def find_ssh_key() -> Path | None:
    for stem in ("id_ed25519", "id_rsa"):
        key = HOME / ".ssh" / stem
        if key.exists() and key.with_suffix(".pub").exists():
            return key
    if any((HOME / ".ssh" / stem).exists() for stem in ("id_ecdsa", "id_dsa")):
        raise ValueError("SSH encryption requires an Ed25519 or RSA key; ECDSA/DSA are unsupported")
    return None


def _private_key(identity: Path, prompt: Prompt) -> PrivateKey:
    with identity.open("rb") as stream:
        if os.fstat(stream.fileno()).st_mode & 0o077:
            raise ValueError(f"SSH private key permissions must be 600 or stricter: {identity}")
        data = stream.read()
    loader = (
        serialization.load_ssh_private_key
        if data.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")
        else serialization.load_pem_private_key
    )
    try:
        key = loader(data, password=None)
    except TypeError:
        passphrase = prompt(identity)
        if passphrase is None:
            raise ValueError("SSH key unlock cancelled") from None
        try:
            key = loader(data, password=passphrase.encode())
        except (TypeError, ValueError, UnsupportedAlgorithm):
            raise ValueError("Could not unlock SSH key") from None
    except (ValueError, UnsupportedAlgorithm):
        raise ValueError("Could not load SSH private key") from None
    if not isinstance(key, (rsa.RSAPrivateKey, ed25519.Ed25519PrivateKey)):
        raise ValueError("SSH encryption requires an Ed25519 or RSA key")
    return key


def encrypt_age(data: str, identity: Path) -> bytes:
    result = subprocess.run(
        ["age", "-R", str(identity.with_suffix(".pub")), "-a"],
        input=data.encode(),
        capture_output=True,
        timeout=30,
    )
    if result.returncode:
        raise ValueError("age encryption failed; check the SSH public key")
    return result.stdout


def _decrypt(record: Credential, prompt: Prompt) -> str:
    if record.identity is None:
        raise ValueError("Missing SSH identity")
    key = _private_key(Path(record.identity), prompt)
    encrypted = base64.b64decode(record.payload, validate=True)
    if record.backend == "rsa":
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("Legacy credential requires an RSA key")
        return key.decrypt(encrypted, padding.PKCS1v15()).decode()
    identity = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    with tempfile.TemporaryDirectory(prefix="sudoplz-") as directory:
        ciphertext = Path(directory) / "ciphertext.age"
        ciphertext.write_bytes(encrypted)
        result = subprocess.run(
            ["age", "-d", "-i", "-", str(ciphertext)],
            input=identity,
            capture_output=True,
            timeout=30,
        )
    if result.returncode:
        raise ValueError("age decryption failed; stored SSH identity may have changed")
    return result.stdout.decode()


def _encrypted_record(data: str, identity: Path) -> Credential:
    return Credential(
        "age",
        base64.b64encode(encrypt_age(data, identity)).decode(),
        str(identity.resolve()),
        time.time(),
    )


def _read_password() -> Credential:
    try:
        return _decode_record(PASSWORD_FILE.read_bytes())
    except FileNotFoundError:
        pass
    legacy = [path for path in (AGE_ENCRYPTED_FILE, SSH_ENCRYPTED_FILE) if path.exists()]
    if legacy:
        path = max(legacy, key=lambda item: item.stat().st_mtime)
        backend, stem = ("age", "id_ed25519") if path == AGE_ENCRYPTED_FILE else ("rsa", "id_rsa")
        record = Credential(
            backend,
            base64.b64encode(path.read_bytes()).decode(),
            str(HOME / ".ssh" / stem),
            path.stat().st_mtime,
        )
    else:
        try:
            password = keyring.get_password(SERVICE_NAME, USERNAME)
        except keyring.errors.NoKeyringError:
            password = None
        record = (
            Credential("keyring", USERNAME, None, None)
            if password
            else Credential("empty", "", None, None)
        )
    _write_record(PASSWORD_FILE, record)
    return record


def _retire_previous(previous: Credential) -> None:
    for path in (AGE_ENCRYPTED_FILE, SSH_ENCRYPTED_FILE):
        path.unlink(missing_ok=True)
    usernames = {USERNAME}
    if previous.backend == "keyring":
        usernames.add(previous.payload)
    for username in usernames:
        with suppress(keyring.errors.PasswordDeleteError, keyring.errors.NoKeyringError):
            keyring.delete_password(SERVICE_NAME, username)


def store_password(password: str) -> None:
    if not password or any(character in password for character in ("\n", "\r", "\0")):
        raise ValueError("Password must be nonempty and contain no newline or NUL")
    identity = find_ssh_key()
    record = (
        _encrypted_record(password, identity)
        if identity
        else Credential("keyring", f"{USERNAME}-{uuid.uuid4().hex}", None, time.time())
    )
    with file_lock(PASSWORD_FILE):
        try:
            previous = _read_password()
        except ValueError:
            previous = Credential("empty", "", None, None)
        if record.backend == "keyring":
            keyring.set_password(SERVICE_NAME, record.payload, password)
        try:
            _write_record(PASSWORD_FILE, record)
        except OSError:
            if record.backend == "keyring":
                keyring.delete_password(SERVICE_NAME, record.payload)
            raise
        _retire_previous(previous)


def load_password(expiration_hours: int, prompt: Prompt) -> str | None:
    with file_lock(PASSWORD_FILE):
        record = _read_password()
        if record.backend == "empty":
            return None
        if record.expired(expiration_hours):
            raise ValueError("Stored password expired or has unknown age; run 'sudoplz set'")
        if record.backend == "keyring":
            password = keyring.get_password(SERVICE_NAME, record.payload)
            if password is None:
                raise ValueError("Stored keyring credential is missing; run 'sudoplz set'")
            return password
        return _decrypt(record, prompt)


def password_status(expiration_hours: int) -> Literal["missing", "expired", "stored"]:
    with file_lock(PASSWORD_FILE):
        record = _read_password()
        if record.backend == "empty":
            return "missing"
        if record.expired(expiration_hours):
            return "expired"
        return "stored"


def clear_password() -> None:
    with file_lock(PASSWORD_FILE):
        try:
            previous = _read_password()
        except ValueError:
            previous = Credential("empty", "", None, None)
        _write_record(PASSWORD_FILE, Credential("empty", "", None, None))
        _retire_previous(previous)


def save_totp_secret(secret: str) -> None:
    identity = find_ssh_key()
    if identity is None:
        raise ValueError("TOTP requires an Ed25519 or RSA SSH key")
    with file_lock(TOTP_SECRET_FILE):
        _write_record(TOTP_SECRET_FILE, _encrypted_record(secret, identity))


def load_totp_secret(prompt: Prompt) -> str | None:
    with file_lock(TOTP_SECRET_FILE):
        try:
            data = TOTP_SECRET_FILE.read_bytes()
        except FileNotFoundError:
            return None
        if data.startswith(b"{"):
            record = _decode_record(data)
        else:
            identity = find_ssh_key()
            if identity is None:
                raise ValueError("TOTP requires its original SSH identity")
            record = Credential(
                "age",
                base64.b64encode(data).decode(),
                str(identity),
                TOTP_SECRET_FILE.stat().st_mtime,
            )
        secret = _decrypt(record, prompt)
        _write_record(TOTP_SECRET_FILE, record)
        return secret
