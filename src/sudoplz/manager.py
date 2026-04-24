"""sudoplz — CLI to store, inspect, and clear sudo passwords."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from sudoplz.core import (
    AGE_ENCRYPTED_FILE,
    AUDIT_LOG_FILE,
    SERVICE_NAME,
    SSH_ENCRYPTED_FILE,
    USERNAME,
    age_encrypt,
    find_ssh_key,
    generate_totp_secret,
    has_age,
    load_totp_secret,
    save_totp_secret,
    verify_totp,
)

try:
    import keyring

    HAS_KEYRING = True
except ImportError:
    HAS_KEYRING = False


def encrypt_with_openssl(password: str, pub: Path) -> bytes | None:
    """RSA / ECDSA / DSA path: convert SSH pubkey to PEM, encrypt with pkeyutl."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
        temp_pem = f.name
    try:
        os.chmod(temp_pem, 0o600)
        extract = subprocess.run(
            ["ssh-keygen", "-e", "-m", "PKCS8", "-f", str(pub)],
            capture_output=True,
            text=True,
        )
        if extract.returncode != 0:
            return None
        Path(temp_pem).write_text(extract.stdout)
        result = subprocess.run(
            ["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", temp_pem],
            input=password.encode(),
            capture_output=True,
        )
        return result.stdout if result.returncode == 0 else None
    finally:
        if os.path.exists(temp_pem):
            os.remove(temp_pem)


def store_password(
    password: str, priv: Path | None, pub: Path | None, key_type: str | None
) -> bool:
    """Write password to the appropriate encrypted store."""
    if priv and pub and key_type:
        if key_type == "Ed25519":
            if not has_age():
                print("Error: Ed25519 keys require the 'age' encryption tool", file=sys.stderr)
                print("Install: https://github.com/FiloSottile/age#installation", file=sys.stderr)
                return False
            encrypted = age_encrypt(password, pub)
            if encrypted is None:
                return False
            AGE_ENCRYPTED_FILE.write_bytes(encrypted)
            AGE_ENCRYPTED_FILE.chmod(0o600)
            print(f"Password encrypted with {key_type} key → {AGE_ENCRYPTED_FILE}")
            return True

        encrypted = encrypt_with_openssl(password, pub)
        if encrypted is None:
            print(f"Error: {key_type} encryption failed", file=sys.stderr)
            return False
        SSH_ENCRYPTED_FILE.write_bytes(encrypted)
        SSH_ENCRYPTED_FILE.chmod(0o600)
        print(f"Password encrypted with {key_type} key → {SSH_ENCRYPTED_FILE}")
        return True

    if HAS_KEYRING:
        try:
            keyring.set_password(SERVICE_NAME, USERNAME, password)
            print("Password stored in system keyring")
            return True
        except Exception as e:
            print(f"Keyring storage failed: {e}", file=sys.stderr)

    print("Error: no SSH keys or keyring available for secure storage", file=sys.stderr)
    return False


def _prompt_and_confirm_password() -> str | None:
    password = getpass.getpass("Enter sudo password to store: ")
    if not password:
        print("Error: empty password", file=sys.stderr)
        return None
    if getpass.getpass("Confirm password: ") != password:
        print("Error: passwords don't match", file=sys.stderr)
        return None
    return password


def cmd_set(_args: argparse.Namespace) -> bool:
    password = _prompt_and_confirm_password()
    if password is None:
        return False
    return store_password(password, *find_ssh_key())


def cmd_set_totp(_args: argparse.Namespace) -> bool:
    priv, pub, key_type = find_ssh_key()
    if not priv:
        print("Error: no SSH key found", file=sys.stderr)
        return False

    secret = load_totp_secret(priv)
    if not secret:
        print(
            "Error: TOTP not configured. Run 'sudoplz totp-setup' first.",
            file=sys.stderr,
        )
        return False

    print("TOTP-authenticated password entry (headless mode)")
    print("-" * 50)

    is_tty = sys.stdin.isatty()
    code = input("Enter TOTP code: ").strip() if is_tty else sys.stdin.readline().strip()

    if not verify_totp(secret, code):
        print("Error: invalid TOTP code", file=sys.stderr)
        return False

    print("TOTP verified.")

    if is_tty:
        password = _prompt_and_confirm_password()
    else:
        password = sys.stdin.readline().rstrip("\n")
        confirm = sys.stdin.readline().rstrip("\n")
        if not password or password != confirm:
            print(
                "Error: passwords don't match" if password else "Error: empty password",
                file=sys.stderr,
            )
            password = None

    if password is None:
        return False
    return store_password(password, priv, pub, key_type)


def cmd_totp_setup(_args: argparse.Namespace) -> bool:
    if not has_age():
        print("Error: TOTP requires the 'age' encryption tool", file=sys.stderr)
        return False
    _, pub, _ = find_ssh_key()
    if not pub:
        print("Error: TOTP requires SSH keys", file=sys.stderr)
        return False

    secret = generate_totp_secret()
    if not save_totp_secret(secret, pub):
        print("Error: failed to save TOTP secret", file=sys.stderr)
        return False

    user = os.environ.get("USER", "user")
    host = socket.gethostname()
    print()
    print("=" * 60)
    print("TOTP Setup Complete")
    print("=" * 60)
    print(f"\nSecret: {secret}\n")
    print("Add to your authenticator app:")
    print(f"  Account: {user}@{host} (sudoplz)")
    print(f"  Secret:  {secret}\n")
    print("Or scan this URL:")
    print(f"  otpauth://totp/{user}@{host}:sudoplz?secret={secret}&issuer=sudoplz")
    print("\n" + "=" * 60)
    return True


def cmd_get(_args: argparse.Namespace) -> bool:
    if AGE_ENCRYPTED_FILE.exists():
        print(f"Password stored (age-encrypted at {AGE_ENCRYPTED_FILE})")
        return True
    if SSH_ENCRYPTED_FILE.exists():
        print(f"Password stored (SSH-encrypted at {SSH_ENCRYPTED_FILE})")
        return True
    if HAS_KEYRING:
        try:
            if keyring.get_password(SERVICE_NAME, USERNAME):
                print("Password stored (system keyring)")
                return True
        except Exception as e:
            print(f"Keyring lookup failed: {e}", file=sys.stderr)
    print("No password stored")
    return False


def cmd_clear(_args: argparse.Namespace) -> bool:
    cleared = False
    for path in (AGE_ENCRYPTED_FILE, SSH_ENCRYPTED_FILE):
        if path.exists():
            path.unlink()
            print(f"Removed {path}")
            cleared = True
    if HAS_KEYRING:
        try:
            keyring.delete_password(SERVICE_NAME, USERNAME)
            print("Removed from system keyring")
            cleared = True
        except Exception:
            pass
    if not cleared:
        print("Nothing to clear")
    return cleared


def cmd_test(_args: argparse.Namespace) -> bool:
    askpass = shutil.which("askpass")
    if not askpass:
        print(
            "Error: 'askpass' not on PATH. Install with 'uv tool install .' first.",
            file=sys.stderr,
        )
        return False

    env = os.environ.copy()
    env["SUDO_ASKPASS"] = askpass
    print(f"Testing sudo -A with {askpass}...")
    result = subprocess.run(
        ["sudo", "-A", "echo", "Success!"], env=env, capture_output=True, text=True
    )
    if result.returncode == 0:
        print(f"Test successful: {result.stdout.strip()}")
        return True
    print(f"Test failed: {result.stderr.strip()}", file=sys.stderr)
    return False


def cmd_audit(_args: argparse.Namespace) -> bool:
    if not AUDIT_LOG_FILE.exists():
        print("No audit log found")
        return True
    lines = AUDIT_LOG_FILE.read_text().splitlines()[-50:]
    print(f"\nRecent askpass usage (last {len(lines)} entries):")
    print("-" * 80)
    for line in lines:
        try:
            entry = json.loads(line)
            ts = datetime.fromisoformat(entry["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            cmd = entry.get("command", "")
            print(
                f"{ts} | user={entry.get('user', '?')} | "
                f"proc={entry.get('process', '?')} | cmd={cmd[:60]}"
            )
        except (json.JSONDecodeError, KeyError):
            continue
    print("-" * 80)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sudoplz",
        description="Manage secure sudo password storage.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    commands = [
        ("set", "Store sudo password (terminal prompt)", cmd_set),
        ("set-totp", "Store sudo password with TOTP (headless)", cmd_set_totp),
        ("totp-setup", "Generate TOTP secret for headless entry", cmd_totp_setup),
        ("get", "Check whether a password is stored", cmd_get),
        ("clear", "Remove stored passwords", cmd_clear),
        ("test", "Test sudo -A integration", cmd_test),
        ("audit", "Show recent askpass usage", cmd_audit),
    ]
    for name, help_text, fn in commands:
        p = sub.add_parser(name, help=help_text)
        p.set_defaults(func=fn)

    args = parser.parse_args()
    sys.exit(0 if args.func(args) else 1)


if __name__ == "__main__":
    main()
