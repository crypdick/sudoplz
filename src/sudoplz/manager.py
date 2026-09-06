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
import warnings
from datetime import datetime
from pathlib import Path

import keyring

from sudoplz import credentials
from sudoplz.core import (
    AUDIT_LOG_FILE,
    CONFIG_FILE,
    atomic_write,
    generate_totp_secret,
    load_config,
    verify_totp,
)


def prompt_passphrase(identity: Path) -> str | None:
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(f"Enter passphrase for {identity}: ")
        except (OSError, EOFError, getpass.GetPassWarning):
            return None


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
    credentials.store_password(password)
    print("Password stored securely")
    return True


def cmd_set_totp(_args: argparse.Namespace) -> bool:
    secret = credentials.load_totp_secret(prompt_passphrase)
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
    credentials.store_password(password)
    print("Password stored securely")
    return True


def cmd_totp_setup(_args: argparse.Namespace) -> bool:
    secret = generate_totp_secret()
    credentials.save_totp_secret(secret)

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
    status = credentials.password_status(load_config()["expiration_hours"])
    print(
        {
            "missing": "No password stored",
            "expired": "Stored password expired or has unknown age; run 'sudoplz set'",
            "stored": "Password stored securely",
        }[status]
    )
    return status == "stored"


def cmd_clear(_args: argparse.Namespace) -> bool:
    credentials.clear_password()
    print("Stored password cleared")
    return True


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


def cmd_config(args: argparse.Namespace) -> bool:
    config = load_config()

    if args.show:
        print(json.dumps(config, indent=2))
        return True

    if args.no_expire:
        new_value = 0
    elif args.expire_hours is not None:
        if args.expire_hours < 0:
            print("Error: --expire-hours must be 0 or positive (0 disables)", file=sys.stderr)
            return False
        new_value = args.expire_hours
    else:
        print("Error: specify --show, --no-expire, or --expire-hours N", file=sys.stderr)
        return False

    config["expiration_hours"] = new_value
    atomic_write(CONFIG_FILE, (json.dumps(config, indent=2) + "\n").encode())

    if new_value == 0:
        print("Expiration disabled. Stored password will not expire.")
    else:
        print(f"Expiration set to {new_value} hours.")
    return True


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

    config_parser = sub.add_parser("config", help="View or modify sudoplz configuration")
    config_group = config_parser.add_mutually_exclusive_group(required=True)
    config_group.add_argument("--show", action="store_true", help="Print current configuration")
    config_group.add_argument(
        "--no-expire",
        action="store_true",
        help="Disable password expiration (sets expiration_hours = 0)",
    )
    config_group.add_argument(
        "--expire-hours",
        type=int,
        metavar="N",
        help="Set password expiration in hours (0 disables expiration)",
    )
    config_parser.set_defaults(func=cmd_config)

    args = parser.parse_args()
    try:
        succeeded = args.func(args)
    except (OSError, ValueError, subprocess.SubprocessError, keyring.errors.KeyringError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        succeeded = False
    sys.exit(0 if succeeded else 1)


if __name__ == "__main__":
    main()
