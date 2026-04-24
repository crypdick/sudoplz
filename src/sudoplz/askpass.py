"""Askpass helper invoked by ``sudo -A``.

Prints the stored sudo password to stdout after passing security checks.
Never write anything else to stdout — sudo treats stray output as the
password.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import syslog
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sudoplz.core import (
    AGE_ENCRYPTED_FILE,
    AUDIT_LOG_FILE,
    RATE_LIMIT_FILE,
    SERVICE_NAME,
    SSH_ENCRYPTED_FILE,
    USERNAME,
    age_decrypt,
    find_ssh_key,
    has_age,
    load_config,
    load_totp_secret,
    parent_command,
    process_name,
    verify_totp,
)

try:
    import keyring

    HAS_KEYRING = True
except ImportError:
    HAS_KEYRING = False


def repair_environment() -> None:
    """Restore env vars that ``sudo -A`` strips but our subprocesses need."""
    if sys.platform == "linux" and not os.environ.get("SSH_AUTH_SOCK"):
        sock = f"/run/user/{os.getuid()}/openssh_agent"
        if os.path.exists(sock):
            os.environ["SSH_AUTH_SOCK"] = sock
    if sys.platform == "darwin":
        brew = "/opt/homebrew/bin"
        if os.path.isdir(brew) and brew not in os.environ.get("PATH", ""):
            os.environ["PATH"] = f"{brew}:{os.environ.get('PATH', '')}"


def show_dialog(user: str, host: str, command: str) -> bool:
    """Prompt the user for approval. Return True on Allow."""
    message = (
        "Administrator privileges requested\n\n"
        f"User: {user}\nHost: {host}\nCommand: {command}\n\n"
        "Do you want to allow this?"
    )

    if sys.platform == "darwin":
        escaped = message.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        script = (
            'tell application "System Events"\nactivate\n'
            f'display dialog "{escaped}" '
            'with title "Sudo Authentication Required" '
            'buttons {"Deny", "Allow"} default button "Deny" '
            "with icon caution giving up after 30\nend tell"
        )
        try:
            result = subprocess.run(
                ["osascript", "-e", script], capture_output=True, text=True, timeout=35
            )
            return result.returncode == 0 and "Allow" in result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            syslog.syslog(syslog.LOG_WARNING, f"osascript dialog failed: {e}")
            return False

    if "DISPLAY" not in os.environ:
        return False

    try:
        result = subprocess.run(
            [
                "zenity",
                "--question",
                "--title=Sudo Authentication Required",
                f"--text={message}",
                "--width=450",
                "--ok-label=Allow",
                "--cancel-label=Deny",
            ],
            capture_output=True,
            timeout=60,
        )
        return result.returncode == 0
    except FileNotFoundError:
        syslog.syslog(
            syslog.LOG_ERR,
            "zenity not found; install it (apt install zenity) or set up TOTP",
        )
        return False
    except subprocess.TimeoutExpired:
        syslog.syslog(syslog.LOG_WARNING, "zenity dialog timed out")
        return False


def prompt_totp(identity: Path, user: str, host: str, command: str) -> bool:
    """Headless approval: verify a TOTP code from ``$TOTP`` or /dev/tty."""
    secret = load_totp_secret(identity)
    if not secret:
        return False

    code = os.environ.get("TOTP", "").strip()
    if code:
        syslog.syslog(syslog.LOG_INFO, "TOTP code provided via $TOTP")
    else:
        try:
            sys.stderr.write(
                f"\n{'=' * 50}\nSUDO AUTHENTICATION REQUIRED\n{'=' * 50}\n"
                f"User: {user}\nHost: {host}\nCommand: {command}\n"
                f"{'-' * 50}\nEnter TOTP code to authorize: "
            )
            sys.stderr.flush()
            with open("/dev/tty") as tty:
                code = tty.readline().strip()
        except OSError:
            sys.stderr.write("No TOTP code available. Set $TOTP or run from a terminal.\n")
            return False

    if not code:
        return False

    if verify_totp(secret, code):
        sys.stderr.write("TOTP verified — access granted\n\n")
        sys.stderr.flush()
        syslog.syslog(syslog.LOG_INFO, "Sudo access approved via TOTP")
        return True

    sys.stderr.write("Invalid TOTP code — access denied\n\n")
    sys.stderr.flush()
    syslog.syslog(syslog.LOG_WARNING, "Invalid TOTP code provided")
    return False


def check_rate_limit(max_attempts: int, lockout_minutes: int) -> bool:
    """Enforce per-hour attempt ceiling with lockout.

    Fails closed on corruption — a broken rate-limit file means we can't
    count attempts, which means we can't safely bypass the guard.
    """
    RATE_LIMIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = (
            json.loads(RATE_LIMIT_FILE.read_text())
            if RATE_LIMIT_FILE.exists()
            else {"attempts": [], "lockout_until": None}
        )
    except (OSError, json.JSONDecodeError) as e:
        syslog.syslog(syslog.LOG_ERR, f"Rate limit file unreadable, failing closed: {e}")
        sys.stderr.write(
            f"Error: rate limit file at {RATE_LIMIT_FILE} is unreadable. Delete it to reset.\n"
        )
        return False

    now = datetime.now()
    if data.get("lockout_until"):
        lockout = datetime.fromisoformat(data["lockout_until"])
        if now < lockout:
            remaining = int((lockout - now).total_seconds() / 60)
            syslog.syslog(syslog.LOG_WARNING, f"Rate limit lockout: {remaining} min remaining")
            return False
        data["lockout_until"] = None

    one_hour_ago = now - timedelta(hours=1)
    data["attempts"] = [a for a in data["attempts"] if datetime.fromisoformat(a) > one_hour_ago]

    if len(data["attempts"]) >= max_attempts:
        data["lockout_until"] = (now + timedelta(minutes=lockout_minutes)).isoformat()
        syslog.syslog(syslog.LOG_WARNING, f"Rate limit exceeded; lockout for {lockout_minutes} min")
        RATE_LIMIT_FILE.write_text(json.dumps(data))
        return False

    data["attempts"].append(now.isoformat())
    RATE_LIMIT_FILE.write_text(json.dumps(data))
    return True


def _path_is_allowed(cwd: str, allowed: list[str]) -> bool:
    for raw in allowed:
        p = os.path.normpath(raw)
        if cwd == p or cwd.startswith(p + os.sep):
            return True
    return False


def check_security(config: dict[str, Any], identity: Path | None) -> bool:
    if not check_rate_limit(config["max_attempts_per_hour"], config["lockout_minutes"]):
        return False

    cwd = os.path.normpath(os.getcwd())
    if not _path_is_allowed(cwd, config["allowed_paths"]):
        syslog.syslog(syslog.LOG_WARNING, f"Askpass called from unauthorized path: {cwd}")
        return False

    proc = process_name(os.getppid())
    if proc not in config["allowed_processes"]:
        syslog.syslog(syslog.LOG_WARNING, f"Askpass called by unauthorized process: {proc}")
        return False

    if not (os.getenv("SSH_AUTH_SOCK") or os.getenv("SSH_TTY") or os.getenv("TERM")):
        syslog.syslog(syslog.LOG_WARNING, "Askpass called without terminal/SSH env")
        return False

    expiration_hours = config["expiration_hours"]
    if expiration_hours > 0:
        for blob in (AGE_ENCRYPTED_FILE, SSH_ENCRYPTED_FILE):
            if blob.exists() and (time.time() - blob.stat().st_mtime) > expiration_hours * 3600:
                syslog.syslog(
                    syslog.LOG_INFO, f"Password expired after {expiration_hours}h; removing {blob}"
                )
                try:
                    blob.unlink()
                except OSError as e:
                    syslog.syslog(syslog.LOG_WARNING, f"Could not remove expired {blob}: {e}")
                return False

    if config["require_user_confirmation"]:
        user = os.environ.get("USER", "unknown")
        host = socket.gethostname()
        command = parent_command(os.getppid())
        if "DISPLAY" in os.environ or sys.platform == "darwin":
            approved = show_dialog(user, host, command)
        else:
            approved = prompt_totp(identity, user, host, command) if identity else False
        if not approved:
            syslog.syslog(syslog.LOG_WARNING, "Sudo access denied by user")
            return False
        syslog.syslog(syslog.LOG_INFO, "Sudo access approved by user")

    return True


def prompt_passphrase(priv: Path) -> str | None:
    """GUI prompt for SSH key passphrase (osascript on macOS, zenity on Linux)."""
    if sys.platform == "darwin":
        script = (
            f'display dialog "Enter passphrase for {priv}:" '
            'default answer "" with hidden answer '
            'with title "SSH Key Passphrase Required" '
            'with icon caution'
        )
        try:
            result = subprocess.run(
                ["osascript", "-e", script], capture_output=True, text=True, timeout=120
            )
            if result.returncode != 0:
                return None
            for part in result.stdout.split(", "):
                if part.startswith("text returned:"):
                    return part.removeprefix("text returned:").rstrip("\n")
            return None
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            syslog.syslog(syslog.LOG_WARNING, f"osascript passphrase prompt failed: {e}")
            return None

    if "DISPLAY" not in os.environ:
        return None

    try:
        result = subprocess.run(
            ["zenity", "--password", "--title=SSH Key Passphrase Required"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result.stdout.rstrip("\n") if result.returncode == 0 else None
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        syslog.syslog(syslog.LOG_WARNING, f"zenity passphrase prompt failed: {e}")
        return None


def ensure_ssh_key_loaded(priv: Path) -> bool:
    """Make sure ssh-agent holds the private key, prompting for passphrase if not."""
    if not os.environ.get("SSH_AUTH_SOCK"):
        syslog.syslog(syslog.LOG_ERR, "No SSH_AUTH_SOCK available; start ssh-agent first")
        return False

    try:
        fingerprint_out = subprocess.run(
            ["ssh-keygen", "-lf", str(priv)], capture_output=True, text=True
        )
        if fingerprint_out.returncode != 0:
            return False
        fingerprint = fingerprint_out.stdout.split()[1]

        list_out = subprocess.run(["ssh-add", "-l"], capture_output=True, text=True)
        if list_out.returncode == 0 and fingerprint in list_out.stdout:
            return True
    except FileNotFoundError as e:
        syslog.syslog(syslog.LOG_ERR, f"ssh tooling missing: {e}")
        return False

    passphrase = prompt_passphrase(priv)
    if passphrase is None:
        return False
    add_result = subprocess.run(
        ["ssh-add", str(priv)], input=passphrase.encode(), capture_output=True
    )
    return add_result.returncode == 0


def decrypt_with_openssl(encrypted_file: Path, priv: Path, key_type: str) -> str | None:
    """Decrypt a blob via OpenSSL for RSA / ECDSA / DSA keys."""
    try:
        encrypted = encrypted_file.read_bytes()
    except OSError as e:
        syslog.syslog(syslog.LOG_ERR, f"Cannot read {encrypted_file}: {e}")
        return None

    direct = subprocess.run(
        ["openssl", "pkeyutl", "-decrypt", "-inkey", str(priv)],
        input=encrypted,
        capture_output=True,
    )
    if direct.returncode == 0:
        return direct.stdout.decode().strip()

    base_cmd = {
        "RSA": ["openssl", "rsa", "-in", str(priv)],
        "DSA": ["openssl", "dsa", "-in", str(priv)],
        "ECDSA": ["openssl", "ec", "-in", str(priv)],
    }.get(key_type, ["openssl", "pkey", "-in", str(priv)])

    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
        temp_pem = f.name
    try:
        os.chmod(temp_pem, 0o600)
        if subprocess.run([*base_cmd, "-out", temp_pem], capture_output=True).returncode != 0:
            return None
        result = subprocess.run(
            ["openssl", "pkeyutl", "-decrypt", "-inkey", temp_pem],
            input=encrypted,
            capture_output=True,
        )
        return result.stdout.decode().strip() if result.returncode == 0 else None
    finally:
        if os.path.exists(temp_pem):
            os.remove(temp_pem)


def validate_script_integrity() -> bool:
    """Refuse to run if our own module file is world-writable.

    Group-write is tolerated because user-local installs under
    common umasks produce 664 files where the group is a single-member
    user group. World-write is the real threat — anyone on the box
    could rewrite the script to leak passwords.
    """
    this_file = Path(__file__).resolve()
    os.environ["SUDO_ASKPASS"] = str(this_file)
    stats = this_file.stat()
    if stats.st_mode & 0o002:
        syslog.syslog(
            syslog.LOG_CRIT, f"Askpass module is world-writable: {oct(stats.st_mode)}"
        )
        return False
    return True


def write_audit_entry(ppid: int, proc: str | None, command: str) -> None:
    try:
        AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": datetime.now().isoformat(),
            "pid": ppid,
            "process": proc or "unknown",
            "command": command,
            "user": os.environ.get("USER", "unknown"),
            "cwd": os.getcwd(),
            "status": "approved",
        }
        with AUDIT_LOG_FILE.open("a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as e:
        syslog.syslog(syslog.LOG_WARNING, f"Could not write audit log: {e}")


def main() -> None:
    syslog.openlog("sudoplz")
    repair_environment()

    if not validate_script_integrity():
        print("Error: environment validation failed", file=sys.stderr)
        sys.exit(1)

    config = load_config()
    priv, _, key_type = find_ssh_key()

    if not check_security(config, priv):
        print("Error: security check failed", file=sys.stderr)
        syslog.syslog(syslog.LOG_ERR, "Security check failed")
        sys.exit(1)

    ppid = os.getppid()
    write_audit_entry(ppid, process_name(ppid), parent_command(ppid))

    # Priority 1: age-encrypted file (Ed25519).
    if AGE_ENCRYPTED_FILE.exists() and priv and has_age() and ensure_ssh_key_loaded(priv):
        password = age_decrypt(AGE_ENCRYPTED_FILE.read_bytes(), priv)
        if password:
            print(password)
            syslog.syslog(syslog.LOG_INFO, f"Password retrieved via age ({key_type} key)")
            return

    # Priority 2: OpenSSL-encrypted file (RSA / ECDSA / DSA).
    if SSH_ENCRYPTED_FILE.exists() and priv and key_type and key_type != "Ed25519":
        password = decrypt_with_openssl(SSH_ENCRYPTED_FILE, priv, key_type)
        if password:
            print(password)
            syslog.syslog(syslog.LOG_INFO, f"Password retrieved via SSH ({key_type} key)")
            return

    # Priority 3: system keyring.
    if HAS_KEYRING:
        try:
            password = keyring.get_password(SERVICE_NAME, USERNAME)
            if password:
                print(password)
                syslog.syslog(syslog.LOG_INFO, "Password retrieved via keyring")
                return
        except Exception as e:
            syslog.syslog(syslog.LOG_WARNING, f"Keyring lookup failed: {e}")

    print("Error: no password found in secure storage", file=sys.stderr)
    print("Use 'sudoplz set' to store the password securely", file=sys.stderr)
    syslog.syslog(syslog.LOG_ERR, "No password found in secure storage")
    sys.exit(1)


if __name__ == "__main__":
    main()
