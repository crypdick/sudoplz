"""Askpass helper invoked by ``sudo -A``.

Prints the stored sudo password to stdout after passing security checks.
Never write anything else to stdout — sudo treats stray output as the
password.
"""

from __future__ import annotations

import functools
import getpass
import json
import os
import socket
import subprocess
import sys
import syslog
import warnings
from datetime import datetime, timedelta
from pathlib import Path

import keyring

from sudoplz import credentials
from sudoplz.core import (
    AUDIT_LOG_FILE,
    RATE_LIMIT_FILE,
    Config,
    atomic_write,
    file_lock,
    load_config,
    parent_command,
    process_name,
    verify_totp,
)


def repair_environment() -> None:
    """Restore env vars that ``sudo -A`` strips but our subprocesses need."""
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


def prompt_totp(prompt: credentials.Prompt, user: str, host: str, command: str) -> bool:
    """Headless approval: verify a TOTP code from ``$TOTP`` or /dev/tty."""
    secret = credentials.load_totp_secret(prompt)
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
    try:
        with file_lock(RATE_LIMIT_FILE):
            return _update_rate_limit(max_attempts, lockout_minutes)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError):
        syslog.syslog(syslog.LOG_ERR, "Rate limit state invalid or unwritable; failing closed")
        sys.stderr.write(f"Error: cannot update rate limit at {RATE_LIMIT_FILE}.\n")
        return False


def _update_rate_limit(max_attempts: int, lockout_minutes: int) -> bool:
    try:
        data = json.loads(RATE_LIMIT_FILE.read_text())
    except FileNotFoundError:
        data = {"attempts": [], "lockout_until": None}
    if not isinstance(data, dict) or not isinstance(data.get("attempts"), list):
        raise ValueError("Invalid rate limit state")

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
        atomic_write(RATE_LIMIT_FILE, json.dumps(data).encode())
        return False

    data["attempts"].append(now.isoformat())
    atomic_write(RATE_LIMIT_FILE, json.dumps(data).encode())
    return True


def _path_is_allowed(cwd: str, allowed: list[str]) -> bool:
    for raw in allowed:
        p = os.path.normpath(raw)
        if cwd == p or cwd.startswith(p.rstrip(os.sep) + os.sep):
            return True
    return False


def check_security(config: Config, prompt: credentials.Prompt) -> bool:
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

    if config["require_user_confirmation"]:
        user = os.environ.get("USER", "unknown")
        host = socket.gethostname()
        command = parent_command(os.getppid())
        if "DISPLAY" in os.environ or sys.platform == "darwin":
            approved = show_dialog(user, host, command)
        else:
            approved = prompt_totp(prompt, user, host, command)
        if not approved:
            syslog.syslog(syslog.LOG_WARNING, "Sudo access denied by user")
            return False
        syslog.syslog(syslog.LOG_INFO, "Sudo access approved by user")

    return True


def prompt_passphrase(priv: Path) -> str | None:
    """Read a passphrase through a hidden GUI or terminal prompt."""
    if sys.platform == "darwin":
        escaped = str(priv).replace("\\", "\\\\").replace('"', '\\"')
        script = (
            f'return text returned of (display dialog "Enter passphrase for {escaped}:" '
            'default answer "" with hidden answer '
            'with title "SSH Key Passphrase Required" with icon caution)'
        )
        try:
            result = subprocess.run(
                ["osascript", "-e", script], capture_output=True, text=True, timeout=120
            )
            return result.stdout.removesuffix("\n") if result.returncode == 0 else None
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            syslog.syslog(syslog.LOG_WARNING, f"osascript passphrase prompt failed: {e}")
            return None

    if "DISPLAY" not in os.environ:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                return getpass.getpass(f"Enter passphrase for {priv}: ")
        except (OSError, EOFError, getpass.GetPassWarning):
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


def validate_script_integrity() -> bool:
    """Refuse to run if our own module file is world-writable.

    Group-write is tolerated because user-local installs under
    common umasks produce 664 files where the group is a single-member
    user group. World-write is the real threat — anyone on the box
    could rewrite the script to leak passwords.
    """
    this_file = Path(__file__).resolve()
    stats = this_file.stat()
    if stats.st_mode & 0o002:
        syslog.syslog(syslog.LOG_CRIT, f"Askpass module is world-writable: {oct(stats.st_mode)}")
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

    try:
        config = load_config()
        prompt = functools.cache(prompt_passphrase)
        if not check_security(config, prompt):
            raise ValueError("Security check failed")
        password = credentials.load_password(config["expiration_hours"], prompt)
        if password is None:
            raise ValueError("No password stored; use 'sudoplz set'")
        ppid = os.getppid()
        write_audit_entry(ppid, process_name(ppid), parent_command(ppid))
        print(password)
    except (OSError, ValueError, subprocess.SubprocessError, keyring.errors.KeyringError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
