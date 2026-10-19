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

from sudoplz.context import clear_pending, load_request_context
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
    pam_faillock_lockout,
    parent_command,
    process_name,
    verify_totp,
)
from sudoplz.dialog import (
    has_display,
    prompt_ssh_passphrase,
    prompt_sudo_password,
    show_dialog,
    show_faillock_dialog,
)
from sudoplz.manager import store_password

try:
    import keyring

    HAS_KEYRING = True
except ImportError:
    HAS_KEYRING = False


def repair_environment() -> None:
    """Restore env vars that ``sudo -A`` strips but our subprocesses need."""
    if sys.platform == "linux":
        uid = os.getuid()
        runtime = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{uid}")
        if not os.environ.get("XDG_RUNTIME_DIR") and os.path.isdir(runtime):
            os.environ["XDG_RUNTIME_DIR"] = runtime

        if not os.environ.get("SSH_AUTH_SOCK"):
            for sock in (
                f"{runtime}/ssh-agent.socket",
                f"{runtime}/openssh_agent",
                f"{runtime}/ssh-agent",
            ):
                if os.path.exists(sock):
                    os.environ["SSH_AUTH_SOCK"] = sock
                    break

        # Agent shells often lack DISPLAY/WAYLAND; Qt needs at least one.
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            if os.path.exists(f"{runtime}/wayland-0"):
                os.environ["WAYLAND_DISPLAY"] = "wayland-0"
            # Common Xwayland display on Plasma
            for display in (":1", ":0"):
                os.environ["DISPLAY"] = display
                break

    if sys.platform == "darwin":
        brew = "/opt/homebrew/bin"
        if os.path.isdir(brew) and brew not in os.environ.get("PATH", ""):
            os.environ["PATH"] = f"{brew}:{os.environ.get('PATH', '')}"


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

    user = os.environ.get("USER", "unknown")
    sudo_pid = os.getppid()
    lockout = pam_faillock_lockout(user)
    if lockout:
        syslog.syslog(syslog.LOG_WARNING, lockout.stderr_message)
        print(f"Error: {lockout.stderr_message}", file=sys.stderr)
        _notify_faillock_once(sudo_pid, lockout.user, lockout.remaining_minutes)
        return False

    # Expired ciphertext is removed; approval still proceeds so the user can
    # re-enter the password in the GUI instead of a hard security failure.
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

    if config["require_user_confirmation"]:
        host = socket.gethostname()
        command = parent_command(sudo_pid)
        explain, body, explicit_body = load_request_context(command)
        if not (explain or "").strip():
            syslog.syslog(
                syslog.LOG_WARNING,
                "Sudo access denied: missing SUDOPLZ_EXPLAIN (fail closed)",
            )
            clear_pending()
            return False
        if not explicit_body or not body.strip():
            syslog.syslog(
                syslog.LOG_WARNING,
                "Sudo access denied: missing SUDOPLZ_SCRIPT_BODY (fail closed)",
            )
            clear_pending()
            return False
        try:
            if has_display() or sys.platform == "darwin":
                approved = show_dialog(user, host, command, explain, body)
            else:
                approved = prompt_totp(identity, user, host, command) if identity else False
        finally:
            clear_pending()
        if not approved:
            syslog.syslog(syslog.LOG_WARNING, "Sudo access denied by user")
            return False
        syslog.syslog(syslog.LOG_INFO, "Sudo access approved by user")

    return True


def _notify_faillock_once(sudo_pid: int, user: str, remaining_minutes: int) -> None:
    """Show at most one lockout dialog for this sudo process."""
    runtime = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
    stamp = runtime / "sudoplz" / f"faillock-notified-{sudo_pid}"
    try:
        stamp.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if stamp.exists():
            return
        stamp.write_text(f"{time.time()}\n", encoding="utf-8")
        stamp.chmod(0o600)
    except OSError as e:
        syslog.syslog(syslog.LOG_WARNING, f"faillock notify stamp failed: {e}")

    if has_display() or sys.platform == "darwin":
        show_faillock_dialog(user, remaining_minutes)


def ensure_ssh_key_loaded(priv: Path) -> bool:
    """Load ``priv`` into ssh-agent via PySide6 passphrase prompt if needed."""
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

    passphrase = prompt_ssh_passphrase(priv)
    if passphrase is None:
        return False

    # Feed passphrase on stdin; never let ssh-add spawn SSH_ASKPASS.
    env = os.environ.copy()
    env.pop("SSH_ASKPASS", None)
    env["SSH_ASKPASS_REQUIRE"] = "never"
    add_result = subprocess.run(
        ["ssh-add", str(priv)],
        input=passphrase.encode(),
        capture_output=True,
        env=env,
    )
    if add_result.returncode != 0:
        syslog.syslog(
            syslog.LOG_WARNING,
            f"ssh-add failed: {add_result.stderr.decode(errors='replace').strip()}",
        )
        return False
    return True


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


def _served_stamp(sudo_pid: int) -> Path:
    runtime = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
    return runtime / "sudoplz" / f"served-{sudo_pid}"


def _askpass_already_served(sudo_pid: int) -> bool:
    return _served_stamp(sudo_pid).exists()


def _mark_askpass_served(sudo_pid: int) -> None:
    """One askpass cycle per sudo process — further sudo retries get no UI."""
    stamp = _served_stamp(sudo_pid)
    try:
        stamp.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        stamp.write_text(f"{time.time()}\n", encoding="utf-8")
        stamp.chmod(0o600)
    except OSError as e:
        syslog.syslog(syslog.LOG_WARNING, f"Could not write askpass served stamp: {e}")


def _emit_password(sudo_pid: int, password: str, via: str) -> None:
    _mark_askpass_served(sudo_pid)
    print(password, flush=True)
    syslog.syslog(syslog.LOG_INFO, via)


def main() -> None:
    syslog.openlog("sudoplz")
    repair_environment()

    if not validate_script_integrity():
        print("Error: environment validation failed", file=sys.stderr)
        sys.exit(1)

    sudo_pid = os.getppid()
    if _askpass_already_served(sudo_pid):
        # sudo re-invoked askpass after a failed password — do not prompt again.
        print("Error: askpass already used for this sudo; giving up", file=sys.stderr)
        syslog.syslog(
            syslog.LOG_WARNING,
            f"Askpass refuse re-entry for sudo pid {sudo_pid}",
        )
        sys.exit(1)

    config = load_config()
    priv, _, key_type = find_ssh_key()

    if not check_security(config, priv):
        _mark_askpass_served(sudo_pid)
        print("Error: security check failed", file=sys.stderr)
        syslog.syslog(syslog.LOG_ERR, "Security check failed")
        sys.exit(1)

    write_audit_entry(sudo_pid, process_name(sudo_pid), parent_command(sudo_pid))

    # Priority 1: age-encrypted file (Ed25519).
    # After Allow: unlock key via PySide6 if needed, then decrypt.
    if AGE_ENCRYPTED_FILE.exists() and priv and has_age():
        ensure_ssh_key_loaded(priv)
        password = age_decrypt(AGE_ENCRYPTED_FILE.read_bytes(), priv)
        if password:
            _emit_password(
                sudo_pid, password, f"Password retrieved via age ({key_type} key)"
            )
            return

    # Priority 2: OpenSSL-encrypted file (RSA / ECDSA / DSA).
    if SSH_ENCRYPTED_FILE.exists() and priv and key_type and key_type != "Ed25519":
        password = decrypt_with_openssl(SSH_ENCRYPTED_FILE, priv, key_type)
        if password:
            _emit_password(
                sudo_pid, password, f"Password retrieved via SSH ({key_type} key)"
            )
            return

    # Priority 3: system keyring.
    if HAS_KEYRING:
        try:
            password = keyring.get_password(SERVICE_NAME, USERNAME)
            if password:
                _emit_password(sudo_pid, password, "Password retrieved via keyring")
                return
        except Exception as e:
            syslog.syslog(syslog.LOG_WARNING, f"Keyring lookup failed: {e}")

    # Priority 4: GUI re-prompt after Allow (missing / expired / unreadable store).
    # Enter+confirm lives in this single askpass cycle — not a sudo retry.
    reason = (
        "No encrypted sudo password is available (missing or expired). "
        "Enter it to save with your SSH key and continue this command."
    )
    if has_display() or sys.platform == "darwin":
        password = prompt_sudo_password(reason)
        if password:
            priv, pub, key_type = find_ssh_key()
            if store_password(password, priv, pub, key_type, quiet=True):
                _emit_password(
                    sudo_pid,
                    password,
                    "Password stored via askpass re-prompt and returned",
                )
                return
            _mark_askpass_served(sudo_pid)
            print("Error: could not store sudo password", file=sys.stderr)
            syslog.syslog(syslog.LOG_ERR, "Askpass re-prompt store_password failed")
            sys.exit(1)
        _mark_askpass_served(sudo_pid)
        print("Error: sudo password entry cancelled", file=sys.stderr)
        syslog.syslog(syslog.LOG_WARNING, "Askpass re-prompt cancelled")
        sys.exit(1)

    _mark_askpass_served(sudo_pid)
    print("Error: no password found in secure storage", file=sys.stderr)
    print("Use 'sudoplz set' to store the password securely", file=sys.stderr)
    syslog.syslog(syslog.LOG_ERR, "No password found in secure storage")
    sys.exit(1)


if __name__ == "__main__":
    main()
