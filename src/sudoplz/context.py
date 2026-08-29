"""Load agent-supplied sudo request context (explain + full command body)."""

from __future__ import annotations

import json
import os
import syslog
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

PENDING_MAX_AGE = timedelta(minutes=5)


def pending_path() -> Path:
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime:
        return Path(runtime) / "sudoplz" / "pending.json"
    return Path.home() / ".config" / "sudoplz" / "pending.json"


def _read_body_file(path_str: str) -> str | None:
    path = Path(path_str)
    try:
        if not path.is_file():
            syslog.syslog(syslog.LOG_WARNING, f"SUDOPLZ_SCRIPT path not a file: {path}")
            return None
        # Refuse world-writable body files.
        if path.stat().st_mode & 0o002:
            syslog.syslog(syslog.LOG_WARNING, f"Refusing world-writable SUDOPLZ_SCRIPT: {path}")
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        syslog.syslog(syslog.LOG_WARNING, f"Could not read SUDOPLZ_SCRIPT {path}: {e}")
        return None


def _load_pending() -> dict[str, Any] | None:
    path = pending_path()
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        syslog.syslog(syslog.LOG_WARNING, f"Ignoring unreadable pending request {path}: {e}")
        return None

    created_raw = data.get("created_at")
    if created_raw:
        try:
            created = datetime.fromisoformat(created_raw)
            if datetime.now() - created > PENDING_MAX_AGE:
                syslog.syslog(syslog.LOG_INFO, f"Pending request expired: {path}")
                return None
        except ValueError:
            pass
    return data if isinstance(data, dict) else None


def clear_pending() -> None:
    path = pending_path()
    try:
        if path.exists():
            path.unlink()
    except OSError as e:
        syslog.syslog(syslog.LOG_WARNING, f"Could not clear pending request {path}: {e}")


def load_request_context(fallback_command: str) -> tuple[str | None, str]:
    """Return (explain, body).

    Priority for body: SUDOPLZ_SCRIPT_BODY → SUDOPLZ_SCRIPT file → pending.json → fallback.
    Priority for explain: SUDOPLZ_EXPLAIN → pending.json → None.
    """
    pending = _load_pending()

    explain = os.environ.get("SUDOPLZ_EXPLAIN")
    if explain is None and pending:
        raw = pending.get("explain")
        explain = raw if isinstance(raw, str) else None

    body: str | None = os.environ.get("SUDOPLZ_SCRIPT_BODY")
    if not body:
        script_path = os.environ.get("SUDOPLZ_SCRIPT")
        if script_path:
            body = _read_body_file(script_path)
    if not body and pending:
        raw_body = pending.get("body")
        if isinstance(raw_body, str) and raw_body.strip():
            body = raw_body

    if not body:
        body = fallback_command

    return (explain, body)
