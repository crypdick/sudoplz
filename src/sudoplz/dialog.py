"""Approval dialog for ``sudo -A`` (Linux: PySide6; macOS: osascript)."""

from __future__ import annotations

import os
import subprocess
import sys
import syslog
DIALOG_TIMEOUT_MS = 60_000


def _escape_osascript(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def show_osascript_dialog(user: str, host: str, command: str, explain: str, body: str) -> bool:
    """macOS fallback — truncated text only (no scrollable panel)."""
    del command  # parent argv is noisy; show agent body only
    body_preview = body if len(body) <= 800 else body[:800] + "\n…(truncated)"
    message = (
        "Administrator privileges requested\n\n"
        f"User: {user}\nHost: {host}\n\n"
        f"Explanation:\n{explain}\n\n"
        f"Command:\n{body_preview}\n\n"
        "Do you want to allow this?"
    )
    escaped = _escape_osascript(message)
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


def show_qt_dialog(user: str, host: str, command: str, explain: str, body: str) -> bool:
    """PySide6 dialog: explanation + one scrollable command panel.

    stdout/stderr are redirected for the duration of the dialog — sudo treats
    *all* askpass stdout as the password, so Qt must never write there.
    """
    del command  # parent argv (Cursor wrapper) is huge and unhelpful in the UI
    from PySide6.QtCore import Qt, QTimer
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import (
        QApplication,
        QDialog,
        QDialogButtonBox,
        QFormLayout,
        QHBoxLayout,
        QLabel,
        QPlainTextEdit,
        QVBoxLayout,
        QWidget,
    )

    os.environ.setdefault("QT_LOGGING_TO_CONSOLE", "0")

    saved_out = os.dup(1)
    saved_err = os.dup(2)
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
        os.close(devnull)

        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv[:1])

        dialog = QDialog()
        dialog.setWindowTitle("Sudo Authentication Required")
        dialog.setMinimumSize(560, 420)
        dialog.resize(640, 480)
        dialog.setWindowModality(Qt.WindowModality.ApplicationModal)

        root = QVBoxLayout(dialog)

        header = QLabel("<b>Administrator privileges requested</b>")
        root.addWidget(header)

        meta = QWidget()
        form = QFormLayout(meta)
        form.setContentsMargins(0, 0, 0, 0)
        form.addRow("User:", QLabel(user))
        form.addRow("Host:", QLabel(host))
        root.addWidget(meta)

        root.addWidget(QLabel("<b>Explanation</b>"))
        explain_label = QLabel(explain)
        explain_label.setWordWrap(True)
        explain_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        root.addWidget(explain_label)

        root.addWidget(QLabel("<b>Command</b>"))
        body_edit = QPlainTextEdit()
        body_edit.setReadOnly(True)
        body_edit.setPlainText(body)
        mono = QFont("monospace")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        body_edit.setFont(mono)
        root.addWidget(body_edit, stretch=1)

        prompt = QLabel("Do you want to allow this?")
        root.addWidget(prompt)

        buttons = QDialogButtonBox()
        deny_btn = buttons.addButton("Deny", QDialogButtonBox.ButtonRole.RejectRole)
        allow_btn = buttons.addButton("Allow", QDialogButtonBox.ButtonRole.AcceptRole)
        deny_btn.setDefault(True)
        deny_btn.setAutoDefault(True)
        allow_btn.setDefault(False)
        allow_btn.setAutoDefault(False)
        buttons.rejected.connect(dialog.reject)
        buttons.accepted.connect(dialog.accept)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        btn_row.addWidget(buttons)
        root.addLayout(btn_row)

        approved = {"value": False}

        def on_finished(result: int) -> None:
            approved["value"] = result == QDialog.DialogCode.Accepted

        dialog.finished.connect(on_finished)

        timer = QTimer(dialog)
        timer.setSingleShot(True)
        timer.timeout.connect(dialog.reject)
        timer.start(DIALOG_TIMEOUT_MS)

        dialog.show()
        dialog.raise_()
        dialog.activateWindow()
        app.exec()
        return approved["value"]
    finally:
        os.dup2(saved_out, 1)
        os.dup2(saved_err, 2)
        os.close(saved_out)
        os.close(saved_err)


def show_zenity_fallback(user: str, host: str, command: str, explain: str, body: str) -> bool:
    """Last-resort zenity if PySide6 is unavailable."""
    del command
    body_preview = body if len(body) <= 1500 else body[:1500] + "\n…(truncated)"
    message = (
        "Administrator privileges requested\n\n"
        f"User: {user}\nHost: {host}\n\n"
        f"Explanation:\n{explain}\n\n"
        f"Command:\n{body_preview}\n\n"
        "Do you want to allow this?"
    )
    try:
        result = subprocess.run(
            [
                "zenity",
                "--question",
                "--title=Sudo Authentication Required",
                f"--text={message}",
                "--width=560",
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
            "zenity not found and PySide6 unavailable",
        )
        return False
    except subprocess.TimeoutExpired:
        syslog.syslog(syslog.LOG_WARNING, "zenity dialog timed out")
        return False


def has_display() -> bool:
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def show_dialog(
    user: str,
    host: str,
    command: str,
    explain: str | None = None,
    body: str | None = None,
) -> bool:
    """Prompt the user for approval. Return True on Allow."""
    explain_text = (explain or "").strip() or "(no explanation provided)"
    body_text = (body or "").strip() or command or "(no command body provided)"

    if sys.platform == "darwin":
        return show_osascript_dialog(user, host, command, explain_text, body_text)

    if not has_display():
        return False

    try:
        return show_qt_dialog(user, host, command, explain_text, body_text)
    except Exception as e:
        syslog.syslog(syslog.LOG_WARNING, f"PySide6 dialog failed, falling back to zenity: {e}")
        return show_zenity_fallback(user, host, command, explain_text, body_text)
