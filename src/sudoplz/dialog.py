"""Approval / password dialogs for ``sudo -A`` (Linux: PySide6; macOS: osascript)."""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import syslog
from collections.abc import Iterator
from pathlib import Path

DIALOG_TIMEOUT_MS = 60_000


def _escape_osascript(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


@contextlib.contextmanager
def _silence_stdio() -> Iterator[None]:
    """Redirect fd 1/2 to /dev/null — sudo treats all askpass stdout as the password."""
    saved_out = os.dup(1)
    saved_err = os.dup(2)
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
        os.close(devnull)
        yield
    finally:
        os.dup2(saved_out, 1)
        os.dup2(saved_err, 2)
        os.close(saved_out)
        os.close(saved_err)


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

    with _silence_stdio():
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


def has_display() -> bool:
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def show_faillock_dialog(user: str, remaining_minutes: int) -> None:
    """Explain pam_faillock lockout; offer Polkit unlock or dismiss.

    Never writes to stdout (sudo treats askpass stdout as the password).
    """
    from sudoplz.core import reset_faillock_via_polkit

    title = "Sudo temporarily locked"
    if sys.platform == "darwin":
        message = (
            f"Linux pam_faillock locked account '{user}' after failed sudo attempts "
            f"(~{remaining_minutes} min left). Even the correct password is rejected "
            "until the lock clears. Dismiss and wait, then retry."
        )
        escaped = _escape_osascript(message)
        script = (
            'tell application "System Events"\nactivate\n'
            f'display dialog "{escaped}" with title "{_escape_osascript(title)}" '
            'buttons {"Dismiss"} default button "Dismiss" with icon caution '
            "giving up after 60\nend tell"
        )
        try:
            subprocess.run(["osascript", "-e", script], capture_output=True, timeout=70)
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            syslog.syslog(syslog.LOG_WARNING, f"osascript faillock dialog failed: {e}")
        return

    if not has_display():
        return

    try:
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import (
            QApplication,
            QDialog,
            QDialogButtonBox,
            QHBoxLayout,
            QLabel,
            QVBoxLayout,
        )

        os.environ.setdefault("QT_LOGGING_TO_CONSOLE", "0")
        with _silence_stdio():
            app = QApplication.instance()
            if app is None:
                app = QApplication(sys.argv[:1])

            dialog = QDialog()
            dialog.setWindowTitle(title)
            dialog.setWindowModality(Qt.WindowModality.ApplicationModal)

            root = QVBoxLayout(dialog)
            root.setContentsMargins(10, 8, 10, 8)
            root.setSpacing(6)

            header = QLabel(f"<b>{title}</b>")
            root.addWidget(header)

            # ``user`` is the live account name (never hardcoded).
            body = QLabel(
                f"PAM locked <b>{user}</b> after failed sudo attempts "
                f"(~{remaining_minutes} min left). Correct password is rejected "
                "until unlock.<br><br>"
                "<b>Unlock with Polkit…</b> runs "
                f"<code>faillock --user {user} --reset</code> as root "
                "(separate password prompt).<br><br>"
                "<b>Dismiss</b> waits out the timer."
            )
            body.setWordWrap(True)
            body.setTextFormat(Qt.TextFormat.RichText)
            body.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            root.addWidget(body)

            status = QLabel("")
            status.setWordWrap(True)
            status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            status.setStyleSheet("color: #e67e22;")
            status.hide()
            root.addWidget(status)

            buttons = QDialogButtonBox()
            unlock_btn = buttons.addButton(
                "Unlock with Polkit…", QDialogButtonBox.ButtonRole.ActionRole
            )
            dismiss_btn = buttons.addButton(
                "Dismiss", QDialogButtonBox.ButtonRole.RejectRole
            )
            unlock_btn.setDefault(True)
            unlock_btn.setAutoDefault(True)
            dismiss_btn.setAutoDefault(False)
            dismiss_btn.setDefault(False)

            dialog_width = 440

            def refit() -> None:
                """Grow/shrink cleanly after status appears (avoid fixed-height overlap)."""
                dialog.setMinimumSize(dialog_width, 0)
                dialog.setMaximumSize(16777215, 16777215)
                inner = dialog_width - root.contentsMargins().left() - root.contentsMargins().right()
                body.setFixedWidth(inner)
                status.setFixedWidth(inner)
                app.processEvents()
                # heightForWidth needs the width constraint above
                body_h = body.heightForWidth(inner)
                status_h = status.heightForWidth(inner) if status.isVisible() else 0
                if body_h < 0:
                    body_h = body.sizeHint().height()
                if status_h < 0:
                    status_h = status.sizeHint().height() if status.isVisible() else 0
                chrome = (
                    header.sizeHint().height()
                    + buttons.sizeHint().height()
                    + root.contentsMargins().top()
                    + root.contentsMargins().bottom()
                    + root.spacing() * (3 if status.isVisible() else 2)
                    + 8
                )
                total_h = chrome + body_h + status_h
                dialog.setFixedSize(dialog_width, total_h)

            def on_unlock() -> None:
                status.setText(
                    "Waiting on Polkit… use the Authentication Required window."
                )
                status.show()
                refit()
                unlock_btn.setEnabled(False)
                dismiss_btn.setEnabled(False)
                app.processEvents()
                ok, detail = reset_faillock_via_polkit(user)
                dismiss_btn.setEnabled(True)
                if ok:
                    status.setText("Unlocked — close and retry sudo.")
                    unlock_btn.setEnabled(False)
                    dismiss_btn.setText("Close")
                    dismiss_btn.setDefault(True)
                    syslog.syslog(
                        syslog.LOG_INFO, f"faillock reset via polkit for {user}"
                    )
                else:
                    # Keep detail short so wrap stays readable
                    short = (detail or "not authorized").strip()
                    if len(short) > 160:
                        short = short[:157] + "…"
                    status.setText(f"Unlock failed: {short}\nDismiss or try again.")
                    unlock_btn.setEnabled(True)
                    syslog.syslog(
                        syslog.LOG_WARNING,
                        f"faillock polkit reset failed for {user}: {detail}",
                    )
                refit()

            unlock_btn.clicked.connect(on_unlock)
            dismiss_btn.clicked.connect(dialog.reject)

            btn_row = QHBoxLayout()
            btn_row.setContentsMargins(0, 2, 0, 0)
            btn_row.addStretch(1)
            btn_row.addWidget(buttons)
            root.addLayout(btn_row)

            # No auto-timeout — user may spend time in the Polkit dialog.
            refit()
            unlock_btn.setFocus()
            dialog.show()
            dialog.raise_()
            dialog.activateWindow()
            app.exec()
    except Exception as e:
        syslog.syslog(syslog.LOG_WARNING, f"PySide6 faillock dialog failed: {e}")


def show_dialog(
    user: str,
    host: str,
    command: str,
    explain: str | None = None,
    body: str | None = None,
) -> bool:
    """Prompt the user for approval. Return True on Allow."""
    explain_text = (explain or "").strip()
    if not explain_text:
        syslog.syslog(
            syslog.LOG_WARNING,
            "Sudo access denied: missing SUDOPLZ_EXPLAIN (fail closed)",
        )
        return False

    body_text = (body or "").strip() or command or "(no command body provided)"

    if sys.platform == "darwin":
        return show_osascript_dialog(user, host, command, explain_text, body_text)

    if not has_display():
        return False

    try:
        return show_qt_dialog(user, host, command, explain_text, body_text)
    except Exception as e:
        syslog.syslog(syslog.LOG_ERR, f"PySide6 approval dialog failed: {e}")
        return False


def _show_osascript_password(reason: str) -> str | None:
    message = _escape_osascript(
        f"{reason}\n\nEnter your sudo password (will be saved encrypted):"
    )
    script = (
        'tell application "System Events"\nactivate\n'
        f'display dialog "{message}" '
        'default answer "" with hidden answer '
        'with title "Sudo Password Required" '
        'buttons {"Cancel", "Save"} default button "Save" '
        "with icon caution giving up after 60\nend tell"
    )
    try:
        result = subprocess.run(
            ["osascript", "-e", script], capture_output=True, text=True, timeout=70
        )
        if result.returncode != 0:
            return None
        for part in result.stdout.split(", "):
            if part.startswith("text returned:"):
                password = part.removeprefix("text returned:").rstrip("\n")
                return password or None
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        syslog.syslog(syslog.LOG_WARNING, f"osascript password prompt failed: {e}")
        return None


def _show_qt_password(reason: str) -> str | None:
    from PySide6.QtCore import Qt, QTimer
    from PySide6.QtWidgets import (
        QApplication,
        QDialog,
        QDialogButtonBox,
        QFormLayout,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QVBoxLayout,
    )

    os.environ.setdefault("QT_LOGGING_TO_CONSOLE", "0")

    with _silence_stdio():
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv[:1])

        dialog = QDialog()
        dialog.setWindowTitle("Sudo Password Required")
        dialog.setMinimumWidth(420)
        dialog.setWindowModality(Qt.WindowModality.ApplicationModal)

        root = QVBoxLayout(dialog)
        header = QLabel("<b>Sudo password not stored</b>")
        root.addWidget(header)
        reason_label = QLabel(reason)
        reason_label.setWordWrap(True)
        root.addWidget(reason_label)

        form = QFormLayout()
        password_edit = QLineEdit()
        password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        confirm_edit = QLineEdit()
        confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Password:", password_edit)
        form.addRow("Confirm:", confirm_edit)
        root.addLayout(form)

        mismatch = QLabel("")
        mismatch.setStyleSheet("color: #c0392b;")
        root.addWidget(mismatch)

        buttons = QDialogButtonBox()
        cancel_btn = buttons.addButton("Cancel", QDialogButtonBox.ButtonRole.RejectRole)
        save_btn = buttons.addButton("Save", QDialogButtonBox.ButtonRole.AcceptRole)
        # Enter activates the default button — must be Save, not Cancel.
        cancel_btn.setAutoDefault(False)
        cancel_btn.setDefault(False)
        save_btn.setAutoDefault(True)
        save_btn.setDefault(True)
        buttons.rejected.connect(dialog.reject)

        result_password: dict[str, str | None] = {"value": None}

        def try_accept() -> None:
            password = password_edit.text()
            confirm = confirm_edit.text()
            if not password:
                mismatch.setText("Password cannot be empty.")
                return
            if password != confirm:
                mismatch.setText("Passwords do not match.")
                return
            result_password["value"] = password
            dialog.accept()

        buttons.accepted.connect(try_accept)
        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        btn_row.addWidget(buttons)
        root.addLayout(btn_row)

        timer = QTimer(dialog)
        timer.setSingleShot(True)
        timer.timeout.connect(dialog.reject)
        timer.start(DIALOG_TIMEOUT_MS)

        password_edit.setFocus()
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()
        app.exec()
        return result_password["value"]


def _show_qt_passphrase(key_path: Path) -> str | None:
    """Same PySide6 chrome as the sudo-password dialog — single passphrase field."""
    from PySide6.QtCore import Qt, QTimer
    from PySide6.QtWidgets import (
        QApplication,
        QDialog,
        QDialogButtonBox,
        QFormLayout,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QVBoxLayout,
    )

    os.environ.setdefault("QT_LOGGING_TO_CONSOLE", "0")

    with _silence_stdio():
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv[:1])

        dialog = QDialog()
        dialog.setWindowTitle("SSH Key Passphrase Required")
        dialog.setMinimumWidth(420)
        dialog.setWindowModality(Qt.WindowModality.ApplicationModal)

        root = QVBoxLayout(dialog)
        header = QLabel("<b>Unlock SSH key</b>")
        root.addWidget(header)
        reason_label = QLabel(
            f"Enter the passphrase for <code>{key_path}</code> so the stored "
            "sudo password can be decrypted."
        )
        reason_label.setWordWrap(True)
        reason_label.setTextFormat(Qt.TextFormat.RichText)
        root.addWidget(reason_label)

        form = QFormLayout()
        passphrase_edit = QLineEdit()
        passphrase_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Passphrase:", passphrase_edit)
        root.addLayout(form)

        error = QLabel("")
        error.setStyleSheet("color: #c0392b;")
        root.addWidget(error)

        buttons = QDialogButtonBox()
        cancel_btn = buttons.addButton("Cancel", QDialogButtonBox.ButtonRole.RejectRole)
        unlock_btn = buttons.addButton("Unlock", QDialogButtonBox.ButtonRole.AcceptRole)
        cancel_btn.setAutoDefault(False)
        cancel_btn.setDefault(False)
        unlock_btn.setAutoDefault(True)
        unlock_btn.setDefault(True)
        buttons.rejected.connect(dialog.reject)

        result: dict[str, str | None] = {"value": None}

        def try_accept() -> None:
            text = passphrase_edit.text()
            if not text:
                error.setText("Passphrase cannot be empty.")
                return
            result["value"] = text
            dialog.accept()

        buttons.accepted.connect(try_accept)
        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        btn_row.addWidget(buttons)
        root.addLayout(btn_row)

        timer = QTimer(dialog)
        timer.setSingleShot(True)
        timer.timeout.connect(dialog.reject)
        timer.start(DIALOG_TIMEOUT_MS)

        passphrase_edit.setFocus()
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()
        app.exec()
        return result["value"]


def _show_osascript_passphrase(key_path: Path) -> str | None:
    message = _escape_osascript(
        f"Enter passphrase for {key_path} to decrypt the stored sudo password:"
    )
    script = (
        'tell application "System Events"\nactivate\n'
        f'display dialog "{message}" '
        'default answer "" with hidden answer '
        'with title "SSH Key Passphrase Required" '
        'buttons {"Cancel", "Unlock"} default button "Unlock" '
        "with icon caution giving up after 60\nend tell"
    )
    try:
        result = subprocess.run(
            ["osascript", "-e", script], capture_output=True, text=True, timeout=70
        )
        if result.returncode != 0:
            return None
        for part in result.stdout.split(", "):
            if part.startswith("text returned:"):
                text = part.removeprefix("text returned:").rstrip("\n")
                return text or None
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        syslog.syslog(syslog.LOG_WARNING, f"osascript passphrase prompt failed: {e}")
        return None


def prompt_ssh_passphrase(key_path: str | Path) -> str | None:
    """Ask for an SSH private-key passphrase (PySide6 on Linux)."""
    path = Path(key_path)

    if sys.platform == "darwin":
        return _show_osascript_passphrase(path)

    if not has_display():
        return None

    try:
        return _show_qt_passphrase(path)
    except Exception as e:
        syslog.syslog(syslog.LOG_ERR, f"PySide6 passphrase dialog failed: {e}")
        return None


def prompt_sudo_password(reason: str | None = None) -> str | None:
    """Ask for a sudo password (enter + confirm). Return None on cancel/timeout."""
    reason_text = (reason or "").strip() or (
        "No encrypted sudo password is available. Enter it to save and continue this command."
    )

    if sys.platform == "darwin":
        return _show_osascript_password(reason_text)

    if not has_display():
        return None

    try:
        return _show_qt_password(reason_text)
    except Exception as e:
        syslog.syslog(syslog.LOG_ERR, f"PySide6 password dialog failed: {e}")
        return None
