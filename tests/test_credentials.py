import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import keyring
import keyring.core
from keyring.backend import KeyringBackend

from sudoplz import askpass, core, credentials, manager


class MemoryKeyring(KeyringBackend):
    priority = 1

    def __init__(self):
        self.passwords = {}

    def get_password(self, service, username):
        return self.passwords.get((service, username))

    def set_password(self, service, username, password):
        self.passwords[service, username] = password

    def delete_password(self, service, username):
        if (service, username) not in self.passwords:
            raise keyring.errors.PasswordDeleteError("Missing fixture credential")
        del self.passwords[service, username]


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.home = Path(self.directory.name)
        (self.home / ".ssh").mkdir()
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.keyring = MemoryKeyring()
        self.stack.enter_context(
            patch.object(keyring.core, "get_keyring", return_value=self.keyring)
        )
        for module, name, path in (
            (credentials, "HOME", self.home),
            (credentials, "PASSWORD_FILE", self.home / "credential.json"),
            (credentials, "AGE_ENCRYPTED_FILE", self.home / "legacy.age"),
            (credentials, "SSH_ENCRYPTED_FILE", self.home / "legacy.ssh"),
            (credentials, "TOTP_SECRET_FILE", self.home / "totp.enc"),
            (core, "CONFIG_FILE", self.home / "config.json"),
            (askpass, "RATE_LIMIT_FILE", self.home / "rate.json"),
            (askpass, "AUDIT_LOG_FILE", self.home / "audit.log"),
        ):
            self.stack.enter_context(patch.object(module, name, path))

    def key(self, kind="ed25519", passphrase="", pem=False):
        path = self.home / ".ssh" / f"id_{kind}"
        command = ["ssh-keygen", "-q", "-t", kind, "-N", passphrase, "-f", str(path)]
        if pem:
            command += ["-m", "PEM"]
        subprocess.run(command, check=True, capture_output=True)
        return path

    def no_prompt(self, identity):
        self.fail(f"Unexpected passphrase prompt for fixture {identity.name}")

    def test_age_preserves_password_spaces_for_ed25519_and_rsa(self):
        for kind in ("ed25519", "rsa"):
            with self.subTest(kind=kind):
                key = self.key(kind)
                credentials.store_password(" fixture ")
                self.assertEqual(credentials.load_password(168, self.no_prompt), " fixture ")
                self.assertEqual(credentials.PASSWORD_FILE.stat().st_mode & 0o777, 0o600)
                key.unlink()
                key.with_suffix(".pub").unlink()

    def test_protected_keys_unlock_without_terminal_or_agent(self):
        for kind, pem in (("ed25519", False), ("rsa", False), ("rsa", True)):
            with self.subTest(kind=kind, pem=pem):
                key = self.key(kind, "fixture-passphrase", pem)
                credentials.store_password(" fixture ")
                prompts = []

                def prompt(identity, prompts=prompts):
                    prompts.append(identity)
                    return "fixture-passphrase"

                with patch.dict(os.environ, {}, clear=True):
                    self.assertEqual(credentials.load_password(168, prompt), " fixture ")
                self.assertEqual(prompts, [key])
                key.unlink()
                key.with_suffix(".pub").unlink()

    def test_wrong_or_cancelled_passphrase_fails(self):
        self.key(passphrase="fixture-passphrase")
        credentials.store_password("fixture")
        for answer in ("wrong", None):
            with self.subTest(answer=answer), self.assertRaises(ValueError):
                credentials.load_password(168, lambda _, answer=answer: answer)

    def test_insecure_key_permissions_fail(self):
        key = self.key()
        credentials.store_password("fixture")
        key.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "permissions"):
            credentials.load_password(168, self.no_prompt)

    def test_adding_preferred_key_does_not_change_stored_identity(self):
        self.key("rsa")
        credentials.store_password("fixture")
        self.key("ed25519")
        self.assertEqual(credentials.load_password(168, self.no_prompt), "fixture")

    def test_unsupported_key_does_not_hide_supported_rsa(self):
        self.key("ecdsa")
        with self.assertRaisesRegex(ValueError, "unsupported"):
            credentials.store_password("fixture")
        self.key("rsa")
        credentials.store_password("fixture")
        self.assertEqual(credentials.load_password(168, self.no_prompt), "fixture")

    def test_legacy_openssh_rsa_round_trip(self):
        key = self.key("rsa")
        public_pem = subprocess.run(
            ["ssh-keygen", "-e", "-m", "PKCS8", "-f", str(key.with_suffix(".pub"))],
            check=True,
            capture_output=True,
        ).stdout
        public_file = self.home / "public.pem"
        public_file.write_bytes(public_pem)
        encrypted = subprocess.run(
            ["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", str(public_file)],
            input=b" fixture ",
            check=True,
            capture_output=True,
        ).stdout
        credentials.SSH_ENCRYPTED_FILE.write_bytes(encrypted)
        self.key("ed25519")
        self.assertEqual(credentials.load_password(168, self.no_prompt), " fixture ")

    def test_expired_secondary_file_does_not_block_current_credential(self):
        self.key()
        credentials.store_password("fixture")
        credentials.SSH_ENCRYPTED_FILE.write_bytes(b"old fixture")
        os.utime(credentials.SSH_ENCRYPTED_FILE, (0, 0))
        self.assertEqual(credentials.load_password(168, self.no_prompt), "fixture")

    def test_keyring_credentials_expire(self):
        with patch.object(credentials.time, "time", return_value=1):
            credentials.store_password("fixture")
        with patch.object(credentials.time, "time", return_value=3602):
            with self.assertRaisesRegex(ValueError, "expired"):
                credentials.load_password(1, self.no_prompt)
            self.assertEqual(credentials.load_password(0, self.no_prompt), "fixture")

    def test_legacy_keyring_age_is_not_invented(self):
        self.keyring.set_password(core.SERVICE_NAME, core.USERNAME, "fixture")
        with self.assertRaisesRegex(ValueError, "unknown age"):
            credentials.load_password(168, self.no_prompt)
        self.assertEqual(credentials.load_password(0, self.no_prompt), "fixture")

    def test_failed_decryption_cannot_fall_back_to_old_keyring(self):
        key = self.key()
        credentials.store_password("new fixture")
        self.keyring.set_password(core.SERVICE_NAME, core.USERNAME, "old fixture")
        key.unlink()
        self.key()
        with self.assertRaises(ValueError):
            credentials.load_password(168, self.no_prompt)

    def test_replacement_retires_previous_keyring_record(self):
        credentials.store_password("old fixture")
        self.key()
        credentials.store_password("new fixture")
        self.assertEqual(self.keyring.passwords, {})
        self.assertEqual(credentials.load_password(168, self.no_prompt), "new fixture")

    def test_failed_replacement_preserves_current_keyring_credential(self):
        credentials.store_password("old fixture")
        with (
            patch.object(core.os, "replace", side_effect=OSError("fixture failure")),
            self.assertRaises(OSError),
        ):
            credentials.store_password("new fixture")
        self.assertEqual(credentials.load_password(168, self.no_prompt), "old fixture")
        self.assertEqual(len(self.keyring.passwords), 1)

    def test_clear_prevents_legacy_fallback(self):
        credentials.store_password("fixture")
        credentials.clear_password()
        self.keyring.set_password(core.SERVICE_NAME, core.USERNAME, "old fixture")
        self.assertIsNone(credentials.load_password(0, self.no_prompt))

    def test_totp_secret_keeps_its_identity(self):
        self.key("rsa", passphrase="fixture-passphrase")
        credentials.save_totp_secret("JBSWY3DPEHPK3PXP")
        self.key("ed25519")
        self.assertEqual(
            credentials.load_totp_secret(lambda _: "fixture-passphrase"), "JBSWY3DPEHPK3PXP"
        )

    def test_askpass_and_manager_share_storage(self):
        self.key()
        output = io.StringIO()
        with (
            patch.object(manager.getpass, "getpass", return_value=" fixture "),
            patch.object(os.sys, "argv", ["sudoplz", "set"]),
            contextlib.redirect_stdout(output),
            self.assertRaises(SystemExit) as result,
        ):
            manager.main()
        self.assertEqual(result.exception.code, 0)
        policy = dict(
            core.DEFAULT_CONFIG,
            allowed_paths=[os.getcwd()],
            allowed_processes=[core.process_name(os.getppid())],
        )
        core.CONFIG_FILE.write_text(json.dumps(policy))
        output = io.StringIO()
        with (
            patch.dict(os.environ, {"TERM": "xterm", "DISPLAY": ":fixture"}),
            patch.object(askpass, "show_dialog", return_value=True),
            contextlib.redirect_stdout(output),
        ):
            askpass.main()
        self.assertEqual(output.getvalue(), " fixture \n")

    def test_invalid_policy_outputs_no_password(self):
        credentials.store_password("fixture")
        core.CONFIG_FILE.write_text('{"require_user_confirmation":0}')
        output, errors = io.StringIO(), io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
            self.assertRaises(SystemExit) as result,
        ):
            askpass.main()
        self.assertEqual(result.exception.code, 1)
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn("fixture", errors.getvalue())

    def test_headless_totp_and_password_prompt_once(self):
        self.key(passphrase="fixture-passphrase")
        secret = "JBSWY3DPEHPK3PXP"
        credentials.save_totp_secret(secret)
        credentials.store_password(" fixture ")
        core.CONFIG_FILE.write_text(
            json.dumps(
                dict(
                    core.DEFAULT_CONFIG,
                    allowed_paths=[os.getcwd()],
                    allowed_processes=[core.process_name(os.getppid())],
                )
            )
        )
        output, errors = io.StringIO(), io.StringIO()
        with (
            patch.dict(os.environ, {"TERM": "xterm", "TOTP": core.totp_code(secret)}, clear=True),
            patch.object(askpass.sys, "platform", "linux"),
            patch.object(askpass, "prompt_passphrase", return_value="fixture-passphrase") as prompt,
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            askpass.main()
        self.assertEqual(prompt.call_count, 1)
        self.assertEqual(output.getvalue(), " fixture \n")
        self.assertNotIn("fixture-passphrase", errors.getvalue())

    def test_denial_does_not_unlock_or_output_password(self):
        self.key(passphrase="fixture-passphrase")
        credentials.store_password("fixture")
        core.CONFIG_FILE.write_text(
            json.dumps(
                dict(
                    core.DEFAULT_CONFIG,
                    allowed_paths=[os.getcwd()],
                    allowed_processes=[core.process_name(os.getppid())],
                )
            )
        )
        output, errors = io.StringIO(), io.StringIO()
        with (
            patch.dict(os.environ, {"TERM": "xterm", "DISPLAY": ":fixture"}),
            patch.object(askpass, "show_dialog", return_value=False),
            patch.object(askpass, "prompt_passphrase", side_effect=self.no_prompt),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
            self.assertRaises(SystemExit) as result,
        ):
            askpass.main()
        self.assertEqual(result.exception.code, 1)
        self.assertEqual(output.getvalue(), "")

    def test_expired_credential_does_not_fall_back(self):
        self.key()
        with patch.object(credentials.time, "time", return_value=1):
            credentials.store_password("new fixture")
        self.keyring.set_password(core.SERVICE_NAME, core.USERNAME, "old fixture")
        with self.assertRaisesRegex(ValueError, "expired"):
            credentials.load_password(168, self.no_prompt)

    def test_legacy_age_import_preserves_age(self):
        key = self.key()
        ciphertext = subprocess.run(
            ["age", "-R", str(key.with_suffix(".pub")), "-a"],
            input=b" fixture ",
            check=True,
            capture_output=True,
        ).stdout
        credentials.AGE_ENCRYPTED_FILE.write_bytes(ciphertext)
        os.utime(credentials.AGE_ENCRYPTED_FILE, (1, 1))
        with self.assertRaisesRegex(ValueError, "expired"):
            credentials.load_password(168, self.no_prompt)
        self.assertEqual(credentials.load_password(0, self.no_prompt), " fixture ")

    def test_storage_and_clear_can_recover_corrupt_metadata(self):
        self.key()
        for command in (lambda: credentials.store_password("fixture"), credentials.clear_password):
            credentials.PASSWORD_FILE.write_bytes(b"{broken metadata")
            command()
        self.assertIsNone(credentials.load_password(0, self.no_prompt))

    def test_cli_processes_use_isolated_home(self):
        key = self.key(passphrase="fixture-passphrase")
        credentials.store_password(" fixture ")
        config_dir = self.home / ".config" / "sudoplz"
        config_dir.mkdir(parents=True)
        (config_dir / "credential.json").write_bytes(credentials.PASSWORD_FILE.read_bytes())
        (config_dir / "config.json").write_text(
            json.dumps(
                dict(
                    core.DEFAULT_CONFIG,
                    allowed_paths=[str(self.home)],
                    allowed_processes=[core.process_name(os.getpid())],
                    require_user_confirmation=False,
                )
            )
        )
        env = {
            "HOME": str(self.home),
            "PATH": os.environ["PATH"],
            "TERM": "xterm",
            "PYTHON_KEYRING_BACKEND": "keyring.backends.fail.Keyring",
        }

        def run(module, *args):
            return subprocess.run(
                [sys.executable, "-m", module, *args],
                cwd=self.home,
                env=env,
                start_new_session=True,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=10,
            )

        status = run("sudoplz.manager", "get")
        self.assertEqual(status.returncode, 0)
        self.assertIn("Password stored", status.stdout)
        denied = run("sudoplz.askpass")
        self.assertEqual(denied.returncode, 1)
        self.assertEqual(denied.stdout, "")
        self.assertIn("unlock cancelled", denied.stderr)
        self.assertNotIn("fixture-passphrase", denied.stderr)
        key.unlink()
        key.with_suffix(".pub").unlink()
        self.key()
        credentials.store_password(" fixture ")
        (config_dir / "credential.json").write_bytes(credentials.PASSWORD_FILE.read_bytes())
        approved = run("sudoplz.askpass")
        self.assertEqual(approved.returncode, 0, approved.stderr)
        self.assertEqual(approved.stdout, " fixture \n")
        cleared = run("sudoplz.manager", "clear")
        self.assertEqual(cleared.returncode, 0, cleared.stderr)
        self.assertEqual(run("sudoplz.manager", "get").returncode, 1)
