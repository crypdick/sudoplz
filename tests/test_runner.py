import contextlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sudoplz import manager


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.home = Path(self.directory.name)
        self.sudo = self.home / "sudo"
        self.sudo.write_text(
            f"#!{sys.executable}\n"
            "import json, os, signal, sys\n"
            "print(json.dumps({'args': sys.argv[1:], 'pid': os.getpid(), "
            "'askpass': os.environ.get('SUDO_ASKPASS'), 'input': sys.stdin.read()}), "
            "flush=True)\n"
            "print('fixture stderr', file=sys.stderr)\n"
            "if os.environ.get('FIXTURE_SIGNAL'): os.kill(os.getpid(), signal.SIGTERM)\n"
            "sys.exit(23)\n"
        )
        self.sudo.chmod(0o700)

    def run_cli(self, *args, extra_env=None):
        process = subprocess.Popen(
            [sys.executable, "-m", "sudoplz.manager", *args],
            env=os.environ | {
                "HOME": str(self.home),
                "PATH": str(self.home),
                "SUDO_ASKPASS": "/wrong/askpass",
            } | (extra_env or {}),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = process.communicate("fixture input\n", timeout=10)
        return process, stdout, stderr

    def test_delegates_arguments_environment_streams_and_exit_status(self):
        process, stdout, stderr = self.run_cli("printf", "%s", "two words", "$(literal)")
        self.assertEqual(process.returncode, 23, stderr)
        report = json.loads(stdout)
        self.assertEqual(report["args"], ["-k", "-A", "printf", "%s", "two words", "$(literal)"])
        self.assertEqual(report["pid"], process.pid)
        self.assertEqual(report["input"], "fixture input\n")
        self.assertEqual(report["askpass"], str(Path(sys.executable).with_name("askpass")))
        self.assertEqual(stderr, "fixture stderr\n")

    def test_forwards_sudo_options_and_disambiguates_management_names(self):
        for args, expected in (
            (("-u", "nobody", "id"), ["-u", "nobody", "id"]),
            (("--", "test", "-f", "/fixture"), ["--", "test", "-f", "/fixture"]),
            (("clear",), ["clear"]),
        ):
            with self.subTest(args=args):
                process, stdout, stderr = self.run_cli(*args)
                self.assertEqual(process.returncode, 23, stderr)
                self.assertEqual(json.loads(stdout)["args"], ["-k", "-A", *expected])

    def test_preserves_signal_termination(self):
        process, _, _ = self.run_cli("id", extra_env={"FIXTURE_SIGNAL": "1"})
        self.assertEqual(process.returncode, -signal.SIGTERM)

    def test_missing_sudo_reports_error(self):
        self.sudo.unlink()
        process, stdout, stderr = self.run_cli("id")
        self.assertEqual(process.returncode, 1)
        self.assertEqual(stdout, "")
        self.assertIn("Error:", stderr)
        self.assertIn("sudo", stderr)

    def test_missing_askpass_fails_before_running_sudo(self):
        errors = io.StringIO()
        with (
            patch.object(sys, "argv", ["sudoplz", "id"]),
            patch.object(manager.shutil, "which", return_value=None),
            patch.object(manager.os, "execvpe") as execute,
            contextlib.redirect_stderr(errors),
            self.assertRaises(SystemExit) as result,
        ):
            manager.main()
        self.assertEqual(result.exception.code, 1)
        self.assertIn("'askpass' not found", errors.getvalue())
        execute.assert_not_called()

    def test_help_and_empty_separator_do_not_run_sudo(self):
        for args, status in ((("--help",), 0), ((), 2), (("--",), 2)):
            with self.subTest(args=args):
                process, stdout, stderr = self.run_cli(*args)
                self.assertEqual(process.returncode, status, stderr)
                self.assertNotIn("fixture stderr", stderr)
                self.assertIn("usage:", stdout + stderr)
