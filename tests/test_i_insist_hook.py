import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CHECKER = Path(__file__).resolve().parents[1] / "src" / "sudoplz" / "i_insist_guard.py"
RULE = Path(__file__).resolve().parents[1] / "hooks" / "i-insist.toml"


class SudoAskpassHookTests(unittest.TestCase):
    def check(self, command: str) -> str | None:
        result = subprocess.run(
            [sys.executable, str(CHECKER)],
            input=json.dumps({"kind": "shell", "command": command}),
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(result.stdout)

    def test_local_sudo_without_askpass_is_blocked(self) -> None:
        for command in (
            "sudo apt update",
            "cd /tmp && sudo apt update",
            "FOO=bar sudo -n apt update",
            "/usr/bin/sudo apt update",
            "echo ready; sudo apt update",
            "echo ready # skip this\nsudo apt update",
        ):
            with self.subTest(command=command):
                self.assertIn("sudoplz <command>", self.check(command))

    def test_askpass_option_allows_local_sudo(self) -> None:
        for command in (
            "sudoplz apt update",
            "sudoplz -u root apt update",
            "sudoplz -- test -f /fixture",
            "sudo -A apt update",
            "sudo --askpass apt update",
            "sudo -u root -A apt update",
            "sudo -Ak apt update",
            "sudo -A -u root apt update",
        ):
            with self.subTest(command=command):
                self.assertIsNone(self.check(command))

    def test_options_without_effective_askpass_are_blocked(self) -> None:
        self.assertIn("sudoplz <command>", self.check("sudo -nA apt update"))
        self.assertIn("sudoplz <command>", self.check("sudo -pA apt update"))

    def test_quoted_or_noncommand_sudo_is_ignored(self) -> None:
        for command in (
            "ssh host 'sudo apt update'",
            'ssh host "sudo apt update"',
            "echo 'sudo apt update'",
            "echo sudo",
            "# sudo apt update\necho ok",
            "bash -c 'sudo apt update'",
            "ssh host 'cd /tmp && sudo apt update'",
        ):
            with self.subTest(command=command):
                self.assertIsNone(self.check(command))

    def test_heredoc_data_is_ignored(self) -> None:
        for command in (
            "cat > s.sh <<EOF\nsudo -n apt-get update\nEOF",
            "cat > s.sh <<'EOF'\nsudo apt update; echo $HOME\nEOF\nchmod +x s.sh",
            "ssh host <<EOF\nsudo apt update\nEOF",
            "cat <<-EOF\n\tsudo apt update\n\tEOF",
        ):
            with self.subTest(command=command):
                self.assertIsNone(self.check(command))

    def test_shell_input_and_substitutions_are_inspected(self) -> None:
        for command in (
            "bash <<EOF\nsudo apt update\nEOF",
            "sh -s <<'EOF'\necho $HOME\nsudo -n apt update\nEOF",
            "cat <<EOF\n$(sudo apt update)\nEOF",
            "echo \"$(sudo apt update)\"",
            "env -i sudo apt update",
        ):
            with self.subTest(command=command):
                self.assertIn("sudoplz <command>", self.check(command))
        self.assertIsNone(self.check("bash <<EOF\nsudo -A apt update\nEOF"))

    def test_other_events_are_ignored(self) -> None:
        result = subprocess.run(
            [sys.executable, str(CHECKER)],
            input=json.dumps({"kind": "file_write", "command": None}),
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIsNone(json.loads(result.stdout))

    @unittest.skipUnless(shutil.which("i-insist"), "i-insist is not installed")
    def test_i_insist_registration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            script = home / ".local" / "share" / "sudoplz" / CHECKER.name
            script.parent.mkdir(parents=True)
            script.write_bytes(CHECKER.read_bytes())
            config = home / ".i-insist"
            config.mkdir()
            (config / "sudoplz.toml").write_bytes(RULE.read_bytes())
            env = os.environ | {"HOME": directory, "XDG_CACHE_HOME": directory}
            for command, blocked in (
                ("sudo apt update", True),
                ("sudo -A apt update", False),
                ("ssh host 'sudo apt update'", False),
            ):
                with self.subTest(command=command):
                    event = {
                        "kind": "shell",
                        "command": command,
                        "cwd": directory,
                        "harness": "test",
                        "tool_name": "exec_command",
                    }
                    result = subprocess.run(
                        ["i-insist", "check"],
                        input=json.dumps(event),
                        capture_output=True,
                        text=True,
                        env=env,
                        check=True,
                    )
                    self.assertEqual(json.loads(result.stdout)["blocked"], blocked)
