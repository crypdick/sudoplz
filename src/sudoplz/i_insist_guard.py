"""Advise agents to use sudoplz for local sudo calls."""

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

MESSAGE = (
    "Local sudo needs sudoplz approval. Use `sudoplz <command>` without `-n`; "
    "sudoplz sets SUDO_ASKPASS and runs sudo -k -A. "
    "Use `sudoplz -- <command>` if the command name matches a management command. "
    "If no credential is stored, "
    "ask the user to run `sudoplz set` interactively."
)
WRAPPERS = {"env", "command", "exec", "nohup"}
SHELLS = {"sh", "bash", "zsh", "dash"}
OPTION_ARGUMENTS = {"-u", "-g", "-p", "-h", "-C", "-D", "-R", "-r", "-t", "-T"}
LONG_OPTION_ARGUMENTS = {
    "--user", "--group", "--prompt", "--host", "--close-from", "--chdir", "--chroot",
    "--role", "--type", "--command-timeout",
}


def sudo_uses_askpass(words: list[str | None], start: int) -> bool:
    askpass = False
    no_prompt = False
    skip_argument = False
    for word in words[start:]:
        if skip_argument:
            skip_argument = False
            continue
        if word is None or word == "--" or not word.startswith("-") or word == "-":
            break
        if word in OPTION_ARGUMENTS or word in LONG_OPTION_ARGUMENTS:
            skip_argument = True
        elif word.startswith("--"):
            askpass |= word == "--askpass"
            no_prompt |= word == "--non-interactive"
        else:
            for position, option in enumerate(word[1:], start=1):
                if f"-{option}" in OPTION_ARGUMENTS:
                    skip_argument = position == len(word) - 1
                    break
                askpass |= option == "A"
                no_prompt |= option == "n"
    return askpass and not no_prompt


def literal(word: dict[str, Any]) -> str | None:
    values = []
    for part in word.get("Parts", []):
        kind = part.get("Type")
        if kind == "Lit":
            values.append(re.sub(r"\\(.)", r"\1", part.get("Value", "")))
        elif kind == "SglQuoted":
            values.append(part.get("Value", ""))
        elif kind == "DblQuoted":
            inner = literal(part)
            if inner is None:
                return None
            values.append(inner)
        else:
            return None
    return "".join(values)


def command_words(call: dict[str, Any]) -> list[str | None]:
    words = [literal(word) for word in call.get("Args", [])]
    while words and words[0] in WRAPPERS:
        words = words[1:]
        while words and words[0] is not None and (words[0].startswith("-") or "=" in words[0]):
            words = words[1:]
    return words


def finds_sudo(node: Any, source: bytes) -> bool:
    if isinstance(node, list):
        return any(finds_sudo(child, source) for child in node)
    if not isinstance(node, dict):
        return False
    command = node.get("Cmd")
    if isinstance(command, dict) and command.get("Type") == "CallExpr":
        words = command_words(command)
        if words and words[0] is not None and Path(words[0]).name in SHELLS:
            for redirect in node.get("Redirs") or []:
                body = redirect.get("Hdoc")
                if body and needs_askpass(
                    source[body["Pos"]["Offset"]:body["End"]["Offset"]].decode()
                ):
                    return True
    if node.get("Type") == "CallExpr":
        words = command_words(node)
        if words and words[0] is not None and Path(words[0]).name == "sudo" and not (
            sudo_uses_askpass(words, 1)
        ):
            return True
    # Heredoc data and quoted text hold no CallExpr nodes; substitutions do.
    return any(
        finds_sudo(value, source)
        for key, value in node.items()
        if key not in ("Pos", "End", "Comments")
    )


def needs_askpass(command: str) -> bool:
    try:
        parsed = subprocess.run(
            ["shfmt", "-ln=bash", "--to-json"],
            input=command, text=True, capture_output=True, timeout=2,
        )
        tree = json.loads(parsed.stdout) if parsed.returncode == 0 else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False
    return finds_sudo(tree, command.encode())


def main() -> None:
    event = json.load(sys.stdin)
    command = event.get("command") if event.get("kind") == "shell" else None
    json.dump(MESSAGE if isinstance(command, str) and needs_askpass(command) else None, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
