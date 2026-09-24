"""Advise agents to use sudoplz for local sudo calls."""

import json
import re
import shlex
import sys
from pathlib import Path

MESSAGE = (
    "Local sudo needs sudoplz approval. Use `sudo -A <command>` without `-n`. "
    "Set `SUDO_ASKPASS` to the `askpass` executable; if no credential is stored, "
    "ask the user to run `sudoplz set` interactively."
)
SEPARATORS = {";", "&&", "||", "|", "&", "\n", "(", ")"}
OPTION_ARGUMENTS = {"-u", "-g", "-p", "-h", "-C", "-D", "-R", "-r", "-t", "-T"}
LONG_OPTION_ARGUMENTS = {
    "--user", "--group", "--prompt", "--host", "--close-from", "--chdir", "--chroot",
    "--role", "--type", "--command-timeout",
}


def sudo_uses_askpass(words: list[str], start: int) -> bool:
    askpass = False
    no_prompt = False
    skip_argument = False
    for word in words[start:]:
        if skip_argument:
            skip_argument = False
            continue
        if word in SEPARATORS or word == "--" or not word.startswith("-") or word == "-":
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


def needs_askpass(command: str) -> bool:
    # NOTE: This covers common shell syntax; use a shell AST if full coverage is needed.
    lexer = shlex.shlex(command, posix=False, punctuation_chars=";&|()\n")
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        words = list(lexer)
    except ValueError:
        return False

    command_start = True
    in_comment = False
    for index, word in enumerate(words):
        if in_comment:
            if word == "\n":
                in_comment = False
                command_start = True
            continue
        if word.startswith("#"):
            in_comment = True
            continue
        if word in SEPARATORS:
            command_start = True
        elif command_start and (
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", word)
            or word in {"env", "command", "exec", "nohup"}
        ):
            continue
        elif command_start:
            command_start = False
            if Path(word).name == "sudo" and not sudo_uses_askpass(words, index + 1):
                return True
    return False


def main() -> None:
    event = json.load(sys.stdin)
    command = event.get("command") if event.get("kind") == "shell" else None
    json.dump(MESSAGE if isinstance(command, str) and needs_askpass(command) else None, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
