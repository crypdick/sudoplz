#!/usr/bin/env python3
"""Prepare the automatic release described in README.md's Releases section."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

import tomllib


def release_state(root: Path, source: str) -> str:
    """Reuse this push's release commit; skip CI overtaken by another push."""
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if head == source:
        return "new"
    parent = subprocess.check_output(["git", "rev-parse", "HEAD^"], cwd=root, text=True).strip()
    message = subprocess.check_output(["git", "log", "-1", "--format=%B"], cwd=root, text=True)
    if (
        parent == source
        and message.startswith("Release ")
        and f"Source-Commit: {source}" in message.splitlines()
    ):
        return "retry"
    return "stale"


def release_version(current: str, published: list[str]) -> str:
    """Preserve an unpublished manual bump, otherwise increment the latest patch."""
    if not re.fullmatch(r"\d+\.\d+\.\d+", current):
        raise ValueError(f"Release version must be major.minor.patch: {current}")
    released = [
        tuple(map(int, value.split(".")))
        for value in published
        if re.fullmatch(r"\d+\.\d+\.\d+", value)
    ]
    latest = max(released, default=(-1, -1, -1))
    if tuple(map(int, current.split("."))) > latest:
        return current
    return f"{latest[0]}.{latest[1]}.{latest[2] + 1}"


def published_versions(project: str) -> list[str]:
    """A missing PyPI project has no releases; other registry errors must stop publication."""
    try:
        url = f"https://pypi.org/pypi/{project}/json"
        with urllib.request.urlopen(url, timeout=30) as response:
            return list(json.load(response)["releases"])
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return []
        raise


def main() -> None:
    """Prepare version files and report state to GitHub Actions."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.source):
        parser.error("source must be a full Git commit SHA")
    root = Path.cwd()
    state = release_state(root, args.source)
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = project["version"]
    if state == "new":
        published = published_versions(project["name"])
        version = release_version(version, published)
        subprocess.run(["uv", "version", "--no-sync", version], check=True)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        output.write(f"state={state}\nversion={version}\n")


if __name__ == "__main__":
    main()
