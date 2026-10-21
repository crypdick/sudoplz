import os
import subprocess
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from scripts.prepare_release import published_versions, release_state, release_version


class ReleaseTests(unittest.TestCase):
    def test_choose_unpublished_release(self) -> None:
        for current, published, expected in (
            ("0.2.0", [], "0.2.0"),
            ("0.2.0", ["0.2.0"], "0.2.1"),
            ("0.3.0", ["0.2.9", "0.4.0rc1"], "0.3.0"),
            ("0.2.0", ["0.2.9"], "0.2.10"),
        ):
            with self.subTest(current=current, published=published):
                self.assertEqual(release_version(current, published), expected)

    def test_only_missing_project_counts_as_first_publication(self) -> None:
        def unavailable(status: int) -> urllib.error.HTTPError:
            return urllib.error.HTTPError("https://pypi.org", status, "registry error", {}, None)  # type: ignore[arg-type]

        with mock.patch("urllib.request.urlopen", side_effect=unavailable(404)):
            self.assertEqual(published_versions("sudoplz"), [])
        with (
            mock.patch("urllib.request.urlopen", side_effect=unavailable(503)),
            self.assertRaises(urllib.error.HTTPError),
        ):
            published_versions("sudoplz")

    def test_retry_reuses_release_and_overtaken_runs_are_skipped(self) -> None:
        env = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args: str) -> str:
                return subprocess.check_output(
                    ["git", "-c", "core.hooksPath=/dev/null", "-C", directory, *args],
                    text=True,
                    env=env,
                ).strip()

            git("init", "-b", "main")
            git("config", "user.name", "Release test")
            git("config", "user.email", "test@example.com")
            git("commit", "--allow-empty", "-m", "source")
            source = git("rev-parse", "HEAD")
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(release_state(root, source), "new")
                message = f"Source-Commit: {source}"
                git("commit", "--allow-empty", "-m", "Release 0.2.0", "-m", message)
                self.assertEqual(release_state(root, source), "retry")
                git("commit", "--allow-empty", "-m", "later change")
                self.assertEqual(release_state(root, source), "stale")
