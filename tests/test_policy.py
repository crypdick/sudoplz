import json
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from sudoplz import askpass, core


class ConfigTests(unittest.TestCase):
    def test_reject_invalid_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            for value in (
                [],
                {"expiration_hours": "168"},
                {"expiration_hours": -1},
                {"allowed_paths": "/tmp/"},
                {"allowed_paths": ["relative"]},
                {"require_user_confirmation": 0},
                {"max_attempts_per_hour": 0},
                {"lockout_minutes": True},
                {"allowed_processes": [1]},
                {"typo": 1},
            ):
                with self.subTest(value=value):
                    path.write_text(json.dumps(value))
                    with patch.object(core, "CONFIG_FILE", path), self.assertRaises(ValueError):
                        core.load_config()


class RateLimitTests(unittest.TestCase):
    def test_concurrent_requests_cannot_share_last_allowance(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rate_limit.json"
            path.write_text(json.dumps({"attempts": [], "lockout_until": None}))
            original_read = Path.read_text
            barrier = threading.Barrier(2)

            def slow_read(file, *args, **kwargs):
                result = original_read(file, *args, **kwargs)
                if file == path:
                    time.sleep(0.2)
                return result

            def attempt():
                barrier.wait(timeout=5)
                return askpass.check_rate_limit(1, 15)

            with (
                patch.object(askpass, "RATE_LIMIT_FILE", path),
                patch.object(Path, "read_text", slow_read),
                ThreadPoolExecutor(2) as pool,
            ):
                results = list(pool.map(lambda _: attempt(), range(2)))
            self.assertEqual(sorted(results), [False, True])
            self.assertEqual(len(json.loads(path.read_text())["attempts"]), 1)


class RateLimitFailureTests(unittest.TestCase):
    def test_corrupt_state_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rate.json"
            for value in (
                "{",
                "[]",
                '{"attempts":["bad timestamp"]}',
                '{"attempts":[],"lockout_until":123}',
            ):
                path.write_text(value)
                with self.subTest(value=value), patch.object(askpass, "RATE_LIMIT_FILE", path):
                    self.assertFalse(askpass.check_rate_limit(1, 15))

    def test_failed_atomic_replace_preserves_previous_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rate.json"
            contents = b'{"attempts":[],"lockout_until":null}'
            path.write_bytes(contents)
            with (
                patch.object(askpass, "RATE_LIMIT_FILE", path),
                patch.object(core.os, "replace", side_effect=OSError("fixture failure")),
            ):
                self.assertFalse(askpass.check_rate_limit(1, 15))
            self.assertEqual(path.read_bytes(), contents)
