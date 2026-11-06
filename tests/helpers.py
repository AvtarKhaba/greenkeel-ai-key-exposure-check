"""Shared test support. Fake keys are assembled at runtime from split parts, so no
key-shaped string exists in this repository."""

from __future__ import annotations

import contextlib
import io
import json
import os
import random
import string
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ai_key_exposure_check import files  # noqa: E402
from ai_key_exposure_check.cli import main  # noqa: E402

_MIXED = string.ascii_letters + string.digits
_UPPER = string.ascii_uppercase + string.digits
_HEX = "0123456789abcdef"


def _body(seed: str, length: int, alphabet: str = _MIXED) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice(alphabet) for _ in range(length))


def fake_anthropic(seed: str = "a") -> str:
    return "sk" + "-" + "an" + "t-" + "api03-" + _body(seed, 48)


def fake_openrouter(seed: str = "r") -> str:
    return "sk" + "-" + "o" + "r-" + "v1-" + _body(seed, 48, _HEX)


def fake_openai(seed: str = "o") -> str:
    return "sk" + "-" + "proj-" + _body(seed, 48)


def fake_google(seed: str = "g") -> str:
    return "AI" + "za" + _body(seed, 35)


def fake_aws_access(seed: str = "w") -> str:
    return "AK" + "IA" + _body(seed, 16, _UPPER)


def fake_aws_secret(seed: str = "s") -> str:
    return _body(seed, 40)


def fake_bedrock_api_key(seed: str = "b") -> str:
    return "AB" + "SK" + _body(seed, 40)


def fake_azure(seed: str = "z") -> str:
    return _body(seed, 32, _HEX)


def fake_mistral(seed: str = "m") -> str:
    return _body(seed, 32)


def fake_generic(seed: str = "n") -> str:
    return _body(seed, 40)


def assert_no_secret_leak(test: unittest.TestCase, output: str, secret: str) -> None:
    """Nothing beyond the first 4 characters may appear, in any position."""
    test.assertNotIn(secret, output)
    test.assertNotIn(secret[:5], output)
    test.assertNotIn(secret[4:], output)
    test.assertNotIn(secret[-8:], output)


class ScanTestCase(unittest.TestCase):
    """Runs every test with a temporary HOME and fails on a read outside it."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="akec-")
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(os.path.realpath(tmp.name))
        self.home = self.tmp / "home"
        self.project = self.tmp / "project"
        self.home.mkdir()
        self.project.mkdir()

        env = {
            "HOME": str(self.home),
            "USERPROFILE": str(self.home),
            "APPDATA": str(self.home / "AppData" / "Roaming"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        }
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ("XDG_CONFIG_HOME", "XDG_DATA_HOME"):
            os.environ.pop(name, None)

        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.project)

        # sys.excepthook is replaced by main(); restore it after each test.
        self.addCleanup(setattr, sys, "excepthook", sys.excepthook)

        self.reads: list[str] = []
        self.outside_reads: list[str] = []
        # Checked at cleanup because main() deliberately swallows exceptions.
        self.addCleanup(lambda: self.assertEqual(self.outside_reads, []))
        real_open = files._open_readonly

        def guarded_open(path: str) -> int:
            self.reads.append(path)
            if not os.path.realpath(path).startswith(str(self.tmp) + os.sep):
                self.outside_reads.append(path)
                raise PermissionError("test attempted to read outside its temp directory")
            return real_open(path)

        open_patch = mock.patch.object(files, "_open_readonly", guarded_open)
        open_patch.start()
        self.addCleanup(open_patch.stop)

    def write(self, path: Path, content: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def run_cli(self, *args: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(args))
        return code, out.getvalue(), err.getvalue()

    def scan_json(self, *args: str) -> dict:
        code, out, err = self.run_cli("--path", str(self.project), "--json", *args)
        self.assertEqual(code, 0, err)
        return json.loads(out)

    def rows_for(self, report: dict, location_type: str) -> list[dict]:
        return [row for row in report["rows"] if row["location_type"] == location_type]
