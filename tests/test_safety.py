import ast
import contextlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

import helpers
from ai_key_exposure_check import cli, detect, files, scanner

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "src" / "ai_key_exposure_check"


def all_fake_secrets() -> dict[str, str]:
    return {
        "OPENAI_API_KEY": helpers.fake_openai(),
        "ANTHROPIC_API_KEY": helpers.fake_anthropic(),
        "GEMINI_API_KEY": helpers.fake_google(),
        "AZURE_OPENAI_API_KEY": helpers.fake_azure(),
        "AWS_ACCESS_KEY_ID": helpers.fake_aws_access(),
        "AWS_SECRET_ACCESS_KEY": helpers.fake_aws_secret(),
        "OPENROUTER_API_KEY": helpers.fake_openrouter(),
        "MISTRAL_API_KEY": helpers.fake_mistral(),
        "CUSTOM_SERVICE_TOKEN": helpers.fake_generic(),
    }


class SecretsNeverLeak(helpers.ScanTestCase):
    def setUp(self):
        super().setUp()
        self.secrets = all_fake_secrets()
        content = "".join(f"{name}={value}\n" for name, value in self.secrets.items())
        self.write(self.project / ".env", content)

    def assert_clean(self, *outputs: str) -> None:
        for name, secret in self.secrets.items():
            with self.subTest(secret=name):
                for output in outputs:
                    helpers.assert_no_secret_leak(self, output, secret)

    def test_table(self):
        code, out, err = self.run_cli("--path", str(self.project))
        self.assertEqual(code, 0)
        self.assertIn("9 candidate credentials", out)
        self.assert_clean(out, err)

    def test_table_has_no_previews_by_default(self):
        _, out, _ = self.run_cli("--path", str(self.project))
        self.assertNotIn("…", out)

    def test_json(self):
        code, out, err = self.run_cli("--path", str(self.project), "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["total_candidates"], 9)
        self.assertNotIn("previews", out)
        self.assert_clean(out, err)

    def test_verbose_table_and_json_show_only_four_characters(self):
        _, table, table_err = self.run_cli("--path", str(self.project), "--verbose")
        _, as_json, json_err = self.run_cli("--path", str(self.project), "--json", "--verbose")
        self.assert_clean(table, table_err, as_json, json_err)
        for secret in self.secrets.values():
            self.assertIn(secret[:4] + "…", table)
            self.assertIn(secret[:4] + "…", json.loads(as_json)["rows"][0]["previews"]
                          + [p for r in json.loads(as_json)["rows"] for p in r["previews"]])

    def test_internal_error_prints_type_name_only(self):
        secret = helpers.fake_anthropic()
        for extra in ([], ["--json"], ["--verbose"]):
            with mock.patch.object(cli, "run_scan", side_effect=RuntimeError(f"boom {secret}")):
                code, out, err = self.run_cli("--path", str(self.project), *extra)
            self.assertEqual(code, 2)
            self.assertIn("RuntimeError", err)
            helpers.assert_no_secret_leak(self, out + err, secret)
            self.assertNotIn("Traceback", err)

    def test_failure_inside_file_reading_does_not_leak(self):
        secret = helpers.fake_anthropic()
        with mock.patch.object(scanner, "detect", side_effect=ValueError(f"cannot parse {secret}")):
            code, out, err = self.run_cli("--path", str(self.project))
        self.assertEqual(code, 2)
        helpers.assert_no_secret_leak(self, out + err, secret)

    def test_excepthook_prints_no_message_or_traceback(self):
        secret = helpers.fake_anthropic()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            try:
                raise RuntimeError(secret)
            except RuntimeError as exc:
                cli._silent_excepthook(type(exc), exc, exc.__traceback__)
        helpers.assert_no_secret_leak(self, err.getvalue(), secret)
        self.assertNotIn("Traceback", err.getvalue())

    def test_key_pasted_as_an_argument_is_not_echoed(self):
        secret = helpers.fake_anthropic()
        for args in ([secret], [f"--{secret}"], ["--json", secret], [f"--json={secret}"]):
            code, out, err = self.run_cli(*args)
            self.assertEqual(code, 2)
            helpers.assert_no_secret_leak(self, out + err, secret)

    def test_key_pasted_as_a_path_is_not_echoed(self):
        secret = helpers.fake_anthropic()
        for args in (["--path", secret], ["--repo", secret], ["--path", str(self.project), "--repo", str(self.tmp / secret)]):
            code, out, err = self.run_cli(*args)
            self.assertEqual(code, 2)
            helpers.assert_no_secret_leak(self, out + err, secret)

    @unittest.skipUnless(shutil.which("git"), "git is required")
    def test_git_failure_does_not_echo_output_or_path(self):
        secret = helpers.fake_anthropic()
        not_a_repo = self.tmp / secret
        not_a_repo.mkdir()
        code, out, err = self.run_cli("--path", str(self.project), "--repo", str(not_a_repo))
        self.assertEqual(code, 2)
        helpers.assert_no_secret_leak(self, out + err, secret)

    def test_key_in_a_file_path_is_masked(self):
        secret = helpers.fake_anthropic()
        other = helpers.fake_openai()
        self.write(self.project / secret / ".env", f"OPENAI_API_KEY={other}\n")
        for args in ([], ["--json"], ["--verbose"]):
            _, out, err = self.run_cli("--path", str(self.project), *args)
            helpers.assert_no_secret_leak(self, out + err, secret)
            helpers.assert_no_secret_leak(self, out + err, other)

    def test_control_characters_in_a_file_path_are_replaced(self):
        self.write(self.project / "a\x1b[31mb" / ".env", f"OPENAI_API_KEY={helpers.fake_openai()}\n")
        _, out, _ = self.run_cli("--path", str(self.project))
        self.assertNotIn("\x1b", out)

    def test_subprocess_entry_point_with_ascii_stdout(self):
        env = {
            "HOME": str(self.home),
            "USERPROFILE": str(self.home),
            "PYTHONPATH": str(ROOT / "src"),
            "PYTHONIOENCODING": "ascii",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PATH": os.environ.get("PATH", ""),
        }
        completed = subprocess.run(
            [sys.executable, "-m", "ai_key_exposure_check", "--path", str(self.project), "--verbose"],
            env=env, capture_output=True, text=True, check=False, timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("9 candidate credentials", completed.stdout)
        self.assertNotIn("Traceback", completed.stderr)
        for secret in self.secrets.values():
            helpers.assert_no_secret_leak(self, completed.stdout + completed.stderr, secret)


class NoNetworkNoWrites(helpers.ScanTestCase):
    def populate(self):
        self.write(self.project / ".env", f"OPENAI_API_KEY={helpers.fake_openai()}\n")
        self.write(self.home / ".bash_history", f"export ANTHROPIC_API_KEY={helpers.fake_anthropic()}\n")
        self.write(self.home / ".mcp.json", f'{{"MISTRAL_API_KEY": "{helpers.fake_mistral()}"}}\n')
        self.write(self.home / ".config" / "aider" / "c.yaml", f"api_key: {helpers.fake_generic()}\n")

    @unittest.skipUnless(shutil.which("git"), "git is required")
    def test_scan_opens_no_network_socket(self):
        self.populate()
        repo = self.tmp / "repo"
        repo.mkdir()
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True, capture_output=True)
        self.write(repo / "a.py", f'API_KEY = "{helpers.fake_generic("r")}"\n')
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True, capture_output=True)

        attempts = []

        def forbid(sock, address):
            attempts.append(address)
            raise AssertionError("network connection attempted during scan")

        with mock.patch.object(socket.socket, "connect", forbid), mock.patch.object(socket.socket, "connect_ex", forbid):
            # The patch itself must work, or this test proves nothing.
            with socket.socket() as probe, self.assertRaises(AssertionError):
                probe.connect(("127.0.0.1", 9))
            self.assertEqual(len(attempts), 1)
            attempts.clear()

            # main() swallows exceptions, so check both the attempts and the exit code.
            for extra in ([], ["--json"], ["--verbose"]):
                code, _, _ = self.run_cli("--path", str(self.project), "--repo", str(repo), *extra)
                self.assertEqual(code, 0)
        self.assertEqual(attempts, [])

    def test_package_imports_no_network_modules(self):
        banned = {
            "socket", "ssl", "http", "urllib", "ftplib", "smtplib", "poplib", "imaplib",
            "telnetlib", "xmlrpc", "asyncio", "requests", "httpx", "aiohttp", "webbrowser",
        }
        for path in PACKAGE.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    names = [node.module or ""]
                for name in names:
                    self.assertNotIn(name.split(".")[0], banned, f"{path.name} imports {name}")

    def test_package_uses_only_the_standard_library(self):
        for path in PACKAGE.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    names = [node.module or ""]
                else:
                    continue
                for name in names:
                    self.assertIn(name.split(".")[0], sys.stdlib_module_names, f"{path.name} imports {name}")

    def test_scan_writes_no_files(self):
        self.populate()

        def snapshot():
            return sorted(
                (str(path), path.stat().st_size, path.stat().st_mtime_ns)
                for path in self.tmp.rglob("*") if path.is_file()
            )

        before = snapshot()
        for extra in ([], ["--json"], ["--verbose"]):
            self.run_cli("--path", str(self.project), *extra)
        self.assertEqual(before, snapshot())

    def test_only_listed_files_are_read(self):
        self.populate()
        self.write(self.home / ".ssh" / "id_rsa", "not for reading\n")
        self.write(self.home / ".aws" / "credentials", "not for reading\n")
        self.write(self.home / "notes.txt", "not for reading\n")
        self.run_cli("--path", str(self.project))
        for path in self.reads:
            self.assertNotIn(".ssh", path)
            self.assertNotIn(".aws", path)
            self.assertFalse(path.endswith("notes.txt"))


class SkipsAndDedupe(helpers.ScanTestCase):
    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root can read everything")
    def test_unreadable_file_is_counted_not_named(self):
        path = self.write(self.project / ".env.secretname", f"OPENAI_API_KEY={helpers.fake_openai()}\n")
        os.chmod(path, 0)
        self.addCleanup(os.chmod, path, 0o600)
        for args in ([], ["--json"]):
            code, out, err = self.run_cli("--path", str(self.project), *args)
            self.assertEqual(code, 0)
            self.assertNotIn("secretname", out + err)
        self.assertEqual(self.scan_json()["skipped"]["unreadable"], 1)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root can read everything")
    def test_unreadable_directory_is_counted(self):
        path = self.project / "locked"
        path.mkdir()
        os.chmod(path, 0)
        self.addCleanup(os.chmod, path, 0o700)
        self.assertEqual(self.scan_json()["skipped"]["unreadable"], 1)

    def test_binary_file_is_skipped_and_counted(self):
        path = self.project / ".env"
        path.write_bytes(b"\0\1\2" + f"OPENAI_API_KEY={helpers.fake_openai()}".encode())
        report = self.scan_json()
        self.assertEqual(report["skipped"]["binary"], 1)
        self.assertEqual(report["total_candidates"], 0)

    def test_large_file_is_skipped_and_counted(self):
        path = self.project / ".env"
        path.write_text(f"OPENAI_API_KEY={helpers.fake_openai()}\n" + "#" * (files.MAX_FILE_BYTES + 1))
        report = self.scan_json()
        self.assertEqual(report["skipped"]["too_large"], 1)
        self.assertEqual(report["total_candidates"], 0)

    def test_symlink_loops_are_ignored(self):
        os.symlink(self.project / ".env", self.project / ".env")
        (self.project / "a").mkdir()
        os.symlink(self.project, self.project / "a" / "back_to_top")
        os.symlink(self.project / "b.env", self.project / "c.env")
        os.symlink(self.project / "c.env", self.project / "b.env")
        self.write(self.project / "a" / ".env", f"OPENAI_API_KEY={helpers.fake_openai()}\n")
        report = self.scan_json()
        self.assertEqual(report["total_candidates"], 1)
        self.assertEqual(report["skipped"]["unreadable"], 0)

    def test_dangling_symlink_is_ignored(self):
        os.symlink(self.tmp / "gone", self.project / ".env")
        self.assertEqual(self.scan_json()["skipped"]["unreadable"], 0)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs FIFOs")
    def test_fifo_does_not_hang(self):
        os.mkfifo(self.project / ".env")
        self.assertEqual(self.scan_json()["total_candidates"], 0)

    def test_same_secret_same_location_counts_once(self):
        key = helpers.fake_openai()
        self.write(self.project / ".env", f"OPENAI_API_KEY={key}\nOTHER_KEY={key}\n# {key}\n")
        self.assertEqual(self.scan_json()["total_candidates"], 1)

    def test_same_secret_in_two_locations_counts_twice(self):
        key = helpers.fake_openai()
        self.write(self.project / ".env", f"OPENAI_API_KEY={key}\n")
        self.write(self.project / "sub" / ".env", f"OPENAI_API_KEY={key}\n")
        self.assertEqual(self.scan_json()["total_candidates"], 2)

    def test_different_secrets_in_one_file_count_separately(self):
        self.write(self.project / ".env", f"A_KEY={helpers.fake_openai('1')}\nB_KEY={helpers.fake_openai('2')}\n")
        self.assertEqual(self.scan_json()["total_candidates"], 2)

    def test_symlink_to_scanned_file_is_not_double_counted(self):
        self.write(self.project / ".env", f"OPENAI_API_KEY={helpers.fake_openai()}\n")
        os.symlink(self.project / ".env", self.project / ".env.local")
        self.assertEqual(self.scan_json()["total_candidates"], 1)

    def test_path_overlapping_home_is_not_double_counted(self):
        self.write(self.home / ".mcp.json", f'{{"MISTRAL_API_KEY": "{helpers.fake_mistral()}"}}\n')
        code, out, _ = self.run_cli("--path", str(self.home), "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["total_candidates"], 1)


class OutputAndExitCodes(helpers.ScanTestCase):
    def test_exit_zero_when_keys_found(self):
        self.write(self.project / ".env", f"OPENAI_API_KEY={helpers.fake_openai()}\n")
        self.assertEqual(self.run_cli("--path", str(self.project))[0], 0)

    def test_fail_on_found(self):
        self.assertEqual(self.run_cli("--path", str(self.project), "--fail-on-found")[0], 0)
        self.write(self.project / ".env", f"OPENAI_API_KEY={helpers.fake_openai()}\n")
        self.assertEqual(self.run_cli("--path", str(self.project), "--fail-on-found")[0], 1)
        self.assertEqual(self.run_cli("--path", str(self.project), "--fail-on-found", "--json")[0], 1)

    def test_verdict_is_the_last_single_line(self):
        _, out, _ = self.run_cli("--path", str(self.project))
        self.assertTrue(out.strip().splitlines()[-1].startswith("Verdict: no candidate"))
        self.write(self.project / ".env", f"OPENAI_API_KEY={helpers.fake_openai()}\n")
        _, out, _ = self.run_cli("--path", str(self.project))
        lines = out.strip().splitlines()
        self.assertIn("1 candidate credential in 1 location", lines[-1])
        self.assertIn("cannot tell whether any key is live", lines[-1])

    def test_table_counts_by_location_and_provider(self):
        self.write(
            self.project / ".env",
            f"A_KEY={helpers.fake_openai('1')}\nB_KEY={helpers.fake_openai('2')}\nMISTRAL_KEY={helpers.fake_mistral()}\n",
        )
        report = self.scan_json()
        counts = {row["provider"]: row["count"] for row in report["rows"]}
        self.assertEqual(counts, {"OpenAI": 2, "Mistral": 1})
        _, out, _ = self.run_cli("--path", str(self.project))
        self.assertIn(".env file", out)
        self.assertIn("OpenAI", out)

    def test_home_is_shortened_in_paths(self):
        self.write(self.home / ".bash_history", f"export OPENAI_API_KEY={helpers.fake_openai()}\n")
        report = self.scan_json()
        self.assertEqual(report["rows"][0]["path"], "~/.bash_history")


class RepositoryContainsNoKeyShapedStrings(unittest.TestCase):
    def test_no_detector_hits_in_source_tests_or_docs(self):
        paths = [ROOT / "README.md", ROOT / "pyproject.toml"]
        paths += sorted(PACKAGE.glob("*.py")) + sorted((ROOT / "tests").glob("*.py"))
        for path in paths:
            with self.subTest(path=path.name):
                self.assertEqual(detect.detect(path.read_text(encoding="utf-8")), [])


if __name__ == "__main__":
    unittest.main()
