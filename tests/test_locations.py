import json
import os
import shutil
import subprocess
import unittest
from unittest import mock

import helpers
from ai_key_exposure_check import locations


class EnvFiles(helpers.ScanTestCase):
    def test_env_variants_are_found(self):
        for name in (".env", ".env.local", "prod.env", "nested/deep/.env.production"):
            self.write(self.project / name, f"OPENAI_API_KEY={helpers.fake_openai(name)}\n")
        report = self.scan_json()
        self.assertEqual(report["by_location_type"], {"env": 4})

    def test_default_path_is_cwd(self):
        self.write(self.project / ".env", f"OPENAI_API_KEY={helpers.fake_openai()}\n")
        code, out, _ = self.run_cli("--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["by_location_type"], {"env": 1})

    def test_excluded_directories_are_not_read(self):
        key = f"OPENAI_API_KEY={helpers.fake_openai()}\n"
        for directory in ("node_modules/pkg", ".git", "venv", ".venv", "site-packages"):
            self.write(self.project / directory / ".env", key)
        self.write(self.project / "customenv" / "pyvenv.cfg", "home = /nowhere\n")
        self.write(self.project / "customenv" / ".env", key)
        report = self.scan_json()
        self.assertEqual(report["total_candidates"], 0)
        self.assertFalse([path for path in self.reads if "node_modules" in path or "customenv" in path])

    def test_other_files_under_path_are_not_read(self):
        self.write(self.project / "settings.py", f"OPENAI_API_KEY={helpers.fake_openai()}\n")
        self.assertEqual(self.scan_json()["total_candidates"], 0)
        self.assertFalse([path for path in self.reads if path.endswith("settings.py")])


class McpConfigs(helpers.ScanTestCase):
    def config(self, key: str) -> str:
        return json.dumps({"mcpServers": {"x": {"command": "npx", "env": {"MISTRAL_API_KEY": key}}}}, indent=2)

    def test_project_level_files(self):
        for index, name in enumerate(
            (".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", "claude_desktop_config.json")
        ):
            self.write(self.project / name, self.config(helpers.fake_mistral(str(index))))
        report = self.scan_json()
        self.assertEqual(report["by_location_type"], {"mcp": 4})
        self.assertEqual(report["by_provider"], {"Mistral": 4})

    def test_unrelated_mcp_json_is_not_read(self):
        self.write(self.project / "other" / "mcp.json", self.config(helpers.fake_mistral()))
        self.assertEqual(self.scan_json()["total_candidates"], 0)

    def test_desktop_config_for_each_os_location_and_home_level_files(self):
        desktop = "claude_desktop_config.json"
        paths = [
            self.home / "Library" / "Application Support" / "Claude" / desktop,
            self.home / ".config" / "Claude" / desktop,
            self.home / "AppData" / "Roaming" / "Claude" / desktop,
            self.home / ".mcp.json",
            self.home / ".cursor" / "mcp.json",
            self.home / ".vscode" / "mcp.json",
        ]
        for index, path in enumerate(paths):
            with self.subTest(path=path.name):
                self.write(path, self.config(helpers.fake_mistral(str(index))))
                self.assertEqual(self.scan_json()["by_location_type"]["mcp"], index + 1)

    def test_key_passed_in_args_array(self):
        key = helpers.fake_generic()
        self.write(self.project / ".mcp.json", json.dumps({"args": ["--api-key", key]}))
        self.assertEqual(self.scan_json()["by_provider"], {"Generic": 1})


class ShellHistory(helpers.ScanTestCase):
    def test_each_history_file(self):
        cases = [
            (self.home / ".bash_history", "export OPENAI_API_KEY={}\n"),
            (self.home / ".zsh_history", ": 1700000000:0;export OPENAI_API_KEY={}\n"),
            (self.home / ".local/share/fish/fish_history", "- cmd: set -x OPENAI_API_KEY {}\n  when: 1\n"),
            (self.home / ".config/fish/fish_history", "- cmd: set -gx OPENAI_API_KEY {}\n  when: 1\n"),
        ]
        for index, (path, template) in enumerate(cases):
            with self.subTest(path=path.name, index=index):
                self.write(path, template.format(helpers.fake_openai(str(index))))
                report = self.scan_json()
                self.assertEqual(report["by_location_type"]["shell_history"], index + 1)

    def test_xdg_data_home_for_fish(self):
        data = self.tmp / "xdg-data"
        os.environ["XDG_DATA_HOME"] = str(data)
        self.write(data / "fish" / "fish_history", f"- cmd: set -x OPENAI_API_KEY {helpers.fake_openai()}\n")
        self.assertEqual(self.scan_json()["by_location_type"], {"shell_history": 1})


class AiCliConfig(helpers.ScanTestCase):
    def test_every_listed_folder_is_scanned(self):
        for index, name in enumerate(locations.AI_CLI_CONFIG_DIRS):
            self.write(
                self.home / ".config" / name / "config.yaml",
                f"api_key: {helpers.fake_generic(str(index))}\n",
            )
        report = self.scan_json()
        self.assertEqual(report["by_location_type"], {"ai_cli_config": len(locations.AI_CLI_CONFIG_DIRS)})

    def test_unlisted_config_folder_is_not_read(self):
        self.write(self.home / ".config" / "unrelated-app" / "config.yaml", f"api_key: {helpers.fake_generic()}\n")
        self.assertEqual(self.scan_json()["total_candidates"], 0)
        self.assertFalse([path for path in self.reads if "unrelated-app" in path])

    def test_xdg_config_home(self):
        config = self.tmp / "xdg-config"
        os.environ["XDG_CONFIG_HOME"] = str(config)
        self.write(config / "aider" / "keys.toml", f'api_key = "{helpers.fake_generic()}"\n')
        self.assertEqual(self.scan_json()["by_location_type"], {"ai_cli_config": 1})


@unittest.skipUnless(shutil.which("git"), "git is required")
class GitTracked(helpers.ScanTestCase):
    def setUp(self):
        super().setUp()
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.git("init", "-q")

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True)

    def test_only_tracked_files_are_scanned(self):
        self.write(self.repo / "app.py", f'API_KEY = "{helpers.fake_generic("t")}"\n')
        self.write(self.repo / "untracked.py", f'API_KEY = "{helpers.fake_generic("u")}"\n')
        self.git("add", "app.py")
        report = self.scan_json("--repo", str(self.repo))
        self.assertEqual(report["by_location_type"], {"git_tracked": 1})
        self.assertTrue(report["rows"][0]["path"].endswith("app.py"))

    def test_git_is_invoked_without_a_shell(self):
        real_run = subprocess.run
        calls = []

        def spy(command, **kwargs):
            calls.append((command, kwargs))
            return real_run(command, **kwargs)

        with mock.patch.object(locations.subprocess, "run", spy):
            self.scan_json("--repo", str(self.repo))
        self.assertEqual(len(calls), 1)
        command, kwargs = calls[0]
        self.assertIsInstance(command, list)
        self.assertIs(kwargs["shell"], False)
        self.assertEqual(command[-2:], ["ls-files", "-z"])

    def test_odd_file_names_survive(self):
        self.write(self.repo / "with space\nand newline.py", f'API_KEY = "{helpers.fake_generic()}"\n')
        self.git("add", ".")
        self.assertEqual(self.scan_json("--repo", str(self.repo))["by_location_type"], {"git_tracked": 1})

    def test_tracked_symlink_leaving_the_repo_is_not_followed(self):
        outside = self.write(self.tmp / "outside.txt", f'API_KEY = "{helpers.fake_generic()}"\n')
        os.symlink(outside, self.repo / "link.txt")
        self.git("add", ".")
        self.assertEqual(self.scan_json("--repo", str(self.repo))["total_candidates"], 0)
        self.assertNotIn(str(outside), [os.path.realpath(path) for path in self.reads])

    def test_repo_is_not_scanned_unless_requested(self):
        self.write(self.repo / "app.py", f'API_KEY = "{helpers.fake_generic()}"\n')
        self.git("add", ".")
        self.assertEqual(self.scan_json()["total_candidates"], 0)

    def test_hostile_fsmonitor_config_does_not_run(self):
        marker = self.tmp / "marker"
        hook = self.write(self.tmp / "hook.sh", f'#!/bin/sh\ntouch "{marker}"\n')
        os.chmod(hook, 0o755)
        self.write(self.repo / "app.py", "x = 1\n")
        self.git("add", ".")
        self.git("config", "core.fsmonitor", str(hook))
        self.scan_json("--repo", str(self.repo))
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
