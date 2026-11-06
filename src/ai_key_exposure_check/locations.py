"""The complete list of places this tool reads. The README mirrors this file."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path

from .files import walk_files

ENV = "env"
MCP = "mcp"
SHELL_HISTORY = "shell_history"
AI_CLI_CONFIG = "ai_cli_config"
GIT_TRACKED = "git_tracked"

LOCATION_LABELS = {
    ENV: ".env file",
    MCP: "MCP config",
    SHELL_HISTORY: "Shell history",
    AI_CLI_CONFIG: "AI CLI config",
    GIT_TRACKED: "Git-tracked file",
}

AI_CLI_CONFIG_DIRS = (
    "aichat", "aider", "anthropic", "chatgpt", "claude", "claude-code", "codex",
    "continue", "crush", "fabric", "gemini", "github-copilot", "goose",
    "io.datasette.llm", "litellm", "llm", "mistral", "mods", "ollama", "openai",
    "opencode", "openrouter", "shell_gpt",
)

GIT_TIMEOUT_SECONDS = 60


class RepoError(Exception):
    """Messages are fixed strings: git's output and the path are never included."""


def home_dir() -> Path | None:
    try:
        return Path.home()
    except RuntimeError:
        return None


def is_env_file(name: str) -> bool:
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def is_mcp_config(path: str) -> bool:
    name = os.path.basename(path)
    if name in (".mcp.json", "claude_desktop_config.json"):
        return True
    return name == "mcp.json" and os.path.basename(os.path.dirname(path)) in (".cursor", ".vscode")


def targets_under_path(root: str, on_error: Callable[[OSError], None]) -> Iterator[tuple[str, str]]:
    for path in walk_files(root, on_error):
        if is_env_file(os.path.basename(path)):
            yield ENV, path
        elif is_mcp_config(path):
            yield MCP, path


def home_mcp_files(home: Path) -> list[Path]:
    appdata = os.environ.get("APPDATA")
    roaming = Path(appdata) if appdata else home / "AppData" / "Roaming"
    desktop = "claude_desktop_config.json"
    return [
        home / "Library" / "Application Support" / "Claude" / desktop,  # macOS
        home / ".config" / "Claude" / desktop,  # Linux
        roaming / "Claude" / desktop,  # Windows
        home / ".mcp.json",
        home / ".cursor" / "mcp.json",
        home / ".vscode" / "mcp.json",
    ]


def shell_history_files(home: Path) -> list[Path]:
    data_home = os.environ.get("XDG_DATA_HOME")
    fish_data = Path(data_home) if data_home else home / ".local" / "share"
    return [
        home / ".bash_history",
        home / ".zsh_history",
        fish_data / "fish" / "fish_history",
        home / ".config" / "fish" / "fish_history",
    ]


def ai_cli_config_roots(home: Path) -> list[Path]:
    bases = [home / ".config"]
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg and Path(xdg) != bases[0]:
        bases.append(Path(xdg))
    return [base / name for base in bases for name in AI_CLI_CONFIG_DIRS]


def targets_in_home(home: Path, on_error: Callable[[OSError], None]) -> Iterator[tuple[str, str]]:
    for path in home_mcp_files(home):
        yield MCP, str(path)
    for path in shell_history_files(home):
        yield SHELL_HISTORY, str(path)
    for root in ai_cli_config_roots(home):
        if root.is_dir():
            for path in walk_files(str(root), on_error):
                yield AI_CLI_CONFIG, path


def _within(root: str, path: str) -> bool:
    try:
        return os.path.commonpath([root, path]) == root
    except ValueError:
        return False


def targets_in_repo(repo: str) -> Iterator[tuple[str, str]]:
    """List tracked files with ``git ls-files``, invoked without a shell."""
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0")
    command = [
        "git",
        "-c", "core.fsmonitor=false",  # a repo's config must not run a program
        "-C", repo,
        "ls-files", "-z",
    ]
    try:
        completed = subprocess.run(
            command,
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
            env=env,
            check=False,
        )
    except FileNotFoundError:
        raise RepoError("git is not installed or not on PATH") from None
    except (OSError, subprocess.SubprocessError):
        raise RepoError("could not run git for --repo") from None
    if completed.returncode != 0:
        raise RepoError("--repo is not a readable git repository") from None

    root = os.path.realpath(repo)
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        path = os.path.join(repo, os.fsdecode(raw))
        # A tracked symlink's target is not tracked content; do not leave the repo.
        if not os.path.islink(path) and _within(root, os.path.realpath(path)):
            yield GIT_TRACKED, path
