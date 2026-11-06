<img src="assets/greenkeel-mark.svg" alt="GreenKeel" width="56">

# AI Key Exposure Check

**By [GreenKeel](https://greenkeel.dev).** A small open-source CLI that shows where AI keys are sitting on your machine.

Counts candidate AI provider credentials on your own machine: how many, where, and for which provider.

- **Nothing leaves your machine.** The tool makes no network calls and has no runtime dependencies beyond the Python standard library.
- **Secret values are never printed or stored.** The most any output can contain is a masked preview: the first 4 characters + `…`. Previews are off unless you pass `--verbose`.
- **No files are written.** Not a report, not a cache, not a log.

## Usage

Requires Python 3.10+.

```sh
pip install git+https://github.com/AvtarKhaba/greenkeel-ai-key-exposure-check
ai-key-exposure-check             # or: python -m ai_key_exposure_check
ai-key-exposure-check --path ~/projects --repo ~/projects/my-app
```

| Option | Effect |
| --- | --- |
| `--path DIR` | Where to look for `.env` and MCP files, recursively. Default: current directory. |
| `--repo DIR` | Also scan the files tracked by git in this repository. Not scanned otherwise. |
| `--json` | JSON instead of a table. |
| `--verbose` | Add masked previews to the table or JSON. |
| `--fail-on-found` | Exit 1 if any candidate is found. |

Exit codes: `0` whether or not keys are found, `1` only with `--fail-on-found` and at least one candidate, `2` on a usage or internal error. Error messages name the problem but never repeat your arguments, exception text or a traceback.

## Exactly what it reads

**Under `--path`, recursively**

- `.env`, `.env.*`, `*.env`
- `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`
- Skipped directories: `node_modules`, `.git`, `venv`, `.venv`, `virtualenv`, `.virtualenv`, `.tox`, `.nox`, `site-packages`, `__pycache__`, `.mypy_cache`, `.pytest_cache`, `Cache`, `cache`, `.cache`, and anything containing `pyvenv.cfg` or `conda-meta`.

**In your home directory**

- MCP configs:
  - `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
  - `~/.config/Claude/claude_desktop_config.json` (Linux)
  - `%APPDATA%\Claude\claude_desktop_config.json` (Windows)
  - `~/.mcp.json`, `~/.cursor/mcp.json`, `~/.vscode/mcp.json`
- Shell history: `~/.bash_history`, `~/.zsh_history`, `~/.local/share/fish/fish_history` (or under `$XDG_DATA_HOME`), `~/.config/fish/fish_history`
- All text files in these folders under `~/.config` (and `$XDG_CONFIG_HOME`, if set): `aichat`, `aider`, `anthropic`, `chatgpt`, `claude`, `claude-code`, `codex`, `continue`, `crush`, `fabric`, `gemini`, `github-copilot`, `goose`, `io.datasette.llm`, `litellm`, `llm`, `mistral`, `mods`, `ollama`, `openai`, `opencode`, `openrouter`, `shell_gpt`

**With `--repo`**

- Files listed by `git ls-files`, as they are in the working tree. Git runs without a shell. A tracked symlink is not followed.

**Skipped everywhere**

Files that cannot be read are counted, never listed. Binary files (a NUL byte in the first 8 KiB) and files over 5 MiB are skipped and counted. Symlinked directories are not followed, and looping or dangling symlinks and non-regular files such as FIFOs are ignored.

Nothing else is read. In particular, `--path` set to a large directory such as your home is thorough but slow, because every directory is walked to find matching file names.

## What it detects

| Provider | How |
| --- | --- |
| Anthropic | Prefix `sk-ant-`, or a variable name containing `ANTHROPIC` or `CLAUDE` |
| OpenAI | Prefix `sk-`, `sk-proj-` etc., or a name containing `OPENAI` |
| OpenRouter | Prefix `sk-or-`, or a name containing `OPENROUTER` |
| Google/Gemini | Prefix `AIza`, or a name such as `GEMINI_API_KEY` or `GOOGLE_API_KEY` |
| AWS Bedrock | Access key prefixes `AKIA`, `ASIA`; Bedrock API key prefixes `ABSK`, `bedrock-api-key-`; or names such as `AWS_SECRET_ACCESS_KEY` |
| Azure OpenAI | **Variable name only**, such as `AZURE_OPENAI_API_KEY` |
| Mistral | **Variable name only**, such as `MISTRAL_API_KEY` |
| Generic | A high-entropy value (20+ characters, Shannon entropy of at least 3.5 bits per character, contains a digit) next to any name containing `KEY`, `TOKEN` or `SECRET`, or after `Bearer` |

"Next to a name" covers `.env`, shell, JSON, YAML and TOML assignments, fish `set -x NAME value`, and flags such as `--api-key value`. Placeholders, variable references, file paths and URLs are ignored.

The same secret appearing more than once in one file is counted once. The same secret in two files is counted in each.

## What it cannot tell you

**It finds candidates. It cannot tell whether a key is live**, because checking would mean sending it over the network. Treat a finding as "look at this", and treat a clean result as "nothing matched", not as proof that nothing is exposed.

- Azure, Mistral and similar keys have no distinctive prefix. A key held in a variable with an unhelpful name is reported as Generic, or missed.
- Labels are best effort. `sk-` is also used by other vendors, `AKIA` keys are general AWS keys that may not have Bedrock access, and `AIza` keys are general Google keys.
- It misses low-entropy secrets, generic tokens without a digit, values containing a placeholder word such as `example`, UUID-shaped generic tokens, and UTF-16 files (treated as binary).
- It does not look at git history, only the current working tree of tracked files.
- It does not read `~/.aws/credentials`, OS keychains, cloud secret stores, or browser storage. Shell history is read only from the default file names, not a custom `$HISTFILE`.
- Generic hits can be false positives, such as a hash stored under a name containing `KEY`.
- Masked previews reveal the first 4 characters of a value. That is why they are opt-in; think before pasting `--verbose` output anywhere.
- It protects what it prints. It cannot stop other software from reading the same files.

Reading your files updates their access times on filesystems that track them. With `--repo`, git is the only subprocess started, and its output is discarded apart from the file list.

## Development

```sh
python -m unittest discover -s tests
```

Tests only use a temporary `HOME`, and build fake keys at runtime from split parts so that no key-shaped string exists in the repository.

## About

This tool is free to use on its own, and nothing it finds is sent to anyone.

[GreenKeel](https://greenkeel.dev) is an LLM gateway that runs in your own cloud. Real provider keys stay behind it, and each person, agent and pipeline gets its own scoped, expiring, capped key. To talk through what you find, [request a free 30-minute exposure call](https://greenkeel.dev/?topic=exposure-call#contact).

MIT licensed; see [LICENSE](LICENSE). GreenKeel is provided by TopDown Ltd. The MIT licence covers the code, not the GreenKeel name or logo.
