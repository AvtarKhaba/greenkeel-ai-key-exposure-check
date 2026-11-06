"""Command line entry point.

Error handling is deliberately terse. User-supplied values and exception
messages are never echoed, and no traceback is ever printed, because any of
them could carry a secret.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import NoReturn

from . import __version__
from .locations import RepoError
from .report import TOOL_NAME, render_json, render_table
from .scanner import run_scan

EXIT_OK = 0
EXIT_FOUND = 1
EXIT_ERROR = 2


class _QuietParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # argparse's message quotes the offending argument, which may be a key
        # pasted by mistake. Report the problem without repeating the value.
        self.exit(EXIT_ERROR, f"{TOOL_NAME}: error: invalid arguments (values are not echoed); see --help\n")


def _build_parser() -> argparse.ArgumentParser:
    parser = _QuietParser(
        prog=TOOL_NAME,
        allow_abbrev=False,
        description=(
            "Count candidate AI provider credentials on this machine. Local only: "
            "no network, no files written, secret values never printed."
        ),
    )
    parser.add_argument("--path", default=None, help="directory to search for .env and MCP files (default: cwd)")
    parser.add_argument("--repo", default=None, help="also scan the files tracked by git in this repository")
    parser.add_argument("--json", action="store_true", help="print JSON instead of a table")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help='also show masked previews (first 4 characters + "…"); off by default',
    )
    parser.add_argument("--fail-on-found", action="store_true", help="exit 1 if any candidate is found")
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    return parser


def _fail(message: str) -> int:
    print(f"{TOOL_NAME}: error: {message}", file=sys.stderr)
    return EXIT_ERROR


def _silent_excepthook(exc_type: type[BaseException], _exc: BaseException, _tb: object) -> None:
    sys.stderr.write(f"{TOOL_NAME}: error: internal error ({exc_type.__name__})\n")


def _make_output_encoding_safe() -> None:
    # On a non-UTF-8 terminal the mask character must not crash the report.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")


def _run(argv: list[str] | None) -> int:
    args = _build_parser().parse_args(argv)
    path = args.path if args.path is not None else os.getcwd()
    if not os.path.isdir(path):
        return _fail("--path is not a directory")
    if args.repo is not None and not os.path.isdir(args.repo):
        return _fail("--repo is not a directory")

    result = run_scan(path, args.repo)
    print(render_json(result, args.verbose) if args.json else render_table(result, args.verbose))
    sys.stdout.flush()  # surface a closed pipe here, not during interpreter shutdown
    return EXIT_FOUND if args.fail_on_found and result.findings else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    sys.excepthook = _silent_excepthook
    _make_output_encoding_safe()
    try:
        return _run(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_ERROR
    except RepoError as exc:
        return _fail(str(exc))
    except KeyboardInterrupt:
        return _fail("interrupted")
    except BrokenPipeError:
        # Reader went away (for example `| head`). Stop flush-at-exit complaining.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return EXIT_ERROR
    except BaseException as exc:  # noqa: BLE001 - the type name only, never the message
        return _fail(f"internal error ({type(exc).__name__})")
