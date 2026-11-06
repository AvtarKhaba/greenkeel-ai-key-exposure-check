"""Read-only file access. This module is the only place file contents are opened."""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Callable, Iterator
from enum import Enum

MAX_FILE_BYTES = 5 * 1024 * 1024
BINARY_SNIFF_BYTES = 8192

SKIP_DIRS = frozenset(
    {
        "node_modules", ".git", "venv", ".venv", "virtualenv", ".virtualenv",
        ".tox", ".nox", "site-packages", "__pycache__", ".mypy_cache",
        ".pytest_cache", "Cache", "cache", ".cache",
    }
)
_VENV_MARKERS = ("pyvenv.cfg", "conda-meta")
_IGNORED_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR, errno.ELOOP})


class ReadStatus(Enum):
    OK = "ok"
    IGNORED = "ignored"  # vanished, a dangling or looping symlink, or not a regular file
    UNREADABLE = "unreadable"
    BINARY = "binary"
    TOO_LARGE = "too_large"


def _open_readonly(path: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    return os.open(path, flags)


def read_candidate(path: str, max_bytes: int = MAX_FILE_BYTES) -> tuple[ReadStatus, str]:
    """Return (status, text); text is empty unless status is OK."""
    try:
        # O_NONBLOCK plus the regular-file check stops a FIFO hanging the scan.
        fd = _open_readonly(path)
    except OSError as exc:
        return (ReadStatus.IGNORED if exc.errno in _IGNORED_ERRNOS else ReadStatus.UNREADABLE), ""
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return ReadStatus.IGNORED, ""
        if info.st_size > max_bytes:
            return ReadStatus.TOO_LARGE, ""
        chunks = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError:
        return ReadStatus.UNREADABLE, ""
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > max_bytes:
        return ReadStatus.TOO_LARGE, ""
    if b"\0" in data[:BINARY_SNIFF_BYTES]:
        return ReadStatus.BINARY, ""
    return ReadStatus.OK, data.decode("utf-8", "replace")


def _skip_dir(parent: str, name: str) -> bool:
    if name in SKIP_DIRS:
        return True
    return any(os.path.exists(os.path.join(parent, name, marker)) for marker in _VENV_MARKERS)


def walk_files(root: str, on_error: Callable[[OSError], None]) -> Iterator[str]:
    """Yield files under ``root``. Symlinked directories are never followed, so
    a symlink loop cannot trap the walk."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=on_error):
        dirnames[:] = sorted(name for name in dirnames if not _skip_dir(dirpath, name))
        for name in sorted(filenames):
            yield os.path.join(dirpath, name)


def file_identity(path: str) -> tuple[int, int] | str | None:
    """Identity that survives symlinks, hard links and case-insensitive names.
    None means the file should be silently ignored."""
    try:
        info = os.stat(path)
    except OSError as exc:
        return None if exc.errno in _IGNORED_ERRNOS else os.path.abspath(path)
    return (info.st_dev, info.st_ino) if info.st_ino else os.path.realpath(path)


def is_ignorable_error(exc: OSError) -> bool:
    return exc.errno in _IGNORED_ERRNOS
