"""Tie locations, file reading and detection together."""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass, field

from . import files, locations
from .detect import detect, redact


@dataclass(frozen=True)
class Finding:
    location_type: str
    path: str
    provider: str
    preview: str


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    unreadable: int = 0
    binary: int = 0
    too_large: int = 0


def display_path(path: str, home: str | None) -> str:
    """Render a path safely: credential-like segments masked, control characters
    replaced so a crafted filename cannot drive the terminal."""
    absolute = os.path.abspath(path)
    if home and (absolute == home or absolute.startswith(home.rstrip(os.sep) + os.sep)):
        absolute = "~" + absolute[len(home.rstrip(os.sep)):]
    return "".join(ch if ch.isprintable() else "?" for ch in redact(absolute))


def _targets(path: str, repo: str | None, result: ScanResult) -> Iterator[tuple[str, str]]:
    def on_walk_error(exc: OSError) -> None:
        if not files.is_ignorable_error(exc):
            result.unreadable += 1

    yield from locations.targets_under_path(path, on_walk_error)
    home = locations.home_dir()
    if home is not None:
        yield from locations.targets_in_home(home, on_walk_error)
    if repo is not None:
        yield from locations.targets_in_repo(repo)


def run_scan(path: str, repo: str | None = None) -> ScanResult:
    result = ScanResult()
    home = locations.home_dir()
    home_text = str(home) if home is not None else None
    seen: set[tuple[str, object]] = set()

    for location_type, target in _targets(path, repo, result):
        identity = files.file_identity(target)
        if identity is None or (location_type, identity) in seen:
            continue
        seen.add((location_type, identity))

        status, text = files.read_candidate(target)
        if status is files.ReadStatus.UNREADABLE:
            result.unreadable += 1
        elif status is files.ReadStatus.BINARY:
            result.binary += 1
        elif status is files.ReadStatus.TOO_LARGE:
            result.too_large += 1
        elif status is files.ReadStatus.OK:
            result.files_scanned += 1
            digests: set[bytes] = set()
            shown = display_path(target, home_text)
            for hit in detect(text):
                if hit.digest not in digests:  # same secret, same location: count once
                    digests.add(hit.digest)
                    result.findings.append(Finding(location_type, shown, hit.provider, hit.preview))
    return result
