"""Render a ScanResult. Input is findings only, which never hold raw secrets."""

from __future__ import annotations

import json
from collections import Counter

from . import __version__
from .locations import LOCATION_LABELS
from .scanner import ScanResult

TOOL_NAME = "ai-key-exposure-check"


def _rows(result: ScanResult) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str, str], list[str]] = {}
    for finding in result.findings:
        key = (finding.location_type, finding.path, finding.provider)
        grouped.setdefault(key, []).append(finding.preview)
    return [
        {
            "location_type": location_type,
            "path": path,
            "provider": provider,
            "count": len(previews),
            "previews": sorted(previews),
        }
        for (location_type, path, provider), previews in sorted(grouped.items())
    ]


def verdict(result: ScanResult) -> str:
    total = len(result.findings)
    if total == 0:
        return "Verdict: no candidate AI credentials found in the locations scanned (this does not prove there are none)."
    locations = len({(f.location_type, f.path) for f in result.findings})
    noun = "credential" if total == 1 else "credentials"
    places = "location" if locations == 1 else "locations"
    return f"Verdict: {total} candidate {noun} in {locations} {places}; this tool cannot tell whether any key is live."


def _skipped_line(result: ScanResult) -> str:
    return (
        f"Scanned {result.files_scanned} files. Skipped: {result.unreadable} unreadable, "
        f"{result.binary} binary, {result.too_large} too large."
    )


def render_table(result: ScanResult, verbose: bool = False) -> str:
    headers = ["Location", "Path", "Provider", "Count"] + (["Preview"] if verbose else [])
    table = []
    for row in _rows(result):
        cells = [LOCATION_LABELS[row["location_type"]], row["path"], row["provider"], str(row["count"])]
        if verbose:
            cells.append(", ".join(row["previews"]))
        table.append(cells)

    lines = []
    if table:
        widths = [max(len(r[i]) for r in [headers] + table) for i in range(len(headers))]
        def fmt(cells: list[str]) -> str:
            return "  ".join(c.ljust(w) for c, w in zip(cells, widths)).rstrip()
        lines.append(fmt(headers))
        lines.append("  ".join("-" * w for w in widths))
        lines.extend(fmt(cells) for cells in table)
        lines.append("")
    lines.append(_skipped_line(result))
    lines.append(verdict(result))
    return "\n".join(lines)


def render_json(result: ScanResult, verbose: bool = False) -> str:
    rows = _rows(result)
    if not verbose:
        for row in rows:
            del row["previews"]
    by_location = Counter(f.location_type for f in result.findings)
    by_provider = Counter(f.provider for f in result.findings)
    payload = {
        "tool": TOOL_NAME,
        "version": __version__,
        "total_candidates": len(result.findings),
        "by_location_type": dict(sorted(by_location.items())),
        "by_provider": dict(sorted(by_provider.items())),
        "rows": rows,
        "files_scanned": result.files_scanned,
        "skipped": {
            "unreadable": result.unreadable,
            "binary": result.binary,
            "too_large": result.too_large,
        },
        "verdict": verdict(result),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
