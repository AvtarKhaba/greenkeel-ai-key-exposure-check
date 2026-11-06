"""Credential detection.

Safety property: raw secret values stay inside ``detect``. A ``Hit`` carries a
masked preview and a keyed digest (the key is random per process and never
leaves it), so nothing downstream, including exception messages, can hold more
of a secret than ``PREVIEW_CHARS`` characters.
"""

from __future__ import annotations

import bisect
import hashlib
import hmac
import math
import re
import secrets
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache

ANTHROPIC = "Anthropic"
OPENAI = "OpenAI"
GOOGLE = "Google/Gemini"
AZURE = "Azure OpenAI"
AWS = "AWS Bedrock"
OPENROUTER = "OpenRouter"
MISTRAL = "Mistral"
GENERIC = "Generic"

PREVIEW_CHARS = 4
MASK_SUFFIX = "…"

MIN_VALUE_LEN = 20
MAX_VALUE_LEN = 4096
MIN_ENTROPY_NAMED = 3.0
MIN_ENTROPY_GENERIC = 3.5

_DIGEST_KEY = secrets.token_bytes(32)


def mask(value: str) -> str:
    """Return the only form of a secret allowed to leave this module."""
    return value[:PREVIEW_CHARS] + MASK_SUFFIX


@dataclass(frozen=True)
class Hit:
    provider: str
    preview: str
    digest: bytes
    start: int
    end: int


def _hit(provider: str, value: str, start: int, end: int) -> Hit:
    digest = hmac.new(_DIGEST_KEY, value.encode("utf-8", "replace"), hashlib.sha256).digest()
    return Hit(provider, mask(value), digest, start, end)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in Counter(value).values())


# Providers with a distinctive prefix. Order matters only for readability: the
# OpenAI pattern explicitly excludes the Anthropic and OpenRouter prefixes.
_TOKEN_START = r"(?<![A-Za-z0-9_-])"
_PREFIX_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (ANTHROPIC, re.compile(_TOKEN_START + r"sk-ant-[A-Za-z0-9_-]{20,}")),
    (OPENROUTER, re.compile(_TOKEN_START + r"sk-or-[A-Za-z0-9_-]{20,}")),
    (OPENAI, re.compile(_TOKEN_START + r"sk-(?!ant-|or-)[A-Za-z0-9_-]{20,}")),
    (GOOGLE, re.compile(_TOKEN_START + r"AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])")),
    (AWS, re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])")),
    (AWS, re.compile(r"(?<![A-Za-z0-9+/=])ABSK[A-Za-z0-9+/=]{20,}")),
    (AWS, re.compile(_TOKEN_START + r"bedrock-api-key-[A-Za-z0-9+/=_.%-]{20,}")),
)

# Name and separator only. The value is matched separately from the end of the
# separator, so finditer rescans the value and "env:API_KEY=x" finds API_KEY.
# Lookbehinds restrict attempts to token starts, keeping long lines linear.
_ASSIGN_RE = re.compile(
    r"(?<![A-Za-z0-9_.\-])"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_.\-]{0,127})"
    r"[\\\"'\]]*[ \t]*(?:=>|:=|=|:)[ \t]*(?:[Bb]earer[ \t]+)?"
)
_FISH_SET_RE = re.compile(
    r"(?<![A-Za-z0-9_\-])set[ \t]+(?:-[A-Za-z\-]+[ \t]+)*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]{0,127})[ \t]+"
)
_FLAG_RE = re.compile(
    r"(?<![A-Za-z0-9_\-])--?(?P<name>[A-Za-z][A-Za-z0-9\-]{0,63})"
    r"(?:[ \t]*=[ \t]*|[ \t]+|[\\\"']*[ \t]*,[ \t]*)"
)
_BEARER_RE = re.compile(r"(?<![A-Za-z0-9_\-])[Bb]earer[ \t]+")
_BEARER_NAME = "BEARER_TOKEN"

_VALUE_RE = re.compile(r"[\\\"'`]*(?P<value>[A-Za-z0-9_\-+/=.:~]{1,%d})" % MAX_VALUE_LEN)

_DENIED_NAME_PARTS = (
    "MONKEY", "DONKEY", "TURKEY", "HOCKEY", "KEYBOARD", "KEYWORD", "KEYFRAME",
    "KEYSPACE", "KEYRING", "KEYCHAIN", "TOKENIZ", "MAX_TOKENS", "MAXTOKENS",
    "PUBLIC_KEY", "PUBLICKEY", "PUBKEY", "PRIMARY_KEY", "FOREIGN_KEY",
    "SORT_KEY", "PARTITION_KEY", "CACHE_KEY",
)
_DENIED_NAME_SUFFIXES = (
    "TOKENS", "_PATH", "_FILE", "_DIR", "_URL", "_URI", "_NAME", "_ENV",
    "_HEADER", "_LIMIT", "_COUNT", "_TTL", "_EXPIRY", "_TYPE",
)
_NOT_GENERIC_NAME_PARTS = ("PUBLIC", "PUBLISHABLE")


@lru_cache(maxsize=4096)
def classify_name(name: str) -> str | None:
    """Map a variable name to a provider, or None if it is not credential-like."""
    upper = name.upper().replace("-", "_").replace(".", "_")
    if not any(word in upper for word in ("KEY", "TOKEN", "SECRET")):
        return None
    if any(part in upper for part in _DENIED_NAME_PARTS):
        return None
    if upper.endswith(_DENIED_NAME_SUFFIXES):
        return None

    if "OPENROUTER" in upper:
        return OPENROUTER
    if "AOAI" in upper or ("AZURE" in upper and ("OPENAI" in upper or "API_KEY" in upper)):
        return AZURE
    if "OPENAI" in upper:
        return OPENAI
    if "ANTHROPIC" in upper or "CLAUDE" in upper:
        return ANTHROPIC
    if "MISTRAL" in upper:
        return MISTRAL
    if "GEMINI" in upper or "GENAI" in upper or (
        "GOOGLE" in upper and ("API" in upper or "AI_" in upper or "GENERATIVE" in upper)
    ):
        return GOOGLE
    if "BEDROCK" in upper or "SECRET_ACCESS_KEY" in upper or (
        "AWS" in upper and ("ACCESS_KEY" in upper or "SESSION_TOKEN" in upper)
    ):
        return AWS
    if any(part in upper for part in _NOT_GENERIC_NAME_PARTS):
        return None
    return GENERIC


_PLACEHOLDER_WORDS = (
    "your", "example", "placeholder", "changeme", "change_me", "change-me",
    "replace", "insert", "redacted", "dummy", "sample", "xxxx", "fake", "todo",
    "1234567", "abcdefgh",
)
_REPEATED_RUN_RE = re.compile(r"(.)\1{4,}")
_DOTTED_IDENTIFIER_RE = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_NON_SECRET_PREFIXES = ("/", "./", "../", "~/", "=", "arn:", "sha1-", "sha256-", "sha384-", "sha512-")
_FILE_SUFFIXES = (".pem", ".json", ".key", ".txt", ".yaml", ".yml", ".toml", ".env", ".crt")


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(word in lowered for word in _PLACEHOLDER_WORDS) or bool(_REPEATED_RUN_RE.search(value))


def _prefixed_token_is_plausible(token: str) -> bool:
    return (
        any(ch.isdigit() for ch in token)
        and not _looks_like_placeholder(token)
        and shannon_entropy(token) >= MIN_ENTROPY_NAMED
    )


def _named_value_is_plausible(value: str, provider: str) -> bool:
    if len(value) < MIN_VALUE_LEN or value.startswith(_NON_SECRET_PREFIXES) or "://" in value:
        return False
    if value.lower().endswith(_FILE_SUFFIXES) or _looks_like_placeholder(value):
        return False
    if _DOTTED_IDENTIFIER_RE.match(value) and not value.startswith("eyJ"):
        return False
    if provider != GENERIC:
        return shannon_entropy(value) >= MIN_ENTROPY_NAMED
    return (
        shannon_entropy(value) >= MIN_ENTROPY_GENERIC
        and any(ch.isdigit() for ch in value)
        and not _UUID_RE.match(value)
    )


def detect(text: str) -> list[Hit]:
    """Return candidate credentials in ``text``, strongest evidence first."""
    hits: list[Hit] = []
    taken: list[tuple[int, int]] = []

    for provider, pattern in _PREFIX_PATTERNS:
        for match in pattern.finditer(text):
            # Rejected tokens still claim their span, so a placeholder such as
            # a prefix followed by filler is not re-reported by the name rules.
            taken.append(match.span())
            if _prefixed_token_is_plausible(match.group()):
                hits.append(_hit(provider, match.group(), *match.span()))
    taken.sort()
    starts = [span[0] for span in taken]

    def overlaps_prefix_token(start: int, end: int) -> bool:
        index = bisect.bisect_right(starts, start)
        return (index > 0 and taken[index - 1][1] > start) or (index < len(starts) and starts[index] < end)

    def named(provider: str, end_of_separator: int) -> None:
        value_match = _VALUE_RE.match(text, end_of_separator)
        if value_match is None:
            return
        value = value_match.group("value")
        start = value_match.start("value")
        end = value_match.end("value")
        if text[end:end + 1] == "(":  # a function call, not a literal
            return
        stripped = value.rstrip(".:")
        end -= len(value) - len(stripped)
        if not overlaps_prefix_token(start, end) and _named_value_is_plausible(stripped, provider):
            hits.append(_hit(provider, stripped, start, end))

    for pattern in (_ASSIGN_RE, _FISH_SET_RE, _FLAG_RE):
        for match in pattern.finditer(text):
            provider = classify_name(match.group("name"))
            if provider is not None:
                named(provider, match.end())

    bearer_provider = classify_name(_BEARER_NAME)
    for match in _BEARER_RE.finditer(text):
        named(bearer_provider, match.end())

    return hits


def redact(text: str) -> str:
    """Mask anything credential-like in free text such as a file path."""
    hits = sorted(detect(text), key=lambda hit: hit.start, reverse=True)
    last_start = len(text) + 1
    for hit in hits:
        if hit.end <= last_start:
            text = text[: hit.start] + hit.preview + text[hit.end :]
            last_start = hit.start
    return text
