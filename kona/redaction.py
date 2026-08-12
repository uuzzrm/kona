"""Small, conservative secret redaction helpers used before anything is persisted."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable, Sequence


REDACTED = "[REDACTED]"


@dataclass(frozen=True)
class RedactionResult:
    text: str
    count: int


# These patterns intentionally target recognizable credential shapes. Kona does not
# attempt to classify arbitrary user data as a secret.
_KEY_VALUE = re.compile(
    r"(?i)(\b(?:api[_-]?key|access[_-]?token|auth(?:orization)?|password|passwd|private[_-]?key|secret|token)\b\s*[:=]\s*)((?:Bearer\s+)?[^\s,;&]+)"
)
_BEARER = re.compile(r"(?i)(\bBearer\s+)([A-Za-z0-9._~+/=-]+)")
_KNOWN_TOKEN = re.compile(
    r"(?x)"
    r"(?:"
    r"sk-[A-Za-z0-9_-]{16,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|gh[pousr]_[A-Za-z0-9_]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|AKIA[0-9A-Z]{16}"
    r")"
)
_SENSITIVE_FLAGS = {
    "--access-token",
    "--api-key",
    "--auth-token",
    "--authorization",
    "--client-secret",
    "--password",
    "--passwd",
    "--secret",
    "--token",
}


def _replace_group(match: re.Match[str]) -> str:
    return f"{match.group(1)}{REDACTED}"


def redact_text(value: str) -> RedactionResult:
    """Return *value* with common credential forms replaced.

    Redaction is deliberately applied to command displays and captured streams,
    never to a process environment or to the command that is actually executed.
    """

    total = 0

    value, count = _KEY_VALUE.subn(_replace_group, value)
    total += count
    value, count = _BEARER.subn(_replace_group, value)
    total += count
    value, count = _KNOWN_TOKEN.subn(REDACTED, value)
    total += count
    return RedactionResult(value, total)


def redact_argv(argv: Sequence[str]) -> tuple[list[str], int]:
    """Redact each argument and return the safe display argv plus replacement count."""

    safe: list[str] = []
    total = 0
    redact_next = False
    for argument in argv:
        if redact_next:
            safe.append(REDACTED)
            total += 1
            redact_next = False
            continue
        result = redact_text(argument)
        safe.append(result.text)
        total += result.count
        if argument.casefold() in _SENSITIVE_FLAGS:
            redact_next = True
    return safe, total


def redact_lines(lines: Iterable[str]) -> tuple[list[str], int]:
    """Redact a finite iterable of lines, primarily useful to callers and tests."""

    redacted: list[str] = []
    total = 0
    for line in lines:
        result = redact_text(line)
        redacted.append(result.text)
        total += result.count
    return redacted, total
