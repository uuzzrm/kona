"""Deterministic, privacy-minimal finding baselines for CI adoption."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import stat
from typing import Any


BASELINE_SCHEMA = "kona.baseline/v1"
_MAX_BASELINE_BYTES = 4 * 1024 * 1024
_MAX_BASELINE_ENTRIES = 100_000
_FINGERPRINT = re.compile(r"sha256:[0-9a-fA-F]{64}\Z")
_RULE_ID = re.compile(r"[A-Z]{3}[0-9]{3}\Z")
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


class BaselineError(ValueError):
    """Raised when a baseline cannot be trusted or safely written."""


@dataclass(frozen=True)
class Baseline:
    """The validated fingerprint set used to suppress known findings."""

    fingerprints: frozenset[str]


def _validate_entry(entry: Any, index: int) -> tuple[str, str, str]:
    if not isinstance(entry, dict) or set(entry) != {"fingerprint", "rule_id", "severity"}:
        raise BaselineError(f"baseline finding {index} must contain only fingerprint, rule_id, and severity")
    fingerprint = entry["fingerprint"]
    rule_id = entry["rule_id"]
    severity = entry["severity"]
    if not isinstance(fingerprint, str) or not _FINGERPRINT.fullmatch(fingerprint):
        raise BaselineError(f"baseline finding {index} has an invalid fingerprint")
    if not isinstance(rule_id, str) or not _RULE_ID.fullmatch(rule_id):
        raise BaselineError(f"baseline finding {index} has an invalid rule ID")
    if not isinstance(severity, str) or severity not in _SEVERITIES:
        raise BaselineError(f"baseline finding {index} has an invalid severity")
    return fingerprint, rule_id, severity


def _parse(payload: Any) -> Baseline:
    if not isinstance(payload, dict) or set(payload) != {"schema", "tool", "findings"}:
        raise BaselineError("baseline must contain exactly schema, tool, and findings")
    if payload["schema"] != BASELINE_SCHEMA:
        raise BaselineError(f"unsupported baseline schema: {payload.get('schema')!r}")
    if payload["tool"] != {"name": "kona"}:
        raise BaselineError("baseline tool metadata is invalid")
    findings = payload["findings"]
    if not isinstance(findings, list):
        raise BaselineError("baseline findings must be an array")
    if len(findings) > _MAX_BASELINE_ENTRIES:
        raise BaselineError(f"baseline exceeds entry limit: {_MAX_BASELINE_ENTRIES}")
    fingerprints: set[str] = set()
    for index, entry in enumerate(findings):
        fingerprint, _rule_id, _severity = _validate_entry(entry, index)
        if fingerprint in fingerprints:
            raise BaselineError(f"baseline contains duplicate fingerprint at entry {index}")
        fingerprints.add(fingerprint)
    return Baseline(frozenset(fingerprints))


def _read(path: Path) -> bytes:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise BaselineError(f"refusing to read symlinked baseline: {path}")
    try:
        before = candidate.stat(follow_symlinks=False)
    except OSError as error:
        raise BaselineError(f"could not inspect baseline: {path}") from error
    if not stat.S_ISREG(before.st_mode):
        raise BaselineError(f"baseline must be a regular file: {path}")
    if before.st_size > _MAX_BASELINE_BYTES:
        raise BaselineError(f"baseline exceeds size limit: {_MAX_BASELINE_BYTES}")
    try:
        with candidate.open("rb") as handle:
            data = handle.read(_MAX_BASELINE_BYTES + 1)
        after = candidate.stat(follow_symlinks=False)
    except OSError as error:
        raise BaselineError(f"could not read baseline: {path}") from error
    if len(data) > _MAX_BASELINE_BYTES or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise BaselineError(f"baseline changed during read: {path}")
    return data


def load_baseline(path: Path) -> Baseline:
    """Load and strictly validate one local baseline without network access."""

    try:
        payload = json.loads(_read(path).decode("utf-8"))
    except UnicodeDecodeError as error:
        raise BaselineError(f"baseline is not valid UTF-8: {path}") from error
    except json.JSONDecodeError as error:
        raise BaselineError(f"baseline is not valid JSON: {path}") from error
    return _parse(payload)


def write_baseline(report: dict[str, Any], path: Path) -> int:
    """Write a deterministic, non-overwriting baseline from raw findings."""

    candidate = path.expanduser()
    if candidate.exists() or candidate.is_symlink():
        raise BaselineError(f"refusing to overwrite baseline: {path}")
    findings = report.get("findings")
    if not isinstance(findings, list) or len(findings) > _MAX_BASELINE_ENTRIES:
        raise BaselineError("scan report findings cannot produce a baseline")
    entries: list[dict[str, str]] = []
    fingerprints: set[str] = set()
    for index, finding in enumerate(findings):
        fingerprint, rule_id, severity = _validate_entry(
            {
                "fingerprint": finding.get("fingerprint") if isinstance(finding, dict) else None,
                "rule_id": finding.get("rule_id") if isinstance(finding, dict) else None,
                "severity": finding.get("severity") if isinstance(finding, dict) else None,
            },
            index,
        )
        if fingerprint in fingerprints:
            raise BaselineError(f"scan report contains duplicate fingerprint at entry {index}")
        fingerprints.add(fingerprint)
        entries.append({"fingerprint": fingerprint, "rule_id": rule_id, "severity": severity})
    entries.sort(key=lambda item: item["fingerprint"])
    payload = {
        "schema": BASELINE_SCHEMA,
        "tool": {"name": "kona"},
        "findings": entries,
    }
    candidate.parent.mkdir(parents=True, exist_ok=True)
    try:
        with candidate.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
    except FileExistsError as error:
        raise BaselineError(f"refusing to overwrite baseline: {path}") from error
    except OSError as error:
        raise BaselineError(f"could not write baseline: {path}") from error
    return len(entries)


def apply_baseline(report: dict[str, Any], baseline: Baseline) -> dict[str, Any]:
    """Return a report where only fingerprints absent from the baseline remain active."""

    findings = report.get("findings")
    if not isinstance(findings, list):
        raise BaselineError("scan report findings must be an array")
    active: list[dict[str, Any]] = []
    matched: set[str] = set()
    for finding in findings:
        fingerprint = finding.get("fingerprint") if isinstance(finding, dict) else None
        if isinstance(fingerprint, str) and fingerprint in baseline.fingerprints:
            matched.add(fingerprint)
        else:
            active.append(finding)
    counts = {severity: 0 for severity in _SEVERITIES}
    for finding in active:
        severity = finding.get("severity") if isinstance(finding, dict) else None
        if severity in counts:
            counts[severity] += 1
    summary = dict(report.get("summary", {}))
    summary.update(
        {
            **counts,
            "total": len(active),
            "verdict": "attention" if active else "no-enabled-rule-findings",
            "baseline_suppressed": len(matched),
            "baseline_unmatched": len(baseline.fingerprints - matched),
        }
    )
    limitations = list(report.get("limitations", []))
    limitations.append("An explicitly supplied baseline suppresses only matching finding fingerprints; unmatched baseline entries are reported as stale.")
    return {
        **report,
        "findings": active,
        "summary": summary,
        "baseline": {
            "schema": BASELINE_SCHEMA,
            "applied": True,
            "entries": len(baseline.fingerprints),
            "suppressed": len(matched),
            "unmatched": len(baseline.fingerprints - matched),
        },
        "limitations": limitations,
    }
