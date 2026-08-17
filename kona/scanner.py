"""Bounded, offline repository trust scanning for AI coding projects."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any
from urllib.parse import quote

from . import __version__
from .redaction import redact_text


class ScanError(ValueError):
    """Raised when a trustworthy complete scan cannot be produced."""


@dataclass(frozen=True)
class ScanPolicy:
    max_entries: int = 20_000
    max_file_bytes: int = 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    max_depth: int = 40


_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "target", "coverage", "__pycache__"}
_SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_KNOWN_TOKEN = re.compile(r"(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,})")
_ASSIGNMENT = re.compile(r"(?i)^\s*(?:export\s+)?['\"]?(api[_-]?key|access[_-]?token|password|passwd|private[_-]?key|secret|token)['\"]?\s*[:=]\s*['\"]?([^'\"\s#]{12,})")
_PLACEHOLDER = re.compile(r"(?i)^(?:example|dummy|changeme|replace[-_]?me|test|placeholder|your[-_]|\[redacted\]|<[^>]+>|\$\{[^}]+\})")
_USES = re.compile(r"\buses\s*:\s*['\"]?([^\s'\"]+)['\"]?")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")

_SARIF_RULES: dict[str, tuple[str, str, str]] = {
    "SEC001": ("Private key material", "A private-key PEM header is present.", "Revoke and remove the private key from the repository and its history."),
    "SEC002": ("Provider credential", "A provider-specific credential shape is present.", "Revoke the credential and load its replacement from a secret store."),
    "SEC003": ("Hard-coded credential assignment", "A sensitive variable is assigned a non-placeholder value.", "Move the value to an environment variable or secret store and rotate it."),
    "CFG001": ("Broad workflow write permission", "The workflow requests write-all permissions.", "Declare only the minimum required permissions."),
    "CFG002": ("Privileged pull request trigger", "pull_request_target runs in the base repository security context.", "Avoid executing pull-request-controlled content in this workflow."),
    "CFG003": ("Mutable Action reference", "A third-party Action is not pinned to a full commit SHA.", "Pin the Action to a reviewed 40-character commit SHA."),
    "AGT001": ("Instruction exposes credentials", "An Agent instruction requests handling credentials through an unsafe side effect.", "Remove the instruction and keep credentials outside Agent-visible outputs."),
    "AGT002": ("Instruction bypasses a safeguard", "An Agent instruction requests bypassing a verification or security control.", "Require the control and document any narrowly scoped exception."),
    "DEP001": ("Dependency lockfile missing", "A dependency-bearing project has no nearby recognized lockfile.", "Commit the lockfile used by this package root."),
    "DEP002": ("Floating remote dependency", "A remote Python dependency is not pinned to an immutable revision.", "Pin the dependency to an immutable commit and verify its integrity."),
}


def _is_reparse_point(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _safe_preview(line: str, start: int, end: int) -> str:
    value = line[:start] + "[REDACTED]" + line[end:]
    value = "".join(character if character.isprintable() else "?" for character in value.strip())
    return value[:160]


def _looks_placeholder(value: str) -> bool:
    normalized = value.strip()
    return bool(_PLACEHOLDER.match(normalized)) or (len(normalized) >= 12 and len(set(normalized.casefold())) == 1)


def _read_regular_file(path: Path, relative: str, limit: int) -> tuple[bytes, os.stat_result]:
    """Open one file without following a final-component link, then validate its handle."""

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if os.name != "nt" and not no_follow:
        raise ScanError("this platform cannot safely open repository files without following links")
    try:
        descriptor = os.open(path, flags | no_follow)
    except OSError as error:
        raise ScanError(f"could not safely open repository file: {relative}") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _is_reparse_point(opened):
            raise ScanError(f"unsafe link or special file prevents a complete scan: {relative}")
        if opened.st_size > limit:
            raise ScanError(f"repository file exceeds scan size limit: {relative}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(limit + 1)
        if len(data) > limit:
            raise ScanError(f"repository file exceeds scan size limit: {relative}")
        return data, opened
    finally:
        os.close(descriptor)


def _finding(rule_id: str, severity: str, category: str, title: str, message: str, path: str, line: int, preview: str, remediation: str) -> dict[str, Any]:
    fingerprint = hashlib.sha256(f"{rule_id}\0{path}\0{line}\0{title}".encode()).hexdigest()
    preview = redact_text(preview).text
    return {
        "id": f"sha256:{fingerprint}", "rule_id": rule_id, "severity": severity,
        "confidence": "high", "category": category, "title": title, "message": message,
        "location": {"path": path, "line": line},
        "evidence": {"preview": preview[:160], "redacted": "[REDACTED]" in preview},
        "remediation": remediation, "fingerprint": f"sha256:{fingerprint}",
    }


def _scan_text(relative: str, text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    workflow = relative.startswith(".github/workflows/") and relative.rsplit(".", 1)[-1].lower() in {"yml", "yaml"}
    instruction = Path(relative).name.upper() in {"AGENTS.MD", "CLAUDE.MD", "CODEX.MD"}
    for number, line in enumerate(text.splitlines(), 1):
        code_line = line.split("#", 1)[0] if workflow else line
        token_spans: list[tuple[int, int]] = []
        private = _PRIVATE_KEY.search(line)
        if private:
            findings.append(_finding("SEC001", "critical", "secret", "Private key material", "A private-key PEM header is present.", relative, number, _safe_preview(line, private.start(), private.end()), "Revoke and remove the private key from the repository and its history."))
        for match in _KNOWN_TOKEN.finditer(line):
            if not _looks_placeholder(match.group(0)[3:] if match.group(0).startswith("sk-") else match.group(0)):
                token_spans.append(match.span())
                findings.append(_finding("SEC002", "high", "secret", "Provider credential", "A provider-specific credential shape is present.", relative, number, _safe_preview(line, match.start(), match.end()), "Revoke the credential and load its replacement from a secret store."))
        for match in _ASSIGNMENT.finditer(line):
            value_span = match.span(2)
            if not _looks_placeholder(match.group(2)) and not any(start <= value_span[0] and value_span[1] <= end for start, end in token_spans):
                findings.append(_finding("SEC003", "high", "secret", "Hard-coded credential assignment", "A sensitive variable is assigned a non-placeholder value.", relative, number, _safe_preview(line, match.start(2), match.end(2)), "Move the value to an environment variable or secret store and rotate it."))
        if workflow:
            if re.search(r"\bpermissions\s*:\s*write-all\b", code_line, re.I):
                findings.append(_finding("CFG001", "high", "github-actions", "Broad workflow write permission", "The workflow requests write-all permissions.", relative, number, line.strip(), "Declare only the minimum required permissions."))
            if re.search(r"\bpull_request_target\s*:", code_line):
                findings.append(_finding("CFG002", "medium", "github-actions", "Privileged pull request trigger", "pull_request_target runs in the base repository security context.", relative, number, line.strip(), "Avoid executing pull-request-controlled content in this workflow."))
            used = _USES.search(code_line)
            released_self_smoke = relative == ".github/workflows/released-action-smoke.yml" and used and used.group(1) == "uuzzrm/kona@v0"
            if used and not released_self_smoke and not used.group(1).startswith(("./", "docker://")) and "@" in used.group(1):
                reference = used.group(1).rsplit("@", 1)[1]
                if not re.fullmatch(r"[0-9a-fA-F]{40}", reference):
                    findings.append(_finding("CFG003", "medium", "github-actions", "Mutable Action reference", "A third-party Action is not pinned to a full commit SHA.", relative, number, used.group(1), "Pin the Action to a reviewed 40-character commit SHA."))
        if instruction:
            lowered = line.casefold()
            unsafe_secret_action = re.search(r"\b(read|print|send|upload|commit|transmit|expose)\b.*\b(secret|token|password|api key|credential)", lowered)
            negated_secret_action = re.search(r"\b(?:do not|don't|never|must not|should not)\b.{0,32}\b(?:read|print|send|upload|commit|transmit|expose)\b", lowered)
            if unsafe_secret_action and not negated_secret_action:
                findings.append(_finding("AGT001", "high", "agent-instruction", "Instruction exposes credentials", "An Agent instruction requests handling credentials through an unsafe side effect.", relative, number, "[REDACTED INSTRUCTION]", "Remove the instruction and keep credentials outside Agent-visible outputs."))
            if re.search(r"\b(skip|disable|bypass|evade)\b.*\b(test|review|security|permission|protection|verification)", lowered):
                negated_bypass = re.search(r"\b(?:do not|don't|never|must not|should not)\b.{0,32}\b(?:skip|disable|bypass|evade)\b", lowered)
                if not negated_bypass:
                    findings.append(_finding("AGT002", "medium", "agent-instruction", "Instruction bypasses a safeguard", "An Agent instruction requests bypassing a verification or security control.", relative, number, "[REDACTED INSTRUCTION]", "Require the control and document any narrowly scoped exception."))
    if relative.endswith(("requirements.txt", "requirements-dev.txt")):
        for number, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            remote = re.search(r"(?i)(git\+https?://|https?://)", stripped)
            git_pinned = bool(re.search(r"(?i)git\+https?://[^\s]+@[0-9a-f]{40}(?:#|\s|$)", stripped))
            hash_pinned = "--hash=sha256:" in stripped.casefold()
            if stripped and not stripped.startswith("#") and remote and not git_pinned and not hash_pinned:
                findings.append(_finding("DEP002", "medium", "dependency", "Floating remote dependency", "A remote Python dependency is not pinned to an immutable revision.", relative, number, "[REDACTED REMOTE REQUIREMENT]", "Pin the dependency to an immutable commit and verify its integrity."))
    return findings


def scan_repository(root: Path, policy: ScanPolicy = ScanPolicy()) -> dict[str, Any]:
    candidate = root.expanduser()
    if candidate.is_symlink() or not candidate.is_dir():
        raise ScanError("scan root must be a real directory and cannot be a symlink")
    absolute = candidate.resolve()
    logical_target = "." if candidate == Path(".") else candidate.name
    if min(policy.max_entries, policy.max_file_bytes, policy.max_total_bytes, policy.max_depth) < 1:
        raise ScanError("scan limits must be positive")
    entries = files = total = 0
    findings: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    package_roots: set[str] = set()
    lock_roots: set[str] = set()
    python_roots: set[str] = set()
    python_lock_roots: set[str] = set()
    def traversal_error(error: OSError) -> None:
        raise ScanError(f"could not traverse repository: {error.filename or 'unknown path'}")
    for current, dirs, names in os.walk(absolute, topdown=True, followlinks=False, onerror=traversal_error):
        base = Path(current)
        depth = len(base.relative_to(absolute).parts)
        if depth > policy.max_depth:
            raise ScanError(f"repository exceeds scan depth limit: {policy.max_depth}")
        kept: list[str] = []
        for name in sorted(dirs):
            child = base / name
            relative = child.relative_to(absolute).as_posix()
            entries += 1
            if entries > policy.max_entries:
                raise ScanError(f"repository exceeds scan entry limit: {policy.max_entries}")
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as error:
                raise ScanError(f"could not inspect repository entry: {relative}") from error
            if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
                raise ScanError(f"unsafe link or reparse point prevents a complete scan: {relative}")
            elif name in _SKIP_DIRS or relative.startswith(".kona/runs"):
                skipped.append({"path": relative, "reason": "generated-directory"})
            else:
                kept.append(name)
        dirs[:] = kept
        for name in sorted(names):
            child = base / name
            relative = child.relative_to(absolute).as_posix()
            entries += 1
            if entries > policy.max_entries:
                raise ScanError(f"repository exceeds scan entry limit: {policy.max_entries}")
            try:
                before = child.stat(follow_symlinks=False)
                if stat.S_ISLNK(before.st_mode) or _is_reparse_point(before):
                    raise ScanError(f"unsafe link or reparse point prevents a complete scan: {relative}")
                if not stat.S_ISREG(before.st_mode):
                    raise ScanError(f"special file prevents a complete scan: {relative}")
                if before.st_size > policy.max_file_bytes:
                    raise ScanError(f"repository file exceeds scan size limit: {relative}")
                data, opened = _read_regular_file(child, relative, policy.max_file_bytes)
                after = child.stat(follow_symlinks=False)
            except OSError as error:
                raise ScanError(f"could not read repository file: {relative}") from error
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise ScanError(f"repository file changed during scan: {relative}")
            total += len(data)
            if total > policy.max_total_bytes:
                raise ScanError(f"repository exceeds scan byte limit: {policy.max_total_bytes}")
            files += 1
            if name == "package.json":
                package_roots.add(str(Path(relative).parent).replace("\\", "/"))
            if name in {"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"}:
                lock_roots.add(str(Path(relative).parent).replace("\\", "/"))
            if name == "pyproject.toml" and re.search(rb"(?m)^\s*dependencies\s*=\s*\[", data):
                python_roots.add(str(Path(relative).parent).replace("\\", "/"))
            if name in {"uv.lock", "poetry.lock", "Pipfile.lock"}:
                python_lock_roots.add(str(Path(relative).parent).replace("\\", "/"))
            if b"\x00" in data[:8192]:
                skipped.append({"path": relative, "reason": "binary"}); continue
            findings.extend(_scan_text(relative, data.decode("utf-8-sig", errors="replace")))
    def has_lock_at_or_above(package_root: str, roots: set[str]) -> bool:
        current = Path(package_root)
        return any(str(parent).replace("\\", "/") in roots for parent in (current, *current.parents))
    for package_root in sorted(root for root in package_roots if not has_lock_at_or_above(root, lock_roots)):
        path = "package.json" if package_root == "." else f"{package_root}/package.json"
        findings.append(_finding("DEP001", "medium", "dependency", "Node lockfile missing", "A package manifest has no nearby recognized lockfile.", path, 1, path, "Commit the package manager lockfile used by this package root."))
    for package_root in sorted(root for root in python_roots if not has_lock_at_or_above(root, python_lock_roots)):
        path = "pyproject.toml" if package_root == "." else f"{package_root}/pyproject.toml"
        findings.append(_finding("DEP001", "medium", "dependency", "Python lockfile missing", "A Python project manifest has no nearby recognized lockfile.", path, 1, path, "Commit the lockfile used by this Python package root."))
    findings.sort(key=lambda item: (-_SEVERITY[item["severity"]], item["location"]["path"], item["location"]["line"], item["rule_id"]))
    summary = {severity: sum(item["severity"] == severity for item in findings) for severity in _SEVERITY}
    return {"schema": "kona.findings/v1", "tool": {"name": "kona", "version": __version__, "mode": "deterministic"}, "scan": {"target": logical_target, "complete": True, "offline": True, "read_only": True, "authenticated": False, "files_examined": files, "bytes_read": total, "entries_examined": entries, "limits": {"max_entries": policy.max_entries, "max_file_bytes": policy.max_file_bytes, "max_total_bytes": policy.max_total_bytes, "max_depth": policy.max_depth}, "skipped": sorted(skipped, key=lambda item: (item["path"], item["reason"]))}, "findings": findings, "summary": {**summary, "total": len(findings), "verdict": "attention" if findings else "no-enabled-rule-findings"}, "limitations": ["A clean result means only that enabled deterministic rules found no issue in a complete scan.", "Generated directories and binary files listed under scan.skipped are inventoried but their contents are not rule-scanned.", "Kona does not prove that a repository has no vulnerabilities."]}


def threshold_exit_code(report: dict[str, Any], fail_on: str = "high") -> int:
    if not report.get("scan", {}).get("complete"):
        return 2
    if fail_on not in _SEVERITY:
        raise ScanError(f"unknown severity threshold: {fail_on}")
    return 1 if any(_SEVERITY[item["severity"]] >= _SEVERITY[fail_on] for item in report["findings"]) else 0


def _sarif_uri(path: object) -> str | None:
    if not isinstance(path, str) or not path or "\x00" in path:
        return None
    if path.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", path):
        return None
    parts = path.replace("\\", "/").split("/")
    if any(part in {".", ".."} for part in parts):
        return None
    return quote(path.replace("\\", "/"), safe="/!$&'()*+,-.:;=@_~")


def render_sarif_report(report: dict[str, Any]) -> str:
    """Render location-bearing deterministic findings as SARIF 2.1.0.

    This is a presentation adapter. The canonical JSON report retains the
    scanner's complete trust boundary and remains authoritative.
    """

    rules = []
    for rule_id, (title, message, remediation) in _SARIF_RULES.items():
        rules.append(
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": title},
                "fullDescription": {"text": message},
                "help": {"text": remediation},
                "properties": {"category": "kona-deterministic"},
            }
        )
    results = []
    for item in report.get("findings", []):
        if not isinstance(item, dict):
            continue
        rule_id = item.get("rule_id")
        severity = item.get("severity")
        location = item.get("location")
        fingerprint = item.get("fingerprint")
        if rule_id not in _SARIF_RULES or severity not in _SEVERITY or not isinstance(location, dict):
            continue
        uri = _sarif_uri(location.get("path"))
        line = location.get("line")
        if uri is None or isinstance(line, bool) or not isinstance(line, int) or line < 1:
            continue
        if not isinstance(fingerprint, str) or not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", fingerprint):
            continue
        result = {
            "ruleId": rule_id,
            "level": "error" if severity in {"critical", "high"} else "warning" if severity == "medium" else "note",
            "message": {"text": _SARIF_RULES[rule_id][1]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}],
            "partialFingerprints": {"konaFinding": fingerprint.removeprefix("sha256:")},
        }
        results.append(result)
    scan = report["scan"]
    summary = report["summary"]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Kona Guard", "version": report["tool"]["version"], "informationUri": "https://github.com/uuzzrm/kona", "rules": rules}},
                "results": results,
                "properties": {
                    "konaSchema": report["schema"],
                    "verdict": summary["verdict"],
                    "complete": scan["complete"],
                    "offline": scan["offline"],
                    "readOnly": scan["read_only"],
                    "authenticated": scan["authenticated"],
                    "filesExamined": scan["files_examined"],
                    "entriesExamined": scan["entries_examined"],
                    "skippedCount": len(scan.get("skipped", [])),
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def render_scan_report(report: dict[str, Any], *, format: str = "text") -> str:
    if format == "json":
        return json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    if format == "sarif":
        return render_sarif_report(report)
    if format != "text":
        raise ScanError(f"unknown scan report format: {format}")
    lines = ["Kona Project Scan", "Mode: deterministic, offline, read-only", ""]
    for item in report["findings"]:
        location = item["location"]
        lines.extend([f"{item['severity'].upper():8} {item['rule_id']}  {item['title']}", f"         {location['path']}:{location['line']}", f"         {item['message']}", f"         Evidence: {item['evidence']['preview']}", f"         Fix: {item['remediation']}", ""])
    summary = report["summary"]
    skipped = report["scan"].get("skipped", [])
    lines.extend(["Summary", f"  target: {report['scan']['target']}", f"  files examined: {report['scan']['files_examined']}", f"  findings: {summary['critical']} critical, {summary['high']} high, {summary['medium']} medium, {summary['low']} low, {summary['info']} info", f"  skipped/inventoried: {len(skipped)}", "  scan complete: yes", f"  verdict: {summary['verdict']}", "", "Generated directories and binary files listed in JSON are inventoried but not rule-scanned.", "This result covers enabled deterministic rules; it is not proof that the repository has no vulnerabilities."])
    return "\n".join(lines) + "\n"
