"""Evidence contracts: evaluate an Agent run against explicit acceptance checks."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePath, PureWindowsPath
import platform
import re
import sys
from typing import Any, Sequence

from .capture import _file_metadata, _quote_argument, inspect_run, run_capture
from .redaction import redact_argv, redact_text


CONTRACT_SCHEMA_VERSION = 1
REPORT_SCHEMA_VERSION = 2
REPORT_SHA256_NAME = "report.sha256"
MAX_ASSERTION_READ_BYTES = 4 * 1024 * 1024
MAX_STREAM_ASSERTION_READ_BYTES = 8 * 1024 * 1024
MAX_DIRECTORY_ENTRIES = 10_000
DEFAULT_CONTRACT_TIMEOUT_SECONDS = 300.0
CONTRACT_TEMPLATE = {
    "version": CONTRACT_SCHEMA_VERSION,
    "name": "my-agent-task",
    "description": "Describe the observable outcome this task must produce.",
    "cwd": ".",
    "command": ["python", "-c", "print('replace this command')"],
    "timeout": 300,
    "observations": ["path/to/output.txt"],
    "assertions": [
        {"type": "exit_code", "equals": 0},
        {"type": "file_exists", "path": "path/to/output.txt"},
        {"type": "file_content_contains", "path": "path/to/output.txt", "value": "required text"},
    ],
}
STATUS_VALUES = {"success", "failed", "timed_out"}
STREAM_ASSERTIONS = {
    "stdout_contains": ("stdout", True),
    "stdout_not_contains": ("stdout", False),
    "stderr_contains": ("stderr", True),
    "stderr_not_contains": ("stderr", False),
}
FILE_ASSERTIONS = {
    "file_exists",
    "file_content_contains",
    "file_content_not_contains",
    "file_sha256",
    "file_changed",
    "file_unchanged",
    "file_created",
    "file_deleted",
}
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
SURROGATE_PATTERN = re.compile(r"[\ud800-\udfff]")
CONTRACT_FIELDS = frozenset(
    {"version", "name", "description", "cwd", "command", "timeout", "observations", "assertions"}
)
ASSERTION_FIELDS = frozenset({"type", "equals", "path", "value"})


class ContractError(ValueError):
    """Raised when a contract cannot be safely loaded or evaluated."""


def _validate_text(value: Any, field: str, *, allow_empty: bool = True) -> str:
    if not isinstance(value, str) or (not allow_empty and value == ""):
        suffix = "" if allow_empty else " and non-empty"
        raise ContractError(f"{field} must be a string{suffix}")
    if SURROGATE_PATTERN.search(value):
        raise ContractError(f"{field} contains unsupported surrogate characters")
    return value


def init_contract(path: Path) -> Path:
    """Create a non-destructive starter contract and return its absolute path."""

    candidate = path.expanduser()
    if candidate.exists() or candidate.is_symlink():
        raise ContractError(f"refusing to overwrite existing contract: {path}")
    candidate.parent.mkdir(parents=True, exist_ok=True)
    try:
        with candidate.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(CONTRACT_TEMPLATE, handle, indent=2)
            handle.write("\n")
    except FileExistsError as error:
        raise ContractError(f"refusing to overwrite existing contract: {path}") from error
    return candidate.resolve()


@dataclass(frozen=True)
class ContractSpec:
    path: Path
    name: str
    description: str | None
    workspace: Path
    cwd_display: str
    command: list[str]
    timeout: float | None
    observations: list[str]
    assertions: list[dict[str, Any]]
    contract_sha256: str


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _directory_metadata(path: Path) -> dict[str, Any]:
    """Hash a bounded directory tree without following symlinks."""

    digest = hashlib.sha256()
    total_bytes = 0
    entries = 0
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            children = sorted(current.iterdir(), key=lambda item: item.name.casefold(), reverse=True)
        except OSError as error:
            raise ContractError(f"could not inspect observed directory: {current}") from error
        for child in children:
            entries += 1
            if entries > MAX_DIRECTORY_ENTRIES:
                raise ContractError(
                    f"observed directory contains more than {MAX_DIRECTORY_ENTRIES} entries: {path.name}"
                )
            relative = child.relative_to(path).as_posix()
            try:
                if child.is_symlink():
                    target = os.readlink(child)
                    digest.update(
                        f"symlink\0{relative}\0{target}".encode("utf-8", errors="surrogateescape")
                    )
                elif child.is_dir():
                    digest.update(f"directory\0{relative}\n".encode("utf-8"))
                    stack.append(child)
                elif child.is_file():
                    metadata = _file_metadata(child)
                    total_bytes += int(metadata["bytes"])
                    digest.update(
                        f"file\0{relative}\0{metadata['bytes']}\0{metadata['sha256']}\n".encode("ascii")
                    )
                else:
                    digest.update(f"other\0{relative}\n".encode("utf-8"))
            except (OSError, UnicodeError) as error:
                raise ContractError(f"could not inspect observed directory entry: {child}") from error
    return {"bytes": total_bytes, "sha256": digest.hexdigest(), "entries": entries}


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _reject_symlink_components(root: Path, relative: Path, label: str) -> None:
    current = root
    for part in relative.parts:
        if part in {"", "."}:
            continue
        current = current / part
        if current.is_symlink():
            raise ContractError(f"{label} cannot traverse a symlink: {relative}")


def _validate_relative_path(value: Any, field: str) -> str:
    _validate_text(value, field, allow_empty=False)
    if not value.strip():
        raise ContractError(f"{field} must be a non-empty relative path")
    if "\x00" in value:
        raise ContractError(f"{field} contains a NUL byte")
    if "\\" in value:
        raise ContractError(f"{field} must use '/' separators: {value}")
    if ":" in value:
        raise ContractError(f"{field} cannot contain ':': {value}")
    candidate = Path(value)
    if candidate.is_absolute() or PurePath(value).anchor or PureWindowsPath(value).anchor:
        raise ContractError(f"{field} must be relative: {value}")
    if any(part == ".." for part in candidate.parts):
        raise ContractError(f"{field} cannot contain '..': {value}")
    reserved = {"con", "prn", "aux", "nul", *(f"com{index}" for index in range(1, 10)), *(f"lpt{index}" for index in range(1, 10))}
    for part in candidate.parts:
        normalized = part.rstrip(" .").split(".", 1)[0].casefold()
        if normalized in reserved:
            raise ContractError(f"{field} uses a Windows device name: {value}")
    return candidate.as_posix()


def _resolve_workspace(contract_path: Path, cwd_value: str) -> tuple[Path, str]:
    contract_root = contract_path.parent.resolve()
    cwd_display = _validate_relative_path(cwd_value, "cwd")
    cwd = Path(cwd_display)
    _reject_symlink_components(contract_root, cwd, "cwd")
    workspace = (contract_root / cwd).resolve()
    if not _is_relative_to(workspace, contract_root):
        raise ContractError("cwd must remain inside the contract directory")
    if not workspace.is_dir():
        raise ContractError(f"cwd is not an existing directory: {cwd_value}")
    return workspace, cwd_display or "."


def _validate_command(value: Any) -> list[str]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item for item in value):
        raise ContractError("command must be a non-empty array of non-empty strings")
    for index, item in enumerate(value):
        _validate_text(item, f"command[{index}]", allow_empty=False)
        if "\x00" in item:
            raise ContractError("command arguments cannot contain NUL bytes")
    return list(value)


def _validate_timeout(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ContractError("timeout must be a non-negative number or null")
    return float(value) if value else None


def _validate_assertion(assertion: Any, index: int) -> dict[str, Any]:
    if not isinstance(assertion, dict):
        raise ContractError(f"assertions[{index}] must be an object")
    unknown_fields = sorted(set(assertion) - ASSERTION_FIELDS)
    if unknown_fields:
        raise ContractError(f"assertions[{index}] contains unsupported fields: {', '.join(unknown_fields)}")
    assertion_type = assertion.get("type")
    if not isinstance(assertion_type, str):
        raise ContractError(f"assertions[{index}].type must be a string")

    if assertion_type == "exit_code":
        expected = assertion.get("equals")
        if isinstance(expected, bool) or not isinstance(expected, int):
            raise ContractError(f"assertions[{index}].equals must be an integer")
    elif assertion_type == "status":
        expected = assertion.get("equals")
        if not isinstance(expected, str) or expected not in STATUS_VALUES:
            raise ContractError(f"assertions[{index}].equals must be one of {sorted(STATUS_VALUES)}")
    elif assertion_type in STREAM_ASSERTIONS:
        _validate_text(assertion.get("value"), f"assertions[{index}].value", allow_empty=False)
    elif assertion_type in FILE_ASSERTIONS:
        _validate_relative_path(assertion.get("path"), f"assertions[{index}].path")
        if assertion_type == "file_exists":
            expected = assertion.get("equals", True)
            if not isinstance(expected, bool):
                raise ContractError(f"assertions[{index}].equals must be a boolean")
        elif assertion_type in {"file_content_contains", "file_content_not_contains"}:
            _validate_text(assertion.get("value"), f"assertions[{index}].value", allow_empty=False)
        elif assertion_type == "file_sha256":
            expected = assertion.get("equals")
            if not isinstance(expected, str) or not SHA256_PATTERN.fullmatch(expected):
                raise ContractError(f"assertions[{index}].equals must be a 64-character SHA-256 hex digest")
        elif assertion_type in {"file_changed", "file_unchanged", "file_created", "file_deleted"}:
            expected = assertion.get("equals", True)
            if not isinstance(expected, bool):
                raise ContractError(f"assertions[{index}].equals must be a boolean")
    else:
        supported = sorted({"exit_code", "status", *STREAM_ASSERTIONS, *FILE_ASSERTIONS})
        raise ContractError(f"unsupported assertion type {assertion_type!r}; use one of {supported}")

    normalized = dict(assertion)
    normalized["type"] = assertion_type
    if assertion_type == "file_exists" or assertion_type in {"file_changed", "file_unchanged", "file_created", "file_deleted"}:
        normalized.setdefault("equals", True)
    return normalized


def _contract_observation_paths(assertions: Sequence[dict[str, Any]], observations: Sequence[str]) -> list[str]:
    paths = list(observations)
    for assertion in assertions:
        if assertion["type"] in FILE_ASSERTIONS:
            path = assertion["path"]
            if path not in paths:
                paths.append(path)
    return paths


def load_contract(path: Path) -> ContractSpec:
    """Load, validate, and normalize a contract before executing anything."""

    candidate_path = path.expanduser()
    if candidate_path.is_symlink():
        raise ContractError(f"contract must be a regular file: {path}")
    contract_path = candidate_path.resolve()
    if not contract_path.is_file():
        raise ContractError(f"contract must be a regular file: {path}")
    try:
        raw = json.loads(contract_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError(f"could not read JSON contract: {path}") from error
    if not isinstance(raw, dict):
        raise ContractError("contract root must be an object")
    if raw.get("version") != CONTRACT_SCHEMA_VERSION:
        raise ContractError(f"contract version must be {CONTRACT_SCHEMA_VERSION}")
    unknown_fields = sorted(set(raw) - CONTRACT_FIELDS)
    if unknown_fields:
        raise ContractError(f"contract contains unsupported fields: {', '.join(unknown_fields)}")

    name = raw.get("name", contract_path.stem)
    _validate_text(name, "name", allow_empty=False)
    if not name.strip():
        raise ContractError("name must be a non-empty string")
    description = raw.get("description")
    if description is not None:
        _validate_text(description, "description")
    command = _validate_command(raw.get("command"))
    timeout = DEFAULT_CONTRACT_TIMEOUT_SECONDS if "timeout" not in raw else _validate_timeout(raw["timeout"])
    cwd_value = raw.get("cwd", ".")
    _validate_text(cwd_value, "cwd", allow_empty=False)
    workspace, cwd_display = _resolve_workspace(contract_path, cwd_value)

    raw_observations = raw.get("observations", [])
    if not isinstance(raw_observations, list):
        raise ContractError("observations must be an array of relative paths")
    observations: list[str] = []
    for index, value in enumerate(raw_observations):
        normalized = _validate_relative_path(value, f"observations[{index}]")
        if normalized not in observations:
            observations.append(normalized)

    raw_assertions = raw.get("assertions", [])
    if not isinstance(raw_assertions, list):
        raise ContractError("assertions must be an array")
    assertions = [_validate_assertion(value, index) for index, value in enumerate(raw_assertions)]
    has_process_assertion = any(item["type"] in {"exit_code", "status"} for item in assertions)
    if not has_process_assertion:
        assertions.insert(0, {"type": "exit_code", "equals": 0, "implicit": True})

    all_observations = _contract_observation_paths(assertions, observations)
    for index, value in enumerate(all_observations):
        _reject_symlink_components(workspace, Path(value), f"observations[{index}]")

    return ContractSpec(
        path=contract_path,
        name=name,
        description=description,
        workspace=workspace,
        cwd_display=cwd_display,
        command=command,
        timeout=timeout,
        observations=all_observations,
        assertions=assertions,
        contract_sha256=_sha256_file(contract_path),
    )


def _resolve_observed_path(workspace: Path, relative: str) -> Path:
    relative_path = Path(relative)
    _reject_symlink_components(workspace, relative_path, "observed path")
    candidate = (workspace / relative_path).resolve()
    workspace_resolved = workspace.resolve()
    if not _is_relative_to(candidate, workspace_resolved):
        raise ContractError(f"observed path escapes cwd: {relative}")
    return candidate


def _snapshot_one(workspace: Path, relative: str) -> dict[str, Any]:
    relative_path = Path(relative)
    current = workspace
    for part in relative_path.parts:
        if part in {"", "."}:
            continue
        current = current / part
        if current.is_symlink():
            return {"path": relative, "exists": True, "kind": "symlink", "bytes": None, "sha256": None}
    path = _resolve_observed_path(workspace, relative)
    if not path.exists():
        return {"path": relative, "exists": False, "kind": "missing", "bytes": None, "sha256": None}
    if path.is_file():
        metadata = _file_metadata(path)
        return {
            "path": relative,
            "exists": True,
            "kind": "file",
            "bytes": metadata["bytes"],
            "sha256": metadata["sha256"],
        }
    if path.is_dir():
        metadata = _directory_metadata(path)
        return {
            "path": relative,
            "exists": True,
            "kind": "directory",
            "bytes": metadata["bytes"],
            "sha256": metadata["sha256"],
            "entries": metadata["entries"],
        }
    return {"path": relative, "exists": True, "kind": "other", "bytes": None, "sha256": None}


def snapshot_workspace(workspace: Path, paths: Sequence[str]) -> dict[str, dict[str, Any]]:
    """Capture metadata only for declared paths before or after a run."""

    return {relative: _snapshot_one(workspace, relative) for relative in paths}


def _read_text_limited(path: Path, *, limit: int = MAX_ASSERTION_READ_BYTES) -> str:
    if not path.is_file():
        return ""
    if path.stat().st_size > limit:
        raise ContractError(f"assertion input is larger than {limit} bytes: {path.name}")
    return path.read_text(encoding="utf-8", errors="replace")


def _safe_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value).text
    if isinstance(value, list):
        return [_safe_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _safe_value(item) for key, item in value.items()}
    return value


def _assertion_id(index: int) -> str:
    return f"assertion-{index + 1}"


def _assertion_result(
    assertion: dict[str, Any],
    passed: bool,
    expected: Any,
    observed: Any,
    reason: str,
    assertion_index: int,
) -> dict[str, Any]:
    result = {
        "id": _assertion_id(assertion_index),
        "type": assertion["type"],
        "implicit": bool(assertion.get("implicit", False)),
        "passed": passed,
        "expected": _safe_value(expected),
        "observed": _safe_value(observed),
        "reason": _safe_value(reason),
    }
    if "path" in assertion:
        result["path"] = _safe_value(assertion["path"])
    return result


def _file_changed(before: dict[str, Any], after: dict[str, Any]) -> bool:
    fields = ("exists", "kind", "bytes", "sha256", "entries")
    return any(before.get(field) != after.get(field) for field in fields)


def evaluate_assertions(
    spec: ContractSpec,
    manifest: dict[str, Any],
    run_dir: Path,
    before: dict[str, dict[str, Any]],
    after: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Evaluate assertions without persisting command output or observed file contents."""

    stream_text: dict[str, str] = {}
    stream_errors: dict[str, str] = {}
    needed_streams = {
        stream_name
        for assertion in spec.assertions
        if assertion["type"] in STREAM_ASSERTIONS
        for stream_name, _should_contain in [STREAM_ASSERTIONS[assertion["type"]]]
    }
    for stream_name in needed_streams:
        try:
            stream_text[stream_name] = _read_text_limited(
                run_dir / f"{stream_name}.log", limit=MAX_STREAM_ASSERTION_READ_BYTES
            )
        except ContractError as error:
            stream_errors[stream_name] = str(error)
    results: list[dict[str, Any]] = []
    for assertion_index, assertion in enumerate(spec.assertions):
        assertion_type = assertion["type"]
        if assertion_type == "exit_code":
            expected = assertion["equals"]
            observed = manifest["exit_code"]
            results.append(_assertion_result(assertion, observed == expected, expected, observed, "exit code matched" if observed == expected else "exit code did not match", assertion_index))
            continue
        if assertion_type == "status":
            expected = assertion["equals"]
            observed = manifest["status"]
            results.append(_assertion_result(assertion, observed == expected, expected, observed, "run status matched" if observed == expected else "run status did not match", assertion_index))
            continue
        if assertion_type in STREAM_ASSERTIONS:
            stream_name, should_contain = STREAM_ASSERTIONS[assertion_type]
            expected = assertion["value"]
            if stream_name in stream_errors:
                results.append(_assertion_result(assertion, False, expected, "unavailable", stream_errors[stream_name], assertion_index))
                continue
            found = expected in stream_text[stream_name]
            passed = found if should_contain else not found
            phrase = "contained" if should_contain else "did not contain"
            results.append(_assertion_result(assertion, passed, expected, found, f"{stream_name} {phrase} expected text" if passed else f"{stream_name} failed {phrase} check", assertion_index))
            continue

        relative = assertion["path"]
        before_item = before[relative]
        after_item = after[relative]
        if assertion_type == "file_exists":
            expected = assertion["equals"]
            observed = after_item["kind"] == "file"
            results.append(_assertion_result(assertion, observed == expected, expected, observed, f"file existence matched for {relative}" if observed == expected else f"file existence did not match for {relative}", assertion_index))
        elif assertion_type in {"file_changed", "file_unchanged", "file_created", "file_deleted"}:
            changed = _file_changed(before_item, after_item)
            before_is_file = before_item["kind"] == "file"
            after_is_file = after_item["kind"] == "file"
            if assertion_type == "file_changed":
                observed, default_pass = changed, changed
            elif assertion_type == "file_unchanged":
                observed, default_pass = not changed, not changed
            elif assertion_type == "file_created":
                observed, default_pass = (before_item["kind"] == "missing" and after_is_file), (before_item["kind"] == "missing" and after_is_file)
            else:
                observed, default_pass = (before_is_file and after_item["kind"] == "missing"), (before_is_file and after_item["kind"] == "missing")
            expected = assertion["equals"]
            passed = default_pass == expected
            results.append(_assertion_result(assertion, passed, expected, observed, f"file lifecycle matched for {relative}" if passed else f"file lifecycle did not match for {relative}", assertion_index))
        elif assertion_type == "file_sha256":
            expected = assertion["equals"].lower()
            observed = after_item["sha256"] if after_item["kind"] == "file" else None
            passed = observed == expected
            reason = f"file hash matched for {relative}" if passed else f"file hash requires a regular file: {relative}"
            results.append(_assertion_result(assertion, passed, expected, observed, reason, assertion_index))
        else:
            if after_item["kind"] != "file":
                results.append(_assertion_result(assertion, False, assertion["value"], "unavailable", f"observed path is not a regular file: {relative}", assertion_index))
                continue
            path = _resolve_observed_path(spec.workspace, relative)
            expected = assertion["value"]
            try:
                content = _read_text_limited(path)
            except ContractError as error:
                results.append(_assertion_result(assertion, False, expected, "unavailable", str(error), assertion_index))
                continue
            found = expected in content
            should_contain = assertion_type == "file_content_contains"
            passed = found if should_contain else not found
            phrase = "contained" if should_contain else "did not contain"
            results.append(_assertion_result(assertion, passed, expected, found, f"file {phrase} expected text for {relative}" if passed else f"file failed {phrase} check for {relative}", assertion_index))
    return results


def _safe_command(command: Sequence[str]) -> dict[str, Any]:
    safe_argv, redactions = redact_argv(command)
    return {
        "argv": safe_argv,
        "display": " ".join(_quote_argument(argument) for argument in safe_argv),
        "redactions": redactions,
    }


def _contract_summary(spec: ContractSpec, manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": redact_text(spec.name).text,
        "description": redact_text(spec.description).text if spec.description else None,
        "version": CONTRACT_SCHEMA_VERSION,
        "path": redact_text(spec.path.name).text,
        "sha256": spec.contract_sha256,
        "cwd": redact_text(spec.cwd_display).text,
        "command": _safe_command(spec.command),
        "timeout_seconds": spec.timeout,
        "observations": [redact_text(path).text for path in spec.observations],
        "assertions": [
            {
                "id": _assertion_id(index),
                "type": assertion["type"],
                "path": redact_text(assertion["path"]).text if "path" in assertion else None,
                "expected": _safe_value(assertion.get("equals", assertion.get("value"))),
            }
            for index, assertion in enumerate(spec.assertions)
        ],
    }


def _markdown_escape(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\r", "").replace("\n", " ")


def _render_report_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    contract = report["contract"]
    lines = [
        f"# Kona evidence report: {contract['name']}",
        "",
        f"> Status: **{summary['status'].upper()}** - {summary['passed_assertions']}/{summary['total_assertions']} assertions passed",
        "",
        "This report records observable process and workspace evidence. It does not prove that an AI Agent chose the best plan or that an external system accepted the result.",
        "",
        "## Run",
        "",
        f"- Command: `{_markdown_escape(report['run']['command']['display'])}`",
        f"- Working directory: `{_markdown_escape(report['run']['cwd'])}`",
        f"- Process status: `{_markdown_escape(report['run']['status'])}`; exit code `{_markdown_escape(report['run']['exit_code'])}`",
        f"- Duration: `{_markdown_escape(report['run']['duration_ms'])}` ms",
        f"- Contract SHA-256: `{contract['sha256']}`",
        f"- Contract stable during run: `{report['contract_integrity']['stable']}`",
        "",
        "## Assertions",
        "",
        "| Result | Assertion | Expected | Observed |",
        "| --- | --- | --- | --- |",
    ]
    for result in report["assertions"]:
        marker = "PASS" if result["passed"] else "FAIL"
        implicit = " (implicit)" if result["implicit"] else ""
        lines.append(
            f"| {marker} | `{_markdown_escape(result['id'])}` `{_markdown_escape(result['type'])}`{implicit} | `{_markdown_escape(result['expected'])}` | `{_markdown_escape(result['observed'])}` |"
        )
    lines.extend(["", "## Observed files", "", "| Path | Before | After | Change |", "| --- | --- | --- | --- |"])
    for path in report["observations"]:
        before = path["before"]
        after = path["after"]
        change = "changed" if _file_changed(before, after) else "unchanged"
        before_value = f"{before['kind']} / {before['bytes']} bytes" if before["exists"] else "missing"
        after_value = f"{after['kind']} / {after['bytes']} bytes" if after["exists"] else "missing"
        lines.append(f"| `{_markdown_escape(path['path'])}` | {_markdown_escape(before_value)} | {_markdown_escape(after_value)} | {change} |")
    lines.extend(
        [
            "",
            "## Evidence boundary",
            "",
            "- Captured stdout and stderr are redacted best-effort streams.",
            "- Observed files contribute metadata and SHA-256 hashes; file contents are not copied into this report.",
            "- Passing assertions establish only the checks written in the contract and the local process evidence available to Kona.",
        ]
    )
    return "\n".join(lines) + "\n"


def _report_artifact(path: Path) -> dict[str, Any]:
    metadata = _file_metadata(path)
    return {"path": metadata["path"], "bytes": metadata["bytes"], "sha256": metadata["sha256"]}


def run_contract(
    contract_path: Path,
    *,
    output_root: Path,
    quiet: bool = False,
) -> tuple[dict[str, Any], int]:
    """Execute a validated contract and write a JSON plus Markdown evidence package."""

    spec = load_contract(contract_path)
    before = snapshot_workspace(spec.workspace, spec.observations)
    manifest, _child_exit_code = run_capture(
        spec.command,
        output_root=output_root,
        cwd=spec.workspace,
        timeout=spec.timeout,
        label=spec.name,
        quiet=quiet,
    )
    output_root = output_root.expanduser().resolve()
    run_dir = output_root / str(manifest["run_id"])
    after = snapshot_workspace(spec.workspace, spec.observations)
    assertion_results = evaluate_assertions(spec, manifest, run_dir, before, after)
    try:
        contract_after_sha256 = None if spec.path.is_symlink() or not spec.path.is_file() else _sha256_file(spec.path)
    except OSError:
        contract_after_sha256 = None
    contract_stable = contract_after_sha256 == spec.contract_sha256
    process_integrity = inspect_run(run_dir)
    passed_assertions = sum(1 for result in assertion_results if result["passed"])
    all_passed = (
        contract_stable
        and bool(process_integrity["integrity"]["valid"])
        and manifest["status"] != "timed_out"
        and passed_assertions == len(assertion_results)
    )
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": _utc_timestamp(),
        "summary": {
            "status": "passed" if all_passed else "failed",
            "passed_assertions": passed_assertions,
            "failed_assertions": len(assertion_results) - passed_assertions,
            "total_assertions": len(assertion_results),
        },
        "contract": _contract_summary(spec, manifest),
        "contract_integrity": {"stable": contract_stable, "sha256_after": contract_after_sha256},
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "os": sys.platform,
        },
        "run": manifest,
        "assertions": assertion_results,
        "observations": [
            {
                "path": redact_text(relative).text,
                "before": _safe_value(before[relative]),
                "after": _safe_value(after[relative]),
            }
            for relative in spec.observations
        ],
        "integrity": {
            "run_artifacts": process_integrity["integrity"],
            "workspace": {"valid": True, "checked": len(spec.observations)},
        },
        "evidence_boundary": [
            "Process output is captured after best-effort redaction and is not a semantic correctness proof.",
            "Observed files contribute metadata and hashes only; their contents are not copied into the report.",
            "A passing report covers only the assertions declared by this contract in this local environment.",
        ],
    }
    report_markdown_path = run_dir / "report.md"
    report_markdown_path.write_text(_render_report_markdown(report), encoding="utf-8")
    report["integrity"]["report_markdown"] = _report_artifact(report_markdown_path)
    report_json_path = run_dir / "report.json"
    temporary = report_json_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(report_json_path)
    report_digest = _sha256_file(report_json_path)
    (run_dir / REPORT_SHA256_NAME).write_text(f"{report_digest}  report.json\n", encoding="ascii")
    return report, 0 if all_passed else 1


def _inspect_workspace_observations(report: dict[str, Any]) -> dict[str, Any]:
    """Re-check declared after-state metadata when a report is inspected."""

    run = report.get("run")
    observations = report.get("observations")
    if not isinstance(run, dict) or not isinstance(observations, list):
        return {"valid": False, "checked": 0, "reason": "malformed workspace evidence"}
    raw_cwd = run.get("cwd")
    if not isinstance(raw_cwd, str) or not raw_cwd:
        return {"valid": False, "checked": 0, "reason": "run cwd is unavailable"}
    workspace = Path(raw_cwd)
    if workspace.is_symlink() or not workspace.is_dir():
        return {"valid": False, "checked": 0, "reason": "run cwd is not an accessible directory"}
    expected: dict[str, dict[str, Any]] = {}
    try:
        for index, item in enumerate(observations):
            if not isinstance(item, dict):
                return {"valid": False, "checked": index, "reason": "malformed observation entry"}
            relative = item.get("path")
            after = item.get("after")
            if not isinstance(relative, str) or not isinstance(after, dict):
                return {"valid": False, "checked": index, "reason": "malformed observation metadata"}
            normalized = _validate_relative_path(relative, f"report.observations[{index}].path")
            if normalized != relative or relative in expected:
                return {"valid": False, "checked": index, "reason": "invalid or duplicate observation path"}
            expected[relative] = after
        current = snapshot_workspace(workspace, list(expected))
    except (ContractError, OSError, ValueError) as error:
        return {"valid": False, "checked": len(expected), "reason": str(error)}
    details = {
        relative: {"matches": current[relative] == after, "expected": after, "current": current[relative]}
        for relative, after in expected.items()
    }
    return {"valid": all(item["matches"] for item in details.values()), "checked": len(details), "paths": details}


def inspect_contract_report(path: Path) -> dict[str, Any]:
    """Verify a contract report's process artifacts and Markdown companion."""

    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ContractError(f"report path cannot be a symlink: {path}")
    target = candidate.resolve()
    report_path = target / "report.json" if target.is_dir() else target
    if report_path.name != "report.json":
        raise ContractError("expected a contract run directory or report.json")
    if report_path.is_symlink():
        raise ContractError(f"report must be a regular file: {report_path}")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError(f"invalid report: {report_path}") from error
    if not isinstance(report, dict) or report.get("schema_version") != REPORT_SCHEMA_VERSION:
        raise ContractError("unsupported or malformed contract report")
    for key in ("summary", "contract", "run", "assertions", "observations", "integrity"):
        if key not in report:
            raise ContractError(f"contract report is missing {key}")
    if not isinstance(report["summary"], dict) or not isinstance(report["contract"], dict):
        raise ContractError("contract report has malformed summary or contract")
    contract_integrity = report.get("contract_integrity")
    if not isinstance(contract_integrity, dict):
        raise ContractError("contract report has malformed contract integrity")
    if not isinstance(report["run"], dict):
        raise ContractError("contract report has malformed run")
    if not isinstance(report["assertions"], list) or not all(isinstance(item, dict) for item in report["assertions"]):
        raise ContractError("contract report has malformed assertions")
    if not isinstance(report["observations"], list) or not all(isinstance(item, dict) for item in report["observations"]):
        raise ContractError("contract report has malformed observations")
    if not isinstance(report["integrity"], dict):
        raise ContractError("contract report has malformed evidence sections")
    run_dir = report_path.parent
    if not report_path.is_file() or run_dir.is_symlink():
        raise ContractError(f"report must be a regular file: {report_path}")
    try:
        process_report = inspect_run(run_dir)
    except (KeyError, TypeError, ValueError, OSError) as error:
        raise ContractError(f"invalid process evidence in report: {run_dir}") from error
    run_matches_manifest = report["run"] == process_report["manifest"]
    markdown_metadata = report.get("integrity", {}).get("report_markdown")
    markdown_path = run_dir / "report.md"
    markdown_valid = (
        isinstance(markdown_metadata, dict)
        and not markdown_path.is_symlink()
        and markdown_path.is_file()
        and _file_metadata(markdown_path) == markdown_metadata
    )
    digest_path = run_dir / REPORT_SHA256_NAME
    digest_valid = False
    if digest_path.is_file() and not digest_path.is_symlink():
        try:
            digest_line = digest_path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeDecodeError):
            digest_line = ""
        parts = digest_line.split("  ", 1)
        expected_digest = parts[0] if len(parts) == 2 and parts[1] == "report.json" else ""
        digest_valid = bool(SHA256_PATTERN.fullmatch(expected_digest)) and expected_digest == _sha256_file(report_path)
    summary = report["summary"]
    assertion_results = report["assertions"]
    passed_assertions = sum(1 for result in assertion_results if result.get("passed") is True)
    semantic_valid = (
        summary.get("total_assertions") == len(assertion_results)
        and summary.get("passed_assertions") == passed_assertions
        and summary.get("failed_assertions") == len(assertion_results) - passed_assertions
        and summary.get("status") in {"passed", "failed"}
        and summary.get("status")
        == (
            "passed"
            if passed_assertions == len(assertion_results)
            and contract_integrity.get("stable")
            and process_report["integrity"]["valid"]
            and report["run"].get("status") != "timed_out"
            else "failed"
        )
    )
    stored_process_integrity = report["integrity"].get("run_artifacts")
    stored_process_matches = stored_process_integrity == process_report["integrity"]
    workspace_integrity = _inspect_workspace_observations(report)
    stored_workspace_integrity = report["integrity"].get("workspace")
    stored_workspace_present = isinstance(stored_workspace_integrity, dict) and stored_workspace_integrity.get("valid") is True
    return {
        "report": report,
        "integrity": {
            "valid": bool(process_report["integrity"]["valid"])
            and run_matches_manifest
            and markdown_valid
            and digest_valid
            and semantic_valid
            and stored_process_matches
            and stored_workspace_present
            and workspace_integrity["valid"],
            "run_artifacts": process_report["integrity"],
            "report_markdown": {"valid": markdown_valid, "path": str(markdown_path)},
            "report_json": {"valid": digest_valid, "path": str(report_path)},
            "report_digest": {"valid": digest_valid, "path": str(digest_path)},
            "semantics": {"valid": semantic_valid},
            "run_manifest": {"valid": run_matches_manifest},
            "workspace": workspace_integrity,
        },
    }
