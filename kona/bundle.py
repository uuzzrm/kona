"""Portable, deterministic Kona evidence bundles with offline verification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import shutil
import stat
import tempfile
from typing import Any
import zipfile

from . import __version__
from .contract import CONTRACT_FIELDS, CONTRACT_SCHEMA_VERSION, REPORT_SCHEMA_VERSION, _render_report_markdown
from .capture import SCHEMA_VERSION as RUN_SCHEMA_VERSION


BUNDLE_SCHEMA_VERSION = 1
BUNDLE_MEDIA_TYPE = "application/vnd.kona.evidence.bundle.v1+json"
MANIFEST_NAME = "kona.bundle.json"
ARTIFACT_NAMES = ("contract.json", "report.json", "report.md", "report.sha256", "run.json", "stdout.log", "stderr.log")
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


class BundleError(ValueError):
    """Raised when a bundle cannot be safely created or verified."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_name(name: str) -> str:
    if not name or "\\" in name or name.startswith("/") or PureWindowsPath(name).is_absolute():
        raise BundleError(f"unsafe bundle path: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts) or len(path.parts) != 1:
        raise BundleError(f"unsafe bundle path: {name!r}")
    if ":" in name or name.upper() in {"CON", "PRN", "AUX", "NUL", "COM1", "LPT1"}:
        raise BundleError(f"unsafe bundle path: {name!r}")
    return name


def _read_file(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise BundleError(f"bundle artifact must be a regular file: {path.name}")
    size = path.stat().st_size
    if size > MAX_ARTIFACT_BYTES:
        raise BundleError(f"bundle artifact exceeds {MAX_ARTIFACT_BYTES} bytes: {path.name}")
    return path.read_bytes()


def _artifact_records(files: dict[str, bytes]) -> list[dict[str, Any]]:
    return [{"path": name, "bytes": len(files[name]), "sha256": _sha256(files[name])} for name in sorted(files)]


def _manifest(files: dict[str, bytes]) -> dict[str, Any]:
    report = json.loads(files["report.json"].decode("utf-8"))
    contract_digest = _sha256(files["contract.json"])
    if report.get("contract", {}).get("sha256") != contract_digest:
        raise BundleError("contract bytes do not match the report contract digest")
    return {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "media_type": BUNDLE_MEDIA_TYPE,
        "producer": {"name": "kona", "version": __version__},
        "run_id": report.get("run", {}).get("run_id"),
        "artifacts": _artifact_records(files),
        "contract_sha256": contract_digest,
        "report_sha256": _sha256(files["report.json"]),
        "predicate": {
            "status": report.get("summary", {}).get("status"),
            "accepted": report.get("summary", {}).get("status") == "passed",
            "evidence_boundary": report.get("evidence_boundary", []),
        },
        "authenticated": False,
    }


def _write_directory(output: Path, files: dict[str, bytes], manifest_bytes: bytes) -> None:
    if output.exists() or output.is_symlink():
        raise BundleError(f"refusing to overwrite bundle output: {output}")
    output.mkdir(parents=True)
    for name, data in files.items():
        (output / name).write_bytes(data)
    (output / MANIFEST_NAME).write_bytes(manifest_bytes)


def _write_zip(output: Path, files: dict[str, bytes], manifest_bytes: bytes) -> None:
    if output.exists() or output.is_symlink():
        raise BundleError(f"refusing to overwrite bundle output: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted({**files, MANIFEST_NAME: manifest_bytes}.items()):
            info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o100644 << 16
            info.create_system = 3
            archive.writestr(info, data, compress_type=zipfile.ZIP_STORED)


def create_bundle(run: Path, output: Path) -> dict[str, Any]:
    """Create a portable directory or deterministic ZIP from one contract run."""
    run_dir = run.expanduser()
    if run_dir.is_file():
        run_dir = run_dir.parent
    if run_dir.is_symlink() or not run_dir.is_dir():
        raise BundleError("expected a contract run directory or report.json")
    files = {name: _read_file(run_dir / name) for name in ARTIFACT_NAMES}
    manifest = _manifest(files)
    manifest_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    if sum(map(len, files.values())) + len(manifest_bytes) > MAX_BUNDLE_BYTES:
        raise BundleError(f"bundle exceeds {MAX_BUNDLE_BYTES} bytes")
    output = output.expanduser().resolve()
    if output.suffix.lower() == ".zip":
        _write_zip(output, files, manifest_bytes)
    else:
        _write_directory(output, files, manifest_bytes)
    return manifest


def _read_directory(path: Path) -> dict[str, bytes]:
    if path.is_symlink() or not path.is_dir():
        raise BundleError("bundle directory must be a regular directory")
    names = {child.name for child in path.iterdir()}
    expected = set(ARTIFACT_NAMES) | {MANIFEST_NAME}
    if names != expected:
        raise BundleError(f"bundle contents differ: missing={sorted(expected-names)} unexpected={sorted(names-expected)}")
    return {name: _read_file(path / name) for name in expected}


def _read_zip(path: Path) -> dict[str, bytes]:
    if path.is_symlink() or not path.is_file():
        raise BundleError("bundle ZIP must be a regular file")
    if path.stat().st_size > MAX_BUNDLE_BYTES:
        raise BundleError(f"bundle ZIP exceeds {MAX_BUNDLE_BYTES} bytes")
    result: dict[str, bytes] = {}
    total = 0
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len({info.filename for info in infos}) != len(infos):
                raise BundleError("bundle ZIP contains duplicate paths")
            for info in infos:
                name = _safe_name(info.filename)
                if info.compress_type != zipfile.ZIP_STORED:
                    raise BundleError(f"bundle ZIP uses unsupported compression: {name}")
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode) or (mode and not stat.S_ISREG(mode)):
                    raise BundleError(f"bundle ZIP contains a non-regular entry: {name}")
                if info.file_size > MAX_ARTIFACT_BYTES:
                    raise BundleError(f"bundle artifact exceeds {MAX_ARTIFACT_BYTES} bytes: {name}")
                total += info.file_size
                if total > MAX_BUNDLE_BYTES:
                    raise BundleError(f"bundle exceeds {MAX_BUNDLE_BYTES} bytes")
                result[name] = archive.read(info)
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise BundleError("invalid bundle ZIP") from error
    expected = set(ARTIFACT_NAMES) | {MANIFEST_NAME}
    if set(result) != expected:
        raise BundleError(f"bundle contents differ: missing={sorted(expected-set(result))} unexpected={sorted(set(result)-expected)}")
    return result


def _verify_semantics(files: dict[str, bytes], manifest: dict[str, Any]) -> tuple[bool, bool, list[str]]:
    errors: list[str] = []
    try:
        contract = json.loads(files["contract.json"].decode("utf-8-sig"))
        report = json.loads(files["report.json"].decode("utf-8"))
        run = json.loads(files["run.json"].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False, False, ["report or run manifest is invalid JSON"]
    if not isinstance(contract, dict) or contract.get("version") != CONTRACT_SCHEMA_VERSION or set(contract) - CONTRACT_FIELDS:
        errors.append("contract structure is unsupported")
        contract = {}
    if not isinstance(contract.get("command"), list) or not contract.get("command") or not all(isinstance(item, str) and item for item in contract.get("command", [])):
        errors.append("contract command is invalid")
    if report.get("schema_version") != REPORT_SCHEMA_VERSION:
        errors.append("report schema is unsupported")
    if run.get("schema_version") != RUN_SCHEMA_VERSION:
        errors.append("run schema is unsupported")
    summary = report.get("summary", {})
    assertions = report.get("assertions", [])
    passed = sum(1 for item in assertions if isinstance(item, dict) and item.get("passed") is True)
    accepted = summary.get("status") == "passed"
    if report.get("run") != run: errors.append("report run does not match run.json")
    if (not isinstance(assertions, list) or not all(isinstance(item, dict) and isinstance(item.get("passed"), bool) for item in assertions)
            or summary.get("total_assertions") != len(assertions)
            or summary.get("passed_assertions") != passed
            or summary.get("failed_assertions") != len(assertions) - passed): errors.append("assertion summary is inconsistent")
    process_ok = run.get("status") == "success" and isinstance(run.get("exit_code"), int)
    expected_status = "passed" if assertions and passed == len(assertions) and report.get("contract_integrity", {}).get("stable") and process_ok and (report.get("workspace_policy") is None or report.get("workspace_policy", {}).get("valid") is True) else "failed"
    if summary.get("status") != expected_status: errors.append("report status is inconsistent")
    if report.get("contract", {}).get("sha256") != _sha256(files["contract.json"]): errors.append("contract digest is inconsistent")
    contract_assertions = contract.get("assertions", []) if isinstance(contract.get("assertions", []), list) else []
    expected_count = len(contract_assertions) if any(isinstance(item, dict) and item.get("type") in {"exit_code", "status"} for item in contract_assertions) else len(contract_assertions) + 1
    if len(assertions) != expected_count: errors.append("report assertions do not match the contract")
    report_contract = report.get("contract", {})
    if report_contract.get("command", {}).get("argv") != run.get("command", {}).get("argv") or report_contract.get("command", {}).get("argv") != contract.get("command"):
        errors.append("contract command does not match the recorded run")
    if manifest.get("contract_sha256") != _sha256(files["contract.json"]): errors.append("manifest contract digest is inconsistent")
    if manifest.get("report_sha256") != _sha256(files["report.json"]): errors.append("manifest report digest is inconsistent")
    if manifest.get("run_id") != run.get("run_id"): errors.append("manifest run identifier is inconsistent")
    digest_line = files["report.sha256"].decode("ascii", "replace").strip()
    if digest_line != f"{_sha256(files['report.json'])}  report.json": errors.append("report digest is inconsistent")
    artifacts = run.get("artifacts", {})
    for stream in ("stdout", "stderr"):
        metadata = artifacts.get(stream, {})
        data = files[f"{stream}.log"]
        if metadata.get("path") != f"{stream}.log" or metadata.get("bytes") != len(data) or metadata.get("sha256") != _sha256(data): errors.append(f"{stream} artifact is inconsistent")
    markdown_metadata = report.get("integrity", {}).get("report_markdown", {})
    markdown = files["report.md"]
    if markdown_metadata.get("path") != "report.md" or markdown_metadata.get("bytes") != len(markdown) or markdown_metadata.get("sha256") != _sha256(markdown): errors.append("report Markdown is inconsistent")
    try:
        rendered = _render_report_markdown(report).encode("utf-8")
        if markdown != rendered: errors.append("report Markdown does not match report.json")
    except (KeyError, TypeError, ValueError):
        errors.append("report structure cannot render Markdown")
    stored_run_integrity = report.get("integrity", {}).get("run_artifacts", {}).get("artifacts", {})
    for stream in ("stdout", "stderr"):
        stored = stored_run_integrity.get(stream, {})
        metadata = run.get("artifacts", {}).get(stream, {})
        if stored.get("path") != metadata.get("path") or stored.get("bytes") != metadata.get("bytes") or stored.get("sha256") != metadata.get("sha256") or stored.get("matches_manifest") is not True:
            errors.append(f"stored {stream} integrity is inconsistent")
    predicate = manifest.get("predicate", {})
    if (predicate.get("status") != summary.get("status") or predicate.get("accepted") is not accepted
            or predicate.get("evidence_boundary") != report.get("evidence_boundary", [])): errors.append("bundle predicate is inconsistent")
    return not errors, accepted, errors


def verify_bundle(path: Path) -> dict[str, Any]:
    """Verify a bundle using only its own bytes; never consult the original workspace."""
    source = path.expanduser().resolve()
    files = _read_zip(source) if source.is_file() else _read_directory(source)
    try:
        manifest = json.loads(files.pop(MANIFEST_NAME).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BundleError("invalid bundle manifest") from error
    manifest_fields = {"schema_version", "media_type", "producer", "run_id", "artifacts", "contract_sha256", "report_sha256", "predicate", "authenticated"}
    if not isinstance(manifest, dict) or set(manifest) != manifest_fields or manifest.get("schema_version") != BUNDLE_SCHEMA_VERSION or manifest.get("media_type") != BUNDLE_MEDIA_TYPE:
        raise BundleError("unsupported or malformed bundle manifest")
    records = manifest.get("artifacts")
    if not isinstance(records, list) or records != _artifact_records(files):
        raise BundleError("bundle artifact manifest does not match its bytes")
    if manifest.get("authenticated") is not False:
        raise BundleError("bundle authentication claim is unsupported")
    valid, accepted, errors = _verify_semantics(files, manifest)
    if not valid:
        raise BundleError("; ".join(errors))
    return {"valid": True, "accepted": accepted, "authenticated": False, "manifest": manifest, "errors": []}
