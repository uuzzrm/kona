"""Process capture and run-manifest implementation for Kona."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import threading
import time
from typing import IO, Sequence, TextIO

from .redaction import redact_argv, redact_text


SCHEMA_VERSION = 1
DEFAULT_TIMEOUT_SECONDS = 300.0
STREAM_NAMES = ("stdout", "stderr")


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _safe_display_command(argv: Sequence[str]) -> tuple[list[str], str, int]:
    safe_argv, count = redact_argv(argv)
    display = " ".join(_quote_argument(argument) for argument in safe_argv)
    return safe_argv, display, count


def _quote_argument(argument: str) -> str:
    if argument and all(character.isalnum() or character in "-._/:=@%+" for character in argument):
        return argument
    return '"' + argument.replace('"', '\\"') + '"'


def _file_metadata(path: Path) -> dict[str, object]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return {"path": path.name, "bytes": size, "sha256": digest.hexdigest()}


def _write_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
    """Stop the timed-out child, including descendants where the host supports it."""

    if process.poll() is not None:
        return

    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def _capture_stream(
    stream: IO[str],
    destination: TextIO,
    console: TextIO,
    quiet: bool,
    result: dict[str, int],
) -> None:
    for line in iter(stream.readline, ""):
        redacted = redact_text(line)
        destination.write(redacted.text)
        destination.flush()
        result["count"] += redacted.count
        if not quiet:
            console.write(redacted.text)
            console.flush()
    stream.close()
    destination.close()


def _normalized_exit_code(raw_code: int | None, fallback: int = 1) -> int:
    if raw_code is None:
        return fallback
    return raw_code if raw_code >= 0 else 128 + abs(raw_code)


def run_capture(
    command: Sequence[str],
    *,
    output_root: Path,
    cwd: Path | None = None,
    timeout: float | None = DEFAULT_TIMEOUT_SECONDS,
    label: str | None = None,
    quiet: bool = False,
) -> tuple[dict[str, object], int]:
    """Run a command, tee redacted text streams, and write a JSON run manifest."""

    if not command:
        raise ValueError("a command is required after --")
    if timeout is not None and timeout < 0:
        raise ValueError("timeout must be zero or greater")

    output_root = output_root.expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + secrets.token_hex(3)
    run_dir = output_root / run_id
    run_dir.mkdir()

    safe_argv, display_command, command_redactions = _safe_display_command(command)
    safe_label, label_redactions = "", 0
    if label:
        label_result = redact_text(label)
        safe_label, label_redactions = label_result.text, label_result.count
    started_at = _timestamp()
    started_clock = time.monotonic()
    stdout_path = run_dir / "stdout.log"
    stderr_path = run_dir / "stderr.log"
    stream_counts = {"stdout": {"count": 0}, "stderr": {"count": 0}}
    timed_out = False
    spawn_error: str | None = None
    exit_code: int

    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
    start_new_session = os.name != "nt"

    try:
        process = subprocess.Popen(
            list(command),
            cwd=str(cwd) if cwd is not None else None,
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=creationflags,
            start_new_session=start_new_session,
        )
    except OSError as error:
        if isinstance(error, FileNotFoundError):
            spawn_error = f"command not found: {safe_argv[0]}"
        elif isinstance(error, PermissionError):
            spawn_error = f"permission denied: {safe_argv[0]}"
        else:
            spawn_error = f"could not start command: {safe_argv[0]}"
        redacted_error = redact_text(spawn_error)
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text(redacted_error.text + "\n", encoding="utf-8")
        if not quiet:
            sys.stderr.write(redacted_error.text + "\n")
            sys.stderr.flush()
        exit_code = 127 if isinstance(error, FileNotFoundError) else 126
        stream_counts["stderr"]["count"] += redacted_error.count
    else:
        assert process.stdout is not None
        assert process.stderr is not None
        stdout_file = stdout_path.open("w", encoding="utf-8", newline="")
        stderr_file = stderr_path.open("w", encoding="utf-8", newline="")
        threads = [
            threading.Thread(
                target=_capture_stream,
                args=(process.stdout, stdout_file, sys.stdout, quiet, stream_counts["stdout"]),
                name="kona-stdout",
                daemon=True,
            ),
            threading.Thread(
                target=_capture_stream,
                args=(process.stderr, stderr_file, sys.stderr, quiet, stream_counts["stderr"]),
                name="kona-stderr",
                daemon=True,
            ),
        ]
        for thread in threads:
            thread.start()

        try:
            process.wait(timeout=timeout if timeout and timeout > 0 else None)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_process_tree(process)
            exit_code = 124
        except KeyboardInterrupt:
            _terminate_process_tree(process)
            exit_code = 130
        else:
            exit_code = _normalized_exit_code(process.returncode)

        for thread in threads:
            thread.join(timeout=5)

    finished_at = _timestamp()
    duration_ms = round((time.monotonic() - started_clock) * 1000, 3)
    redactions_total = label_redactions + command_redactions + sum(item["count"] for item in stream_counts.values())
    safe_cwd = redact_text(str((cwd or Path.cwd()).expanduser().resolve())).text
    manifest: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "label": safe_label if label else None,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_ms": duration_ms,
        "cwd": safe_cwd,
        "command": {"argv": safe_argv, "display": display_command},
        "status": "timed_out" if timed_out else ("success" if exit_code == 0 else "failed"),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "spawn_error": redact_text(spawn_error).text if spawn_error else None,
        "redactions": {
            "total": redactions_total,
            "label": label_redactions,
            "command": command_redactions,
            "stdout": stream_counts["stdout"]["count"],
            "stderr": stream_counts["stderr"]["count"],
        },
        "artifacts": {
            "stdout": _file_metadata(stdout_path),
            "stderr": _file_metadata(stderr_path),
        },
    }
    _write_json(run_dir / "run.json", manifest)
    return manifest, exit_code


def load_manifest(path: Path) -> tuple[Path, dict[str, object]]:
    """Load a run manifest from either a run directory or its run.json file."""

    path = path.expanduser().resolve()
    manifest_path = path / "run.json" if path.is_dir() else path
    if manifest_path.name != "run.json":
        raise ValueError("expected a run directory or a run.json file")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValueError(f"run manifest not found: {manifest_path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid run manifest: {manifest_path}") from error
    if not isinstance(manifest, dict) or manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported or malformed run manifest")
    return manifest_path.parent, manifest


def inspect_run(path: Path) -> dict[str, object]:
    """Return a manifest plus file existence/hash checks for human or JSON output."""

    run_dir, manifest = load_manifest(path)
    integrity: dict[str, dict[str, object]] = {}
    all_valid = True
    artifacts = manifest.get("artifacts", {})
    if not isinstance(artifacts, dict):
        raise ValueError("run manifest has no valid artifacts section")
    for name in STREAM_NAMES:
        metadata = artifacts.get(name)
        if not isinstance(metadata, dict) or not isinstance(metadata.get("path"), str):
            raise ValueError(f"run manifest has no valid {name} artifact")
        raw_artifact_path = run_dir / metadata["path"]
        if raw_artifact_path.is_symlink():
            raise ValueError(f"run manifest points {name} through a symlink")
        artifact_path = raw_artifact_path.resolve()
        if artifact_path.parent != run_dir.resolve():
            raise ValueError(f"run manifest points {name} outside its run directory")
        observed: dict[str, object] = {"path": str(artifact_path), "exists": artifact_path.is_file()}
        if artifact_path.is_file():
            actual = _file_metadata(artifact_path)
            observed.update(
                {
                    "bytes": actual["bytes"],
                    "sha256": actual["sha256"],
                    "matches_manifest": actual == metadata,
                }
            )
        else:
            observed["matches_manifest"] = False
        integrity[name] = observed
        all_valid = all_valid and bool(observed["matches_manifest"])

    return {"manifest": manifest, "integrity": {"valid": all_valid, "artifacts": integrity}}
