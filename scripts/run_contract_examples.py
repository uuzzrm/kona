"""Run the repository's contract examples in isolated temporary workspaces."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


EXAMPLE_FILES = (
    "release-note.json",
    "release_note_task.py",
    "quality-gate.json",
    "quality-gate-failing.json",
    "quality_gate_task.py",
)


def _run(command: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, check=False)
    if completed.returncode not in {0, 1}:
        raise RuntimeError(
            f"command failed with {completed.returncode}: {' '.join(command)}\n"
            f"stdout: {completed.stdout}\nstderr: {completed.stderr}"
        )
    return completed


def _run_example(workspace: Path, contract_name: str, expected_run_code: int, repo_root: Path) -> str:
    contract = workspace / contract_name
    output = workspace / "runs" / contract.stem
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root) + os.pathsep + env.get("PYTHONPATH", "")

    validation = _run([sys.executable, "-m", "kona", "contract", "validate", str(contract)], cwd=workspace, env=env)
    if validation.returncode != 0:
        raise RuntimeError(f"validation failed for {contract_name}: {validation.stderr}")

    execution = _run(
        [sys.executable, "-m", "kona", "contract", "run", str(contract), "--output", str(output), "--quiet"],
        cwd=workspace,
        env=env,
    )
    if execution.returncode != expected_run_code:
        raise RuntimeError(
            f"unexpected run code for {contract_name}: expected {expected_run_code}, got {execution.returncode}\n"
            f"stdout: {execution.stdout}\nstderr: {execution.stderr}"
        )

    run_dirs = sorted(path for path in output.iterdir() if path.is_dir())
    if len(run_dirs) != 1:
        raise RuntimeError(f"expected one run directory for {contract_name}, found {len(run_dirs)}")
    run_dir = run_dirs[0]
    inspected = _run(
        [sys.executable, "-m", "kona", "contract", "inspect", str(run_dir), "--json"],
        cwd=workspace,
        env=env,
    )
    if inspected.returncode != 0:
        raise RuntimeError(f"inspection failed for {contract_name}: {inspected.stderr}")
    inspection = json.loads(inspected.stdout)
    if inspection["integrity"]["valid"] is not True:
        raise RuntimeError(f"inspection reported invalid evidence for {contract_name}")
    return str(run_dir)


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    source = repo_root / "examples" / "contracts"
    with tempfile.TemporaryDirectory(prefix="kona-contract-examples-") as temporary:
        workspace = Path(temporary)
        for filename in EXAMPLE_FILES:
            shutil.copy2(source / filename, workspace / filename)
        passing_release = _run_example(workspace, "release-note.json", 0, repo_root)
        passing_quality = _run_example(workspace, "quality-gate.json", 0, repo_root)
        failing_quality = _run_example(workspace, "quality-gate-failing.json", 1, repo_root)
        print(f"contract examples passed: release={passing_release}, quality={passing_quality}, failing={failing_quality}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
