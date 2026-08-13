"""GitHub Actions adapter for running Kona as a reviewable CI gate."""

from __future__ import annotations

import argparse
import html
import json
import os
from pathlib import Path
import sys
from typing import Any

from .bundle import BundleError, create_bundle, verify_bundle
from .contract import ContractError, run_contract
from .redaction import redact_text


def _append(path_value: str | None, text: str) -> None:
    if not path_value:
        return
    with Path(path_value).open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def _output(name: str, value: str) -> None:
    _append(os.environ.get("GITHUB_OUTPUT"), f"{name}={value}\n")


def _annotation(level: str, title: str, message: str) -> None:
    safe_title = title.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    safe_message = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::{level} title={safe_title}::{safe_message}")


def _summary(result: dict[str, Any]) -> str:
    accepted = result.get("accepted") is True
    status = "PASS" if accepted else "FAIL"
    report = result.get("report", {})
    summary = report.get("summary", {})
    policy = report.get("workspace_policy")
    lines = [
        f"## Kona Agent gate: {status}",
        "",
        f"- Contract: `{html.escape(str(result.get('contract_name', 'unknown'))).replace('`', '&#96;')}`",
        f"- Assertions: `{summary.get('passed_assertions', 0)}/{summary.get('total_assertions', 0)}`",
        f"- Bundle verified: `{'yes' if result.get('bundle_valid') else 'no'}`",
        "- Bundle authenticated: `no` (Bundle v1 is unsigned)",
    ]
    if isinstance(policy, dict):
        lines.extend(
            [
                f"- Workspace changes: `{len(policy.get('changed_paths', []))}`",
                f"- Unexpected changes: `{len(policy.get('unexpected', []))}`",
                f"- Denied changes: `{len(policy.get('denied', []))}`",
            ]
        )
        for heading, key in (("Denied paths", "denied"), ("Unexpected paths", "unexpected")):
            paths = policy.get(key, [])
            if paths:
                lines.extend(["", f"### {heading}", "", *[f"- `{html.escape(str(path)).replace('`', '&#96;')}`" for path in paths]])
    lines.extend(
        [
            "",
            "The uploaded `.kona.zip` is a portable offline-verifiable evidence record. It does not prove semantic correctness or producer identity.",
            "",
        ]
    )
    return "\n".join(lines)


def run_gate(contract: Path, output_root: Path, bundle_path: Path, *, quiet: bool = True) -> dict[str, Any]:
    """Run, bundle, independently verify, and return one CI gate result."""
    report, run_code = run_contract(contract, output_root=output_root, quiet=quiet)
    run_dir = output_root.expanduser().resolve() / str(report["run"]["run_id"])
    create_bundle(run_dir, bundle_path)
    verified = verify_bundle(bundle_path)
    accepted = run_code == 0 and verified["valid"] and verified["accepted"]
    return {
        "accepted": accepted,
        "exit_code": 0 if accepted else 1,
        "contract_name": report["contract"]["name"],
        "run_id": report["run"]["run_id"],
        "run_dir": str(run_dir),
        "bundle": str(bundle_path.expanduser().resolve()),
        "bundle_valid": verified["valid"],
        "report": report,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a Kona contract as a GitHub Actions gate")
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = run_gate(args.contract, args.output_root, args.bundle)
    except (BundleError, ContractError, OSError, ValueError) as error:
        message = redact_text(str(error)).text
        _annotation("error", "Kona gate could not complete", message)
        safe_message = html.escape(message)
        _append(os.environ.get("GITHUB_STEP_SUMMARY"), f"## Kona Agent gate: ERROR\n\n{safe_message}\n")
        diagnostic = str(args.output_root.expanduser().resolve()) if args.output_root.exists() else ""
        for name, value in (("outcome", "error"), ("accepted", "false"), ("bundle", ""), ("diagnostic", diagnostic), ("run-id", ""), ("exit-code", "2")):
            _output(name, value)
        return 0
    accepted = result["accepted"]
    _append(os.environ.get("GITHUB_STEP_SUMMARY"), _summary(result))
    if not accepted:
        _annotation("error", "Kona Agent gate rejected the task", "The contract, workspace policy, or evidence verification did not pass. See the job summary and bundle artifact.")
    for name, value in (
        ("outcome", "passed" if accepted else "rejected"),
        ("accepted", "true" if accepted else "false"),
        ("bundle", result["bundle"]),
        ("diagnostic", result["run_dir"]),
        ("run-id", str(result["run_id"])),
        ("exit-code", str(result["exit_code"])),
    ):
        _output(name, value)
    print(json.dumps({key: value for key, value in result.items() if key != "report"}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
