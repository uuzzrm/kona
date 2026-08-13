"""Command-line interface for Kona."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .capture import DEFAULT_TIMEOUT_SECONDS, inspect_run, run_capture
from .contract import ContractError, init_contract, inspect_contract_report, load_contract, run_contract
from .redaction import redact_argv, redact_text


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kona",
        description="Capture bounded, redacted evidence from a local Agent command.",
    )
    commands = parser.add_subparsers(dest="subcommand", required=True)

    run = commands.add_parser("run", help="run a command and capture its output")
    run.add_argument("--output", type=Path, default=Path(".kona/runs"), help="directory for run folders")
    run.add_argument("--cwd", type=Path, help="working directory for the child command")
    run.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="seconds before the child is terminated; use 0 to disable (default: 300)",
    )
    run.add_argument("--label", help="short label stored in the manifest")
    run.add_argument("--quiet", action="store_true", help="do not tee child output to the current terminal")
    run.add_argument("command", nargs=argparse.REMAINDER, help="command to execute after --")

    inspect = commands.add_parser("inspect", help="check a run manifest and its captured files")
    inspect.add_argument("run", type=Path, help="run directory or path to run.json")
    inspect.add_argument("--json", action="store_true", dest="as_json", help="print machine-readable JSON")

    contract = commands.add_parser("contract", help="run and inspect declarative Agent task contracts")
    contract_commands = contract.add_subparsers(dest="contract_subcommand", required=True)

    contract_validate = contract_commands.add_parser("validate", help="validate a contract without executing it")
    contract_validate.add_argument("contract", type=Path, help="path to a JSON contract")
    contract_validate.add_argument("--json", action="store_true", dest="as_json", help="print machine-readable JSON")

    contract_init = contract_commands.add_parser("init", help="write a starter contract without overwriting files")
    contract_init.add_argument("path", type=Path, help="new JSON contract path")

    contract_run = contract_commands.add_parser("run", help="execute a contract and write an evidence report")
    contract_run.add_argument("contract", type=Path, help="path to a JSON contract")
    contract_run.add_argument("--output", type=Path, default=Path(".kona/runs"), help="directory for run folders")
    contract_run.add_argument("--quiet", action="store_true", help="do not tee child output to the current terminal")

    contract_inspect = contract_commands.add_parser("inspect", help="verify a contract evidence report")
    contract_inspect.add_argument("report", type=Path, help="contract run directory or report.json")
    contract_inspect.add_argument("--json", action="store_true", dest="as_json", help="print machine-readable JSON")
    return parser


def _run(args: argparse.Namespace) -> int:
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        print("kona run requires a command after --", file=sys.stderr)
        return 2

    try:
        manifest, exit_code = run_capture(
            command,
            output_root=args.output,
            cwd=args.cwd,
            timeout=args.timeout,
            label=args.label,
            quiet=args.quiet,
        )
    except (OSError, ValueError) as error:
        print(f"kona: {error}", file=sys.stderr)
        return 2

    print(
        f"[kona] {manifest['status']} run={manifest['run_id']} "
        f"exit={manifest['exit_code']} redactions={manifest['redactions']['total']}",
        file=sys.stderr,
    )
    print(f"[kona] evidence={args.output.expanduser().resolve() / str(manifest['run_id'])}", file=sys.stderr)
    return exit_code


def _inspect(args: argparse.Namespace) -> int:
    try:
        report = inspect_run(args.run)
    except (OSError, ValueError) as error:
        print(f"kona inspect: {error}", file=sys.stderr)
        return 2

    if args.as_json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0 if report["integrity"]["valid"] else 1

    manifest = report["manifest"]
    integrity = report["integrity"]
    print(f"run_id: {manifest['run_id']}")
    print(f"status: {manifest['status']} (exit {manifest['exit_code']})")
    print(f"duration_ms: {manifest['duration_ms']}")
    print(f"command: {manifest['command']['display']}")
    print(f"redactions: {manifest['redactions']['total']}")
    print(f"integrity: {'PASS' if integrity['valid'] else 'FAIL'}")
    for name, artifact in integrity["artifacts"].items():
        print(f"  {name}: {'PASS' if artifact['matches_manifest'] else 'FAIL'} ({artifact['path']})")
    return 0 if integrity["valid"] else 1


def _contract_validate(args: argparse.Namespace) -> int:
    try:
        spec = load_contract(args.contract)
    except (ContractError, OSError, ValueError) as error:
        print(f"kona contract validate: {redact_text(str(error)).text}", file=sys.stderr)
        return 2
    result = {
        "valid": True,
        "name": redact_text(spec.name).text,
        "version": 1,
        "command": redact_argv(spec.command)[0],
        "cwd": redact_text(spec.cwd_display).text,
        "timeout_seconds": spec.timeout,
        "observations": [redact_text(path).text for path in spec.observations],
        "assertions": [
            {
                "id": f"assertion-{index + 1}",
                "type": assertion["type"],
                "path": redact_text(assertion["path"]).text if "path" in assertion else None,
                "expected": redact_text(str(assertion.get("equals", assertion.get("value")))).text,
            }
            for index, assertion in enumerate(spec.assertions)
        ],
        "sha256": spec.contract_sha256,
    }
    if args.as_json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        safe_command = redact_argv(spec.command)[0]
        print(f"valid: yes\nname: {redact_text(spec.name).text}\ncommand: {' '.join(safe_command)}\nassertions: {len(spec.assertions)}\nsha256: {spec.contract_sha256}")
    return 0


def _contract_init(args: argparse.Namespace) -> int:
    try:
        path = init_contract(args.path)
    except (ContractError, OSError, ValueError) as error:
        print(f"kona contract init: {redact_text(str(error)).text}", file=sys.stderr)
        return 2
    print(f"[kona] starter contract={path}")
    return 0


def _contract_run(args: argparse.Namespace) -> int:
    try:
        report, exit_code = run_contract(args.contract, output_root=args.output, quiet=args.quiet)
    except (ContractError, OSError, ValueError) as error:
        print(f"kona contract run: {redact_text(str(error)).text}", file=sys.stderr)
        return 2
    run_dir = args.output.expanduser().resolve() / str(report["run"]["run_id"])
    summary = report["summary"]
    print(
        f"[kona] contract={report['contract']['name']} status={summary['status']} "
        f"assertions={summary['passed_assertions']}/{summary['total_assertions']}",
        file=sys.stderr,
    )
    print(f"[kona] report={run_dir / 'report.json'}", file=sys.stderr)
    return exit_code


def _contract_inspect(args: argparse.Namespace) -> int:
    try:
        inspected = inspect_contract_report(args.report)
    except (ContractError, OSError, ValueError) as error:
        print(f"kona contract inspect: {redact_text(str(error)).text}", file=sys.stderr)
        return 2
    if args.as_json:
        print(json.dumps(inspected, indent=2, ensure_ascii=False))
        return 0 if inspected["integrity"]["valid"] and inspected["report"]["summary"]["status"] == "passed" else 1
    report = inspected["report"]
    summary = report["summary"]
    integrity = inspected["integrity"]
    print(f"status: {summary['status']} ({summary['passed_assertions']}/{summary['total_assertions']} assertions)")
    print(f"report: {args.report.expanduser().resolve()}")
    print(f"integrity: {'PASS' if integrity['valid'] else 'FAIL'}")
    print(f"  process artifacts: {'PASS' if integrity['run_artifacts']['valid'] else 'FAIL'}")
    print(f"  report markdown: {'PASS' if integrity['report_markdown']['valid'] else 'FAIL'}")
    print(f"  report digest: {'PASS' if integrity['report_digest']['valid'] else 'FAIL'}")
    return 0 if integrity["valid"] and summary["status"] == "passed" else 1


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.subcommand == "run":
        return _run(args)
    if args.subcommand == "inspect":
        return _inspect(args)
    if args.subcommand == "contract":
        if args.contract_subcommand == "validate":
            return _contract_validate(args)
        if args.contract_subcommand == "init":
            return _contract_init(args)
        if args.contract_subcommand == "run":
            return _contract_run(args)
        if args.contract_subcommand == "inspect":
            return _contract_inspect(args)
    return 2
