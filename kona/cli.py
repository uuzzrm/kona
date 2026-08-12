"""Command-line interface for Kona."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .capture import DEFAULT_TIMEOUT_SECONDS, inspect_run, run_capture


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


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.subcommand == "run":
        return _run(args)
    if args.subcommand == "inspect":
        return _inspect(args)
    return 2
