"""Command-line interface for Kona."""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import sys

from .capture import DEFAULT_TIMEOUT_SECONDS, inspect_run, run_capture
from .bundle import BundleError, create_bundle, verify_bundle
from .authoring import AuthoringRequest, author_contract, list_templates
from .contract import ContractError, init_contract, inspect_contract_report, load_contract, run_contract
from .explanation import explain_contract, render_contract_explanation
from .redaction import redact_argv, redact_text
from .scanner import ScanError, ScanPolicy, render_scan_report, scan_repository, threshold_exit_code
from .providers import ProviderConfig, ProviderError, build_findings_payload, explain_findings


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kona",
        description="Kona Guard: offline repository security inspection and verifiable Agent evidence. Start with: kona scan .",
    )
    commands = parser.add_subparsers(dest="subcommand")

    scan = commands.add_parser("scan", help="inspect a repository for deterministic Agent security risks")
    scan.add_argument("path", nargs="?", type=Path, default=Path("."), help="repository directory (default: current directory)")
    scan.add_argument("--format", choices=("text", "json"), default="text")
    scan.add_argument("--output", type=Path, help="write the rendered report without overwriting")
    scan.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "info"), default="high")

    explain = commands.add_parser("explain", help="optionally send redacted findings, never source, for advisory AI explanation")
    explain.add_argument("path", nargs="?", type=Path, default=Path("."))
    explain.add_argument("--provider", required=True, choices=("deepseek", "anthropic"))
    explain.add_argument("--model")
    explain.add_argument("--base-url")
    explain.add_argument("--allow-custom-base-url", action="store_true")
    explain.add_argument("--preview", action="store_true", help="print the exact findings-only payload without network access")
    explain.add_argument("--yes", action="store_true", help="confirm sending the previewed payload")
    explain.add_argument("--format", choices=("text", "json"), default="text")

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

    contract_init = contract_commands.add_parser("init", help="write a starter or template-based contract")
    contract_init.add_argument("path", type=Path, help="new JSON contract path")
    contract_init.add_argument("--template", choices=[item.name for item in list_templates()])
    contract_init.add_argument("--name")
    contract_init.add_argument("--description")
    contract_init.add_argument("--cwd")
    contract_init.add_argument("--timeout", type=float)
    contract_init.add_argument("--allow", action="append", default=[])
    contract_init.add_argument("--deny", action="append", default=[])
    contract_init.add_argument("--observe", action="append", default=[])
    contract_init.add_argument("--output", action="append", default=[], dest="outputs")
    contract_init.add_argument("command", nargs="*", help="authorized argv after --")

    contract_templates = contract_commands.add_parser("templates", help="list safe authoring templates")
    contract_templates.add_argument("--json", action="store_true", dest="as_json")

    contract_explain = contract_commands.add_parser("explain", help="explain authority, evidence, and risks")
    contract_explain.add_argument("contract", type=Path)
    contract_explain.add_argument("--json", action="store_true", dest="as_json")

    contract_run = contract_commands.add_parser("run", help="execute a contract and write an evidence report")
    contract_run.add_argument("contract", type=Path, help="path to a JSON contract")
    contract_run.add_argument("--output", type=Path, default=Path(".kona/runs"), help="directory for run folders")
    contract_run.add_argument("--quiet", action="store_true", help="do not tee child output to the current terminal")

    contract_inspect = contract_commands.add_parser("inspect", help="verify a contract evidence report")
    contract_inspect.add_argument("report", type=Path, help="contract run directory or report.json")
    contract_inspect.add_argument("--json", action="store_true", dest="as_json", help="print machine-readable JSON")

    bundle = commands.add_parser("bundle", help="create and verify portable evidence bundles")
    bundle_commands = bundle.add_subparsers(dest="bundle_subcommand", required=True)
    bundle_create = bundle_commands.add_parser("create", help="create a deterministic portable evidence bundle")
    bundle_create.add_argument("run", type=Path, help="contract run directory or report.json")
    bundle_create.add_argument("--output", type=Path, required=True, help="new bundle directory or .zip path")
    bundle_verify = bundle_commands.add_parser("verify", help="verify a bundle offline")
    bundle_verify.add_argument("bundle", type=Path, help="bundle directory or .zip path")
    bundle_verify.add_argument("--json", action="store_true", dest="as_json", help="print machine-readable JSON")
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


def _scan(args: argparse.Namespace) -> int:
    try:
        report = scan_repository(args.path, ScanPolicy())
        rendered = render_scan_report(report, format=args.format)
        if args.output is not None:
            output = args.output.expanduser()
            if output.exists() or output.is_symlink():
                raise ScanError(f"refusing to overwrite scan report: {args.output}")
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(rendered)
        print(rendered, end="")
        return threshold_exit_code(report, args.fail_on)
    except (ScanError, OSError, ValueError) as error:
        print(f"kona scan: {redact_text(str(error)).text}", file=sys.stderr)
        return 2


def _explain_scan(args: argparse.Namespace) -> int:
    try:
        report = scan_repository(args.path, ScanPolicy())
        payload = build_findings_payload(report)
        if args.preview:
            print(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True))
            return 0
        if not args.yes:
            raise ProviderError("review `kona explain --preview` first, then pass --yes to allow network access")
        result = explain_findings(report, ProviderConfig(args.provider, args.model, args.base_url, args.allow_custom_base_url))
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) if args.format == "json" else result["explanation"] + "\n\n" + result["notice"])
        return 0
    except (ScanError, ProviderError, OSError, ValueError) as error:
        print(f"kona explain: {redact_text(str(error)).text}", file=sys.stderr)
        return 2


def _control_center() -> int:
    """Run the dependency-free TTY adapter over the same scanner interface."""

    last_report: dict[str, object] | None = None
    last_status = 0
    while True:
        print(
            "\nKona Guard — Project Security Inspector\n"
            "Mode: deterministic, offline, read-only\n"
            "AI provider: not configured (network off)\n\n"
            "  1  Scan this project\n"
            "  2  Review last scan\n"
            "  3  Export last scan as JSON\n"
            "  4  Explain last scan with AI (opt-in network)\n"
            "  5  Show contract templates\n"
            "  q  Quit\n"
        )
        try:
            choice = input("Select: ").strip().casefold()
        except EOFError:
            return 0
        if choice == "q":
            return last_status
        if choice == "1":
            try:
                last_report = scan_repository(Path("."), ScanPolicy())
                print(render_scan_report(last_report), end="")
                last_status = threshold_exit_code(last_report, "high")
                print(f"Control-center exit status is now {last_status}.")
            except (ScanError, OSError, ValueError) as error:
                print(f"Scan failed: {redact_text(str(error)).text}", file=sys.stderr)
                last_status = 2
        elif choice == "2":
            print(render_scan_report(last_report), end="") if last_report else print("No scan has been run in this session.")
        elif choice == "3":
            if last_report is None:
                print("No scan has been run in this session.")
            else:
                output = Path("kona-findings.json")
                if output.exists() or output.is_symlink():
                    print(f"Refusing to overwrite {output}.")
                else:
                    output.write_text(render_scan_report(last_report, format="json"), encoding="utf-8", newline="\n")
                    print(f"Wrote {output.resolve()}")
        elif choice == "4":
            if last_report is None:
                print("No scan has been run in this session.")
                continue
            provider = input("Provider (deepseek/anthropic): ").strip().casefold()
            if provider not in {"deepseek", "anthropic"}:
                print("Unknown provider.")
                continue
            model = input("Model (required): ").strip()
            if not model:
                print("A model is required.")
                continue
            payload = build_findings_payload(last_report)
            print("Exact data to be sent (no source, paths, or evidence):")
            print(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True))
            if input("Send to the official provider endpoint? [y/N]: ").strip().casefold() != "y":
                print("Cancelled; no network request was made.")
                continue
            env_name = "DEEPSEEK_API_KEY" if provider == "deepseek" else "ANTHROPIC_API_KEY"
            session_key = getpass.getpass(f"{env_name} (session only; hidden): ")
            if not session_key:
                print("No key entered; cancelled.")
                continue
            previous_key = os.environ.get(env_name)
            try:
                os.environ[env_name] = session_key
                result = explain_findings(last_report, ProviderConfig(provider, model=model))
                print(result["explanation"])
                print(result["notice"])
            except ProviderError as error:
                print(f"AI explanation failed: {redact_text(str(error)).text}", file=sys.stderr)
            finally:
                if previous_key is None:
                    os.environ.pop(env_name, None)
                else:
                    os.environ[env_name] = previous_key
                session_key = ""
        elif choice == "5":
            for item in list_templates():
                print(f"  {item.name}: {item.description}")
        else:
            print("Unknown selection.")


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
        if args.template is None:
            if any((args.command, args.allow, args.deny, args.observe, args.outputs, args.name, args.description, args.cwd, args.timeout is not None)):
                raise ContractError("template authoring options require --template")
            path = init_contract(args.path)
        else:
            command = list(args.command)
            if command and command[0] == "--":
                command.pop(0)
            path = author_contract(
                AuthoringRequest(
                    template=args.template,
                    name=args.name or "my-agent-task",
                    description=args.description,
                    cwd=args.cwd or ".",
                    timeout=300 if args.timeout is None else args.timeout,
                    command=command,
                    allow=args.allow,
                    deny=args.deny,
                    observations=args.observe,
                    outputs=args.outputs,
                ),
                args.path,
            )
    except (ContractError, OSError, ValueError) as error:
        print(f"kona contract init: {redact_text(str(error)).text}", file=sys.stderr)
        return 2
    print(f"[kona] starter contract={path}")
    return 0


def _contract_templates(args: argparse.Namespace) -> int:
    templates = [
        {"name": item.name, "description": item.description, "requirements": list(item.requirements)}
        for item in list_templates()
    ]
    if args.as_json:
        print(json.dumps({"templates": templates}, indent=2, ensure_ascii=False))
    else:
        for item in templates:
            print(f"{item['name']}: {item['description']} (requires: {', '.join(item['requirements'])})")
    return 0


def _contract_explain(args: argparse.Namespace) -> int:
    try:
        explanation = explain_contract(args.contract)
    except (ContractError, OSError, ValueError) as error:
        print(f"kona contract explain: {redact_text(str(error)).text}", file=sys.stderr)
        return 2
    if args.as_json:
        print(json.dumps(explanation, indent=2, ensure_ascii=False))
    else:
        print(render_contract_explanation(explanation), end="")
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


def _bundle_create(args: argparse.Namespace) -> int:
    try:
        manifest = create_bundle(args.run, args.output)
    except (BundleError, OSError, ValueError) as error:
        print(f"kona bundle create: {redact_text(str(error)).text}", file=sys.stderr)
        return 2
    print(f"[kona] bundle={args.output.expanduser().resolve()} run={manifest['run_id']}")
    return 0


def _bundle_verify(args: argparse.Namespace) -> int:
    try:
        result = verify_bundle(args.bundle)
    except (BundleError, OSError, ValueError) as error:
        print(f"kona bundle verify: {redact_text(str(error)).text}", file=sys.stderr)
        return 2
    if args.as_json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"valid: yes\naccepted: {'yes' if result['accepted'] else 'no'}\nauthenticated: no")
    return 0 if result["accepted"] else 1


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    authored_command: list[str] | None = None
    if len(raw_argv) >= 2 and raw_argv[:2] == ["contract", "init"] and "--" in raw_argv:
        separator = raw_argv.index("--")
        authored_command = raw_argv[separator + 1 :]
        raw_argv = raw_argv[:separator]
    args = _build_parser().parse_args(raw_argv)
    if authored_command is not None:
        args.command = authored_command
    if args.subcommand is None:
        if sys.stdin.isatty() and sys.stdout.isatty():
            try:
                return _control_center()
            except KeyboardInterrupt:
                print("", file=sys.stderr)
                return 130
        _build_parser().print_help()
        return 0
    if args.subcommand == "run":
        return _run(args)
    if args.subcommand == "scan":
        return _scan(args)
    if args.subcommand == "explain":
        return _explain_scan(args)
    if args.subcommand == "inspect":
        return _inspect(args)
    if args.subcommand == "contract":
        if args.contract_subcommand == "validate":
            return _contract_validate(args)
        if args.contract_subcommand == "init":
            return _contract_init(args)
        if args.contract_subcommand == "templates":
            return _contract_templates(args)
        if args.contract_subcommand == "explain":
            return _contract_explain(args)
        if args.contract_subcommand == "run":
            return _contract_run(args)
        if args.contract_subcommand == "inspect":
            return _contract_inspect(args)
    if args.subcommand == "bundle":
        if args.bundle_subcommand == "create":
            return _bundle_create(args)
        if args.bundle_subcommand == "verify":
            return _bundle_verify(args)
    return 2
