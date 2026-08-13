"""Read-only, redacted explanations of normalized evidence contracts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .capture import _quote_argument
from .contract import ContractSpec, load_contract
from .redaction import redact_argv, redact_text


_CONTENT_ASSERTIONS = frozenset(
    {"file_content_contains", "file_content_not_contains", "file_sha256"}
)
_BROAD_GLOBS = frozenset({"*", "**", "**/*"})


def _safe_text(value: str) -> str:
    return redact_text(value).text


def _safe_value(value: Any) -> Any:
    if isinstance(value, str):
        return _safe_text(value)
    return value


def _describe_assertion(index: int, assertion: dict[str, Any]) -> dict[str, Any]:
    assertion_type = assertion["type"]
    item: dict[str, Any] = {
        "id": f"assertion-{index + 1}",
        "type": assertion_type,
        "implicit": bool(assertion.get("implicit", False)),
    }
    if "path" in assertion:
        item["path"] = _safe_text(assertion["path"])
    if "equals" in assertion:
        item["expected"] = _safe_value(assertion["equals"])
    elif "value" in assertion:
        item["expected"] = _safe_value(assertion["value"])

    if assertion_type == "exit_code":
        description = f"Process exit code must equal {assertion['equals']!r}."
    elif assertion_type == "status":
        description = f"Process status must equal {_safe_text(assertion['equals'])!r}."
    elif assertion_type in {"stdout_contains", "stdout_not_contains", "stderr_contains", "stderr_not_contains"}:
        stream = "Standard output" if assertion_type.startswith("stdout") else "Standard error"
        qualifier = "must not contain" if "not_contains" in assertion_type else "must contain"
        description = f"{stream} {qualifier} {_safe_text(assertion['value'])!r}."
    else:
        path = _safe_text(assertion["path"])
        if assertion_type == "file_exists":
            description = f"File {path!r} existence must equal {assertion['equals']!r}."
        elif assertion_type in {"file_content_contains", "file_content_not_contains"}:
            qualifier = "must not contain" if assertion_type.endswith("not_contains") else "must contain"
            description = f"File {path!r} {qualifier} {_safe_text(assertion['value'])!r}."
        elif assertion_type == "file_sha256":
            description = f"File {path!r} SHA-256 must equal {_safe_text(assertion['equals'])!r}."
        else:
            state = assertion_type.removeprefix("file_").replace("_", " ")
            description = f"File {path!r} {state} state must equal {assertion['equals']!r}."
    item["description"] = description
    return item


def _warnings(spec: ContractSpec) -> list[dict[str, str]]:
    warnings: list[dict[str, str]] = []
    if spec.workspace_policy is None:
        warnings.append(
            {
                "code": "no-workspace-policy",
                "message": "No workspace policy is present; workspace changes are not acceptance-gated.",
            }
        )
    if spec.timeout is None:
        warnings.append(
            {
                "code": "unbounded-timeout",
                "message": "The command timeout is unbounded and the process may run indefinitely.",
            }
        )
    if spec.workspace_policy is not None:
        allow = spec.workspace_policy.allow
        if any(pattern in _BROAD_GLOBS for pattern in allow):
            warnings.append(
                {
                    "code": "broad-change-authority",
                    "message": "A broad allow glob can authorize changes across most or all of the workspace.",
                }
            )
        if allow:
            warnings.append(
                {
                    "code": "allow-globs-include-deletion",
                    "message": "Workspace allow globs authorize deletion as well as creation and modification of matching paths.",
                }
            )
    if not any(assertion["type"] in _CONTENT_ASSERTIONS for assertion in spec.assertions):
        warnings.append(
            {
                "code": "no-content-assertion",
                "message": "No file content or digest assertion checks the contents of a produced artifact.",
            }
        )
    return warnings


def explain_contract(path: Path) -> dict[str, Any]:
    """Load and explain a contract without executing it or writing any files."""

    spec = load_contract(path)
    safe_command, redaction_count = redact_argv(spec.command)
    policy = spec.workspace_policy
    return {
        "valid": True,
        "contract": {
            "name": _safe_text(spec.name),
            "description": _safe_text(spec.description) if spec.description is not None else None,
            "path": _safe_text(str(spec.path)),
            "sha256": spec.contract_sha256,
        },
        "execution": {
            "command": safe_command,
            "cwd": _safe_text(spec.cwd_display),
            "timeout_seconds": spec.timeout,
            "command_redactions": redaction_count,
        },
        "change_authority": {
            "policy_present": policy is not None,
            "mode": policy.mode if policy is not None else None,
            "allow": [_safe_text(pattern) for pattern in policy.allow] if policy else [],
            "deny": [_safe_text(pattern) for pattern in policy.deny] if policy else [],
            "max_changed_paths": policy.max_changed_paths if policy else None,
            "deny_precedence": True if policy is not None else None,
        },
        "assertions": [
            _describe_assertion(index, assertion)
            for index, assertion in enumerate(spec.assertions)
        ],
        "evidence": {
            "process_streams": ["stdout", "stderr"],
            "streams_bounded": True,
            "streams_redacted_best_effort": True,
            "observations": [_safe_text(item) for item in spec.observations],
            "file_contents_persisted": False,
            "contract_sha256_recorded": True,
        },
        "warnings": _warnings(spec),
        "limitations": {
            "semantic_correctness_proven": False,
            "remote_acceptance_proven": False,
            "authenticated": False,
            "signed": False,
            "git_metadata_observed": False,
            "statement": (
                "Kona evidence is integrity-checked but unsigned and unauthenticated; "
                "it does not establish who produced it or prevent a party from rewriting all artifacts and digests. "
                "Workspace policy does not observe .git metadata and is not a process, network, or operating-system sandbox."
            ),
        },
    }


def render_contract_explanation(explanation: dict[str, Any]) -> str:
    """Render an explanation returned by :func:`explain_contract` as stable text."""

    execution = explanation["execution"]
    authority = explanation["change_authority"]
    timeout = (
        "unbounded"
        if execution["timeout_seconds"] is None
        else f"{execution['timeout_seconds']:g} seconds"
    )
    lines = [
        "Execution",
        f"  Command: {' '.join(_quote_argument(argument) for argument in execution['command'])}",
        f"  Workspace: {execution['cwd']}",
        f"  Timeout: {timeout}",
        "",
        "Change authority",
    ]
    if authority["policy_present"]:
        lines.extend(
            [
                f"  Allowed: {', '.join(authority['allow']) or '(none)'}",
                f"  Denied: {', '.join(authority['deny']) or '(none)'}",
                f"  Maximum changed paths: {authority['max_changed_paths']}",
                "  Deny rules take precedence: yes",
            ]
        )
    else:
        lines.append("  Workspace policy: absent")

    lines.extend(["", "Acceptance"])
    for assertion in explanation["assertions"]:
        implicit = " (implicit)" if assertion["implicit"] else ""
        lines.append(f"  {assertion['id']}{implicit}: {assertion['description']}")

    evidence = explanation["evidence"]
    lines.extend(
        [
            "",
            "Evidence collected",
            "  Process streams: bounded stdout and stderr with best-effort redaction",
            f"  Observed paths: {', '.join(evidence['observations']) or '(none)'}",
            "  File contents persisted: no",
            "",
            "Warnings",
        ]
    )
    warnings = explanation["warnings"]
    if warnings:
        lines.extend(f"  [{warning['code']}] {warning['message']}" for warning in warnings)
    else:
        lines.append("  (none)")

    limitations = explanation["limitations"]
    lines.extend(["", "Limitations", f"  {limitations['statement']}"])
    return "\n".join(lines) + "\n"
