"""Compile explicit authoring requests into ordinary Kona contract v1 files.

Templates exist only at authoring time.  The resulting JSON contains no hidden
permissions and is validated by :func:`kona.contract.load_contract` before it
is returned to the caller.
"""

from __future__ import annotations

from dataclasses import dataclass
import fnmatch
import json
from pathlib import Path
from typing import Sequence

from .contract import CONTRACT_SCHEMA_VERSION, ContractError, load_contract


_CONSERVATIVE_DENY = (
    ".github/**",
    ".env",
    "**/.env",
    ".env.*",
    "**/.env.*",
    "*credential*",
    "**/*credential*",
    "*secret*",
    "**/*secret*",
    "*token*",
    "**/*token*",
    "AGENTS.md",
    "**/AGENTS.md",
    "CLAUDE.md",
    "**/CLAUDE.md",
    "CODEX.md",
    "**/CODEX.md",
    "pyproject.toml",
    "**/pyproject.toml",
    "package.json",
    "**/package.json",
    "package-lock.json",
    "**/package-lock.json",
    "pnpm-lock.yaml",
    "**/pnpm-lock.yaml",
    "yarn.lock",
    "**/yarn.lock",
)


@dataclass(frozen=True)
class TemplateSummary:
    """Stable metadata for one built-in authoring template."""

    name: str
    description: str
    requirements: tuple[str, ...]


@dataclass(frozen=True)
class AuthoringRequest:
    """All authority needed to compile a contract; no repository state is inferred.

    ``command`` is an argv sequence and is never interpreted as a shell string.
    ``required_text`` contains ``(output_path, text)`` pairs and is supported by
    the ``artifact-generator`` template.
    """

    template: str
    name: str
    command: Sequence[str]
    description: str | None = None
    cwd: str = "."
    timeout: int | float | None = 300
    allow: Sequence[str] = ()
    deny: Sequence[str] = ()
    observations: Sequence[str] = ()
    outputs: Sequence[str] = ()
    required_text: Sequence[tuple[str, str]] = ()
    max_changed_paths: int = 50


_TEMPLATES = (
    TemplateSummary(
        "read-only-check",
        "Run an observable check while rejecting every workspace change.",
        ("command",),
    ),
    TemplateSummary(
        "coding-agent",
        "Verify a coding task and permit changes only in explicitly allowed paths.",
        ("command", "allow"),
    ),
    TemplateSummary(
        "artifact-generator",
        "Generate explicitly named artifacts and require each output to exist.",
        ("command", "outputs"),
    ),
)


def list_templates() -> tuple[TemplateSummary, ...]:
    """Return built-in templates in deterministic display order."""

    return _TEMPLATES


def _unique(values: Sequence[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def _output_authority(outputs: Sequence[str]) -> list[str]:
    authority: list[str] = []
    for output in outputs:
        parts = Path(output).parts
        authority.extend(Path(*parts[:index]).as_posix() for index in range(1, len(parts)))
        authority.append(output)
    return _unique(authority)


def _compile(request: AuthoringRequest) -> dict[str, object]:
    template_names = {item.name for item in _TEMPLATES}
    if request.template not in template_names:
        raise ContractError(f"unknown contract template: {request.template}")
    if isinstance(request.command, (str, bytes)):
        raise ContractError("command must be an argv sequence, not a shell string")

    allow = _unique(request.allow)
    outputs = _unique(request.outputs)
    observations = _unique(request.observations)
    deny = _unique((*_CONSERVATIVE_DENY, *request.deny))

    if request.template == "coding-agent" and not allow:
        raise ContractError("coding-agent requires at least one explicitly allowed path")
    if request.template == "artifact-generator" and not outputs:
        raise ContractError("artifact-generator requires at least one output path")
    if request.template == "artifact-generator":
        blocked = [path for path in outputs if any(fnmatch.fnmatchcase(path, pattern) for pattern in deny)]
        if blocked:
            raise ContractError(f"artifact output is denied by the effective workspace policy: {blocked[0]}")
    if request.template != "artifact-generator" and request.required_text:
        raise ContractError("required_text is supported only by artifact-generator")

    assertions: list[dict[str, object]] = [{"type": "exit_code", "equals": 0}]
    if request.template == "artifact-generator":
        observations = _unique((*observations, *outputs))
        assertions.extend({"type": "file_exists", "path": path} for path in outputs)
        output_set = set(outputs)
        for path, value in request.required_text:
            if path not in output_set:
                raise ContractError(f"required_text path is not a declared output: {path}")
            assertions.append({"type": "file_content_contains", "path": path, "value": value})

    policy_allow = allow if request.template == "coding-agent" else _output_authority(outputs) if request.template == "artifact-generator" else []
    contract: dict[str, object] = {
        "version": CONTRACT_SCHEMA_VERSION,
        "name": request.name,
        "description": request.description
        or {
            "read-only-check": "Run a command and reject all workspace changes.",
            "coding-agent": "Verify command success and reject changes outside the explicitly approved scope.",
            "artifact-generator": "Generate declared artifacts and verify that every output exists.",
        }[request.template],
        "cwd": request.cwd,
        "command": list(request.command),
        "timeout": request.timeout,
        "workspace_policy": {
            "mode": "filesystem",
            "allow": policy_allow,
            "deny": deny,
            "max_changed_paths": request.max_changed_paths,
        },
        "observations": observations,
        "assertions": assertions,
    }
    return contract


def author_contract(request: AuthoringRequest, output: Path) -> Path:
    """Compile, exclusively create, validate, and return a contract path.

    This function does not execute the authored command.  Existing files and
    symlinks are never overwritten.  If authoritative validation fails, the
    newly created contract is removed before the error is re-raised.
    """

    candidate = output.expanduser()
    if candidate.exists() or candidate.is_symlink():
        raise ContractError(f"refusing to overwrite existing contract: {output}")
    contract = _compile(request)
    candidate.parent.mkdir(parents=True, exist_ok=True)
    try:
        with candidate.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(contract, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        load_contract(candidate)
    except FileExistsError as error:
        raise ContractError(f"refusing to overwrite existing contract: {output}") from error
    except Exception:
        if candidate.is_file() and not candidate.is_symlink():
            candidate.unlink()
        raise
    return candidate.resolve()


__all__ = ["AuthoringRequest", "TemplateSummary", "author_contract", "list_templates"]
