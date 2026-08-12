"""Validate the repository's Skill metadata without third-party dependencies."""

from __future__ import annotations

import re
from pathlib import Path
import sys


NAME_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _frontmatter(skill: Path) -> dict[str, str]:
    lines = skill.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "---":
        raise ValueError("SKILL.md must start with YAML frontmatter")
    try:
        end = lines.index("---", 1)
    except ValueError as error:
        raise ValueError("SKILL.md frontmatter is not closed") from error
    values: dict[str, str] = {}
    for line in lines[1:end]:
        key, separator, value = line.partition(":")
        if not separator or not key.strip() or not value.strip():
            raise ValueError(f"invalid frontmatter line: {line!r}")
        values[key.strip()] = value.strip()
    return values


def validate(skill_dir: Path) -> None:
    skill = skill_dir / "SKILL.md"
    interface = skill_dir / "agents" / "openai.yaml"
    values = _frontmatter(skill)
    name = values.get("name", "")
    description = values.get("description", "")
    if not NAME_PATTERN.fullmatch(name):
        raise ValueError("Skill name must use lowercase hyphen-case")
    if not description or len(description) > 1024 or "<" in description or ">" in description:
        raise ValueError("Skill description is missing or outside the allowed boundary")
    interface_text = interface.read_text(encoding="utf-8")
    for required in ("display_name:", "short_description:", "default_prompt:"):
        if required not in interface_text:
            raise ValueError(f"openai.yaml is missing {required}")
    if "$" + name not in interface_text:
        raise ValueError("default_prompt must mention the Skill name")


def main(argv: list[str] | None = None) -> int:
    path = Path(argv[0] if argv else "skills/kona-capture")
    try:
        validate(path)
    except (OSError, ValueError) as error:
        print(f"Skill metadata invalid: {error}", file=sys.stderr)
        return 1
    print(f"Skill metadata is valid: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
