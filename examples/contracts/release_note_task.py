from pathlib import Path


target = Path(__file__).with_name("RELEASE.md")
target.write_text(
    "# Release note\n\n## Highlights\n\n- Evidence-first Agent delivery\n",
    encoding="utf-8",
)
print(f"release note written: {target}")
