from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from kona.baseline import Baseline, BaselineError, apply_baseline, load_baseline, write_baseline


def _finding(fingerprint: str, rule_id: str = "SEC002", severity: str = "high") -> dict[str, object]:
    return {
        "fingerprint": fingerprint,
        "rule_id": rule_id,
        "severity": severity,
        "location": {"path": "settings.py", "line": 1},
        "evidence": {"preview": "[REDACTED]"},
    }


class BaselineModuleTests(unittest.TestCase):
    def test_write_load_and_apply_are_deterministic_and_minimal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = {"findings": [_finding("sha256:" + "b" * 64), _finding("sha256:" + "a" * 64, "CFG003", "medium")]}
            first = root / "first.json"
            second = root / "second.json"

            self.assertEqual(write_baseline(report, first), 2)
            self.assertEqual(write_baseline(report, second), 2)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            baseline_text = first.read_text(encoding="utf-8")
            self.assertNotIn("settings.py", baseline_text)
            self.assertNotIn("REDACTED", baseline_text)
            self.assertEqual(len(load_baseline(first).fingerprints), 2)

            applied = apply_baseline(report, Baseline(frozenset({"sha256:" + "a" * 64})))

            self.assertEqual(len(applied["findings"]), 1)
            self.assertEqual(applied["summary"]["baseline_suppressed"], 1)
            self.assertEqual(applied["summary"]["baseline_unmatched"], 0)
            self.assertTrue(applied["baseline"]["applied"])

    def test_apply_reports_stale_baseline_entries(self) -> None:
        report = {"findings": [_finding("sha256:" + "a" * 64)]}
        applied = apply_baseline(report, Baseline(frozenset({"sha256:" + "a" * 64, "sha256:" + "c" * 64})))

        self.assertEqual(applied["findings"], [])
        self.assertEqual(applied["summary"]["baseline_suppressed"], 1)
        self.assertEqual(applied["summary"]["baseline_unmatched"], 1)

    def test_rejects_malformed_baselines_and_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            malformed = root / "malformed.json"
            malformed.write_text(json.dumps({"schema": "kona.baseline/v1", "tool": {"name": "kona"}, "findings": [{"fingerprint": "bad", "rule_id": "SEC002", "severity": ["high"]}]}), encoding="utf-8")

            with self.assertRaises(BaselineError):
                load_baseline(malformed)
            existing = root / "existing.json"
            existing.write_text("keep", encoding="utf-8")
            with self.assertRaises(BaselineError):
                write_baseline({"findings": []}, existing)
            self.assertEqual(existing.read_text(encoding="utf-8"), "keep")


class BaselineCliTests(unittest.TestCase):
    def test_cli_ratchets_known_findings_and_fails_on_new_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            token = "ghp_" + "A" * 36
            (root / "settings.py").write_text(f'TOKEN = "{token}"\n', encoding="utf-8")
            baseline_path = root / ".kona" / "baseline.json"

            created = subprocess.run(
                [sys.executable, "-m", "kona", "scan", str(root), "--format", "json", "--write-baseline", str(baseline_path), "--fail-on", "high"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(created.returncode, 1, created.stderr)
            self.assertTrue(baseline_path.is_file())
            self.assertNotIn(token, baseline_path.read_text(encoding="utf-8"))

            ratcheted = subprocess.run(
                [sys.executable, "-m", "kona", "scan", str(root), "--format", "json", "--baseline", str(baseline_path), "--fail-on", "high"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(ratcheted.returncode, 0, ratcheted.stderr)
            report = json.loads(ratcheted.stdout)
            self.assertEqual(report["findings"], [])
            self.assertEqual(report["summary"]["baseline_suppressed"], 1)
            self.assertEqual(report["summary"]["baseline_unmatched"], 0)

            (root / "new.py").write_text('TOKEN = "' + "ghp_" + "B" * 36 + '"\n', encoding="utf-8")
            new_finding = subprocess.run(
                [sys.executable, "-m", "kona", "scan", str(root), "--format", "json", "--baseline", str(baseline_path), "--fail-on", "high"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(new_finding.returncode, 1, new_finding.stderr)
            new_report = json.loads(new_finding.stdout)
            self.assertEqual(len(new_report["findings"]), 1)
            self.assertEqual(new_report["findings"][0]["location"]["path"], "new.py")

    def test_cli_rejects_invalid_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline_path = root / "invalid.json"
            baseline_path.write_text("{}", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "kona", "scan", str(root), "--baseline", str(baseline_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("baseline", result.stderr.casefold())


if __name__ == "__main__":
    unittest.main()
