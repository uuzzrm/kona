from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from kona.capture import inspect_run, run_capture
from kona.redaction import RedactionResult, redact_argv, redact_text


class RedactionTests(unittest.TestCase):
    def test_common_secret_shapes_are_redacted(self) -> None:
        result = redact_text(
            "token=super-secret password: hunter2 Authorization: Bearer abc.def "
            "sk-12345678901234567890 ghp_123456789012345678901234567890"
        )
        self.assertEqual(result.count, 5)
        self.assertNotIn("super-secret", result.text)
        self.assertNotIn("hunter2", result.text)
        self.assertNotIn("abc.def", result.text)
        self.assertNotIn("sk-123", result.text)
        self.assertNotIn("ghp_", result.text)

    def test_normal_text_is_left_alone(self) -> None:
        self.assertEqual(redact_text("agent completed 3 checks"), RedactionResult("agent completed 3 checks", 0))

    def test_sensitive_flag_value_is_redacted(self) -> None:
        safe, count = redact_argv(["agent", "--token", "plain-secret", "--mode", "safe"])
        self.assertEqual(safe, ["agent", "--token", "[REDACTED]", "--mode", "safe"])
        self.assertEqual(count, 1)


class CaptureTests(unittest.TestCase):
    def test_run_captures_streams_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = (
                "import sys; "
                "print('hello stdout token=secret-value'); "
                "print('hello stderr sk-12345678901234567890', file=sys.stderr)"
            )
            manifest, exit_code = run_capture(
                [sys.executable, "-c", script], output_root=root, timeout=10, quiet=True
            )
            self.assertEqual(exit_code, 0)
            self.assertEqual(manifest["status"], "success")
            run_dir = root / str(manifest["run_id"])
            self.assertEqual(
                (run_dir / "stdout.log").read_text(encoding="utf-8"),
                "hello stdout token=[REDACTED]\n",
            )
            self.assertEqual(
                (run_dir / "stderr.log").read_text(encoding="utf-8"),
                "hello stderr [REDACTED]\n",
            )
            loaded = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(loaded["redactions"]["total"], 4)
            report = inspect_run(run_dir)
            self.assertTrue(report["integrity"]["valid"])

    def test_label_redaction_is_counted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, exit_code = run_capture(
                [sys.executable, "-c", "print('ok')"],
                output_root=Path(temporary),
                label="trial token=private-value",
                quiet=True,
            )
            self.assertEqual(exit_code, 0)
            self.assertEqual(manifest["label"], "trial token=[REDACTED]")
            self.assertEqual(manifest["redactions"]["label"], 1)
            self.assertEqual(manifest["redactions"]["total"], 1)

    def test_nonzero_exit_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, exit_code = run_capture(
                [sys.executable, "-c", "raise SystemExit(7)"],
                output_root=Path(temporary),
                timeout=10,
                quiet=True,
            )
            self.assertEqual(exit_code, 7)
            self.assertEqual(manifest["exit_code"], 7)
            self.assertEqual(manifest["status"], "failed")

    def test_timeout_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, exit_code = run_capture(
                [sys.executable, "-c", "import time; time.sleep(2)"],
                output_root=Path(temporary),
                timeout=0.1,
                quiet=True,
            )
            self.assertEqual(exit_code, 124)
            self.assertTrue(manifest["timed_out"])
            self.assertEqual(manifest["status"], "timed_out")

    def test_missing_command_creates_failure_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, exit_code = run_capture(
                ["kona-command-that-does-not-exist"],
                output_root=Path(temporary),
                timeout=10,
                quiet=True,
            )
            self.assertEqual(exit_code, 127)
            self.assertEqual(manifest["status"], "failed")
            run_dir = Path(temporary) / str(manifest["run_id"])
            self.assertIn("command not found", (run_dir / "stderr.log").read_text(encoding="utf-8").lower())

    def test_inspect_detects_tampered_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, _ = run_capture(
                [sys.executable, "-c", "print('stable')"], output_root=root, quiet=True
            )
            run_dir = root / str(manifest["run_id"])
            (run_dir / "stdout.log").write_text("changed\n", encoding="utf-8")
            report = inspect_run(run_dir)
            self.assertFalse(report["integrity"]["valid"])
            self.assertFalse(report["integrity"]["artifacts"]["stdout"]["matches_manifest"])

    def test_inspect_rejects_artifact_outside_run_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, _ = run_capture(
                [sys.executable, "-c", "print('stable')"], output_root=root, quiet=True
            )
            run_dir = root / str(manifest["run_id"])
            manifest_path = run_dir / "run.json"
            altered = json.loads(manifest_path.read_text(encoding="utf-8"))
            altered["artifacts"]["stdout"]["path"] = "../stdout.log"
            manifest_path.write_text(json.dumps(altered), encoding="utf-8")
            with self.assertRaises(ValueError):
                inspect_run(run_dir)


class CliTests(unittest.TestCase):
    def test_module_cli_returns_child_status_and_inspects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "kona",
                    "run",
                    "--quiet",
                    "--output",
                    str(root),
                    "--",
                    sys.executable,
                    "-c",
                    "print('cli ok')",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            run_dirs = [path for path in root.iterdir() if path.is_dir()]
            self.assertEqual(len(run_dirs), 1)
            inspected = subprocess.run(
                [sys.executable, "-m", "kona", "inspect", "--json", str(run_dirs[0])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(inspected.returncode, 0, inspected.stderr)
            self.assertTrue(json.loads(inspected.stdout)["integrity"]["valid"])


if __name__ == "__main__":
    unittest.main()
