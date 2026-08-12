from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from kona.capture import inspect_run, run_capture
from kona.contract import ContractError, init_contract, inspect_contract_report, load_contract, run_contract
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

    def test_run_caps_noisy_streams_and_marks_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, exit_code = run_capture(
                [sys.executable, "-c", "print('x' * 9000000)"],
                output_root=Path(temporary),
                quiet=True,
            )
            self.assertEqual(exit_code, 0)
            run_dir = Path(temporary) / str(manifest["run_id"])
            self.assertLessEqual((run_dir / "stdout.log").stat().st_size, 8 * 1024 * 1024)
            self.assertTrue(manifest["capture"]["stdout"]["truncated"])
            self.assertIn("stream truncated", (run_dir / "stdout.log").read_text(encoding="utf-8"))

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
            self.assertGreater(manifest["capture"]["stderr"]["bytes"], 0)
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

    def test_inspect_rejects_manifest_artifact_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, _ = run_capture([sys.executable, "-c", "print('stable')"], output_root=root, quiet=True)
            run_dir = root / str(manifest["run_id"])
            manifest_path = run_dir / "run.json"
            altered = json.loads(manifest_path.read_text(encoding="utf-8"))
            altered["artifacts"]["stdout"]["path"] = "stderr"
            manifest_path.write_text(json.dumps(altered), encoding="utf-8")
            with self.assertRaises(ValueError):
                inspect_run(run_dir)


class ContractTests(unittest.TestCase):
    def _write_contract(self, root: Path, **overrides: object) -> Path:
        contract: dict[str, object] = {
            "version": 1,
            "name": "test-contract",
            "description": "A temporary contract used by the test suite.",
            "cwd": ".",
            "command": [sys.executable, "-c", "print('contract ok')"],
            "timeout": 10,
            "observations": [],
            "assertions": [{"type": "exit_code", "equals": 0}],
        }
        contract.update(overrides)
        path = root / "contract.json"
        path.write_text(json.dumps(contract), encoding="utf-8")
        return path

    def test_contract_run_writes_reviewable_passing_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract_path = self._write_contract(
                root,
                name="release-note",
                command=[
                    sys.executable,
                    "-c",
                    "from pathlib import Path; Path('RELEASE.md').write_text('## Highlights\\nShipped\\n', encoding='utf-8'); print('release note written token=secret-value')",
                ],
                assertions=[
                    {"type": "exit_code", "equals": 0},
                    {"type": "status", "equals": "success"},
                    {"type": "file_created", "path": "RELEASE.md"},
                    {"type": "file_content_contains", "path": "RELEASE.md", "value": "## Highlights"},
                    {"type": "stdout_contains", "value": "release note written"},
                ],
            )
            report, exit_code = run_contract(contract_path, output_root=root / "runs", quiet=True)
            self.assertEqual(exit_code, 0)
            self.assertEqual(report["summary"]["status"], "passed")
            run_dir = root / "runs" / str(report["run"]["run_id"])
            self.assertTrue((run_dir / "report.json").is_file())
            self.assertTrue((run_dir / "report.md").is_file())
            self.assertTrue((run_dir / "report.sha256").is_file())
            inspected = inspect_contract_report(run_dir)
            self.assertTrue(inspected["integrity"]["valid"])
            self.assertEqual(inspected["report"]["assertions"][2]["id"], "assertion-3")
            report_text = (run_dir / "report.json").read_text(encoding="utf-8")
            self.assertNotIn("secret-value", report_text)

    def test_failed_contract_keeps_valid_failure_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract_path = self._write_contract(
                root,
                command=[sys.executable, "-c", "raise SystemExit(7)"],
                assertions=[
                    {"type": "exit_code", "equals": 0},
                    {"type": "status", "equals": "success"},
                ],
            )
            report, exit_code = run_contract(contract_path, output_root=root / "runs", quiet=True)
            self.assertEqual(exit_code, 1)
            self.assertEqual(report["summary"]["status"], "failed")
            inspected = inspect_contract_report(root / "runs" / str(report["run"]["run_id"]))
            self.assertTrue(inspected["integrity"]["valid"])
            self.assertEqual(inspected["report"]["summary"]["failed_assertions"], 2)

    def test_stream_negation_and_file_hash_assertions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "artifact.txt"
            target.write_text("stable artifact\n", encoding="utf-8")
            import hashlib

            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            contract_path = self._write_contract(
                root,
                command=[
                    sys.executable,
                    "-c",
                    "import sys; print('expected stdout'); print('expected stderr', file=sys.stderr)",
                ],
                observations=["artifact.txt"],
                assertions=[
                    {"type": "file_sha256", "path": "artifact.txt", "equals": digest},
                    {"type": "stdout_not_contains", "value": "unexpected"},
                    {"type": "stderr_contains", "value": "expected stderr"},
                    {"type": "stderr_not_contains", "value": "secret"},
                ],
            )
            report, exit_code = run_contract(contract_path, output_root=root / "runs", quiet=True)
            self.assertEqual(exit_code, 0)
            self.assertEqual(report["summary"]["failed_assertions"], 0)

    def test_timeout_and_contract_mutation_fail_the_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            timeout_contract = self._write_contract(
                root,
                command=[sys.executable, "-c", "import time; time.sleep(2)"],
                timeout=0.05,
                assertions=[
                    {"type": "status", "equals": "timed_out"},
                    {"type": "exit_code", "equals": 124},
                ],
            )
            timeout_report, timeout_code = run_contract(timeout_contract, output_root=root / "timeout-runs", quiet=True)
            self.assertEqual(timeout_code, 0)
            self.assertEqual(timeout_report["run"]["status"], "timed_out")

            mutation_contract = self._write_contract(
                root,
                command=[
                    sys.executable,
                    "-c",
                    "from pathlib import Path; path = Path('contract.json'); path.write_text(path.read_text() + ' ', encoding='utf-8')",
                ],
            )
            mutation_report, mutation_code = run_contract(mutation_contract, output_root=root / "mutation-runs", quiet=True)
            self.assertEqual(mutation_code, 1)
            self.assertFalse(mutation_report["contract_integrity"]["stable"])
            self.assertEqual(mutation_report["summary"]["status"], "failed")

    def test_explicit_null_timeout_is_unbounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract_path = self._write_contract(
                root,
                timeout=None,
                command=[sys.executable, "-c", "print('unbounded contract')"],
            )
            spec = load_contract(contract_path)
            self.assertIsNone(spec.timeout)

    def test_file_lifecycle_assertions_cover_created_changed_unchanged_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "changed.txt").write_text("old", encoding="utf-8")
            (root / "steady.txt").write_text("steady", encoding="utf-8")
            (root / "deleted.txt").write_text("remove", encoding="utf-8")
            contract_path = self._write_contract(
                root,
                command=[
                    sys.executable,
                    "-c",
                    "from pathlib import Path; Path('changed.txt').write_text('new'); Path('created.txt').write_text('created'); Path('deleted.txt').unlink()",
                ],
                observations=["changed.txt", "steady.txt", "deleted.txt", "created.txt"],
                assertions=[
                    {"type": "file_changed", "path": "changed.txt"},
                    {"type": "file_unchanged", "path": "steady.txt"},
                    {"type": "file_deleted", "path": "deleted.txt"},
                    {"type": "file_created", "path": "created.txt"},
                ],
            )
            _report, exit_code = run_contract(contract_path, output_root=root / "runs", quiet=True)
            self.assertEqual(exit_code, 0)

    def test_missing_file_content_assertion_does_not_false_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract_path = self._write_contract(
                root,
                assertions=[{"type": "file_content_not_contains", "path": "missing.txt", "value": "safe"}],
            )
            report, exit_code = run_contract(contract_path, output_root=root / "runs", quiet=True)
            self.assertEqual(exit_code, 1)
            result = report["assertions"][1]
            self.assertFalse(result["passed"])
            self.assertEqual(result["observed"], "unavailable")

    def test_contract_rejects_traversal_windows_paths_and_symlink_observations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for unsafe in ("../escape.txt", "/absolute.txt", r"C:\\escape.txt", r"\\\\server\\share\\x"):
                with self.subTest(unsafe=unsafe):
                    contract_path = self._write_contract(root, observations=[unsafe])
                    with self.assertRaises(ContractError):
                        load_contract(contract_path)

            with tempfile.TemporaryDirectory(prefix="kona-contract-outside-") as outside_temporary:
                outside = Path(outside_temporary)
                link = root / "link"
                try:
                    os.symlink(outside, link, target_is_directory=True)
                except (OSError, NotImplementedError):
                    self.skipTest("symlinks are unavailable in this environment")
                contract_path = self._write_contract(root, observations=["link/file.txt"])
                with self.assertRaises(ContractError):
                    load_contract(contract_path)

    def test_contract_rejects_nul_and_non_finite_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for timeout in (float("nan"), float("inf"), -1):
                with self.subTest(timeout=timeout):
                    contract_path = self._write_contract(root, timeout=timeout)
                    with self.assertRaises((ContractError, ValueError, json.JSONDecodeError)):
                        load_contract(contract_path)
            contract_path = self._write_contract(root, command=["python\x00bad"])
            with self.assertRaises(ContractError):
                load_contract(contract_path)

    def test_contract_rejects_unknown_top_level_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract_path = self._write_contract(root, assertionss=[{"type": "exit_code", "equals": 0}])
            with self.assertRaises(ContractError):
                load_contract(contract_path)

    def test_contract_rejects_unknown_assertion_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract_path = self._write_contract(
                root,
                assertions=[{"type": "exit_code", "equals": 0, "eqauls": 0}],
            )
            with self.assertRaises(ContractError):
                load_contract(contract_path)

    def test_directory_snapshot_detects_nested_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            observed = root / "output"
            observed.mkdir()
            (observed / "stable.txt").write_text("before", encoding="utf-8")
            contract_path = self._write_contract(
                root,
                command=[
                    sys.executable,
                    "-c",
                    "from pathlib import Path; Path('output/nested.txt').write_text('created', encoding='utf-8')",
                ],
                observations=["output"],
                assertions=[{"type": "file_unchanged", "path": "output", "equals": False}],
            )
            report, exit_code = run_contract(contract_path, output_root=root / "runs", quiet=True)
            self.assertEqual(exit_code, 0)
            self.assertTrue(report["observations"][0]["before"]["entries"] < report["observations"][0]["after"]["entries"])

    def test_contract_accepts_utf8_bom_and_rejects_empty_or_surrogate_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract_path = self._write_contract(root, assertions=[{"type": "stdout_contains", "value": ""}])
            with self.assertRaises(ContractError):
                load_contract(contract_path)
            contract_path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"version": 1, "command": [sys.executable, "-c", "print('ok')"]}).encode("utf-8"))
            self.assertEqual(load_contract(contract_path).command[0], sys.executable)
            contract_path.write_text(json.dumps({"version": 1, "name": "\ud800", "command": ["python"]}), encoding="utf-8", errors="surrogatepass")
            with self.assertRaises(ContractError):
                load_contract(contract_path)

    def test_contract_rejects_windows_device_and_ads_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for unsafe in ("CON", "NUL.txt", "folder/file.txt:secret"):
                contract_path = self._write_contract(root, observations=[unsafe])
                with self.subTest(unsafe=unsafe), self.assertRaises(ContractError):
                    load_contract(contract_path)

    def test_contract_does_not_treat_directory_as_a_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "artifact").mkdir()
            contract_path = self._write_contract(
                root,
                assertions=[{"type": "file_exists", "path": "artifact"}],
            )
            report, exit_code = run_contract(contract_path, output_root=root / "runs", quiet=True)
            self.assertEqual(exit_code, 1)
            self.assertFalse(report["assertions"][1]["passed"])

    def test_contract_report_digest_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract_path = self._write_contract(root)
            report, _ = run_contract(contract_path, output_root=root / "runs", quiet=True)
            report_path = root / "runs" / str(report["run"]["run_id"]) / "report.json"
            altered = json.loads(report_path.read_text(encoding="utf-8"))
            altered["summary"]["status"] = "passed"
            report_path.write_text(json.dumps(altered), encoding="utf-8")
            inspected = inspect_contract_report(report_path)
            self.assertFalse(inspected["integrity"]["valid"])
            self.assertFalse(inspected["integrity"]["report_digest"]["valid"])

    def test_contract_inspect_detects_markdown_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract_path = self._write_contract(root)
            report, _ = run_contract(contract_path, output_root=root / "runs", quiet=True)
            run_dir = root / "runs" / str(report["run"]["run_id"])
            (run_dir / "report.md").write_text("tampered report\n", encoding="utf-8")
            inspected = inspect_contract_report(run_dir)
            self.assertFalse(inspected["integrity"]["valid"])
            self.assertFalse(inspected["integrity"]["report_markdown"]["valid"])

    def test_contract_inspect_detects_observed_artifact_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "artifact.txt"
            contract_path = self._write_contract(
                root,
                command=[sys.executable, "-c", "from pathlib import Path; Path('artifact.txt').write_text('stable', encoding='utf-8')"],
                assertions=[{"type": "file_content_contains", "path": "artifact.txt", "value": "stable"}],
            )
            report, exit_code = run_contract(contract_path, output_root=root / "runs", quiet=True)
            self.assertEqual(exit_code, 0)
            artifact.write_text("changed after execution", encoding="utf-8")
            inspected = inspect_contract_report(root / "runs" / str(report["run"]["run_id"]))
            self.assertFalse(inspected["integrity"]["valid"])
            self.assertFalse(inspected["integrity"]["workspace"]["valid"])

    def test_contract_inspect_detects_run_manifest_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract_path = self._write_contract(root)
            report, _ = run_contract(contract_path, output_root=root / "runs", quiet=True)
            run_dir = root / "runs" / str(report["run"]["run_id"])
            manifest_path = run_dir / "run.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["exit_code"] = 9
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            inspected = inspect_contract_report(run_dir)
            self.assertFalse(inspected["integrity"]["valid"])
            self.assertFalse(inspected["integrity"]["run_manifest"]["valid"])

    def test_contract_inspect_rejects_malformed_assertion_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract_path = self._write_contract(root)
            report, _ = run_contract(contract_path, output_root=root / "runs", quiet=True)
            report_path = root / "runs" / str(report["run"]["run_id"]) / "report.json"
            altered = json.loads(report_path.read_text(encoding="utf-8"))
            altered["assertions"] = [None]
            report_path.write_text(json.dumps(altered), encoding="utf-8")
            with self.assertRaises(ContractError):
                inspect_contract_report(report_path)

    def test_contract_init_is_non_destructive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "contracts" / "task.json"
            created = init_contract(path)
            self.assertEqual(created, path.resolve())
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["version"], 1)
            with self.assertRaises(ContractError):
                init_contract(path)


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

    def test_contract_cli_validate_run_inspect_and_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract_path = root / "contract.json"
            contract_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "name": "cli-contract",
                        "command": [sys.executable, "-c", "print('cli contract ok')"],
                        "assertions": [{"type": "stdout_contains", "value": "cli contract ok"}],
                    }
                ),
                encoding="utf-8",
            )
            validated = subprocess.run(
                [sys.executable, "-m", "kona", "contract", "validate", str(contract_path), "--json"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(validated.returncode, 0, validated.stderr)
            self.assertTrue(json.loads(validated.stdout)["valid"])
            initialized = subprocess.run(
                [sys.executable, "-m", "kona", "contract", "init", str(root / "starter.json")],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            self.assertTrue((root / "starter.json").is_file())
            output_root = root / "runs"
            completed = subprocess.run(
                [sys.executable, "-m", "kona", "contract", "run", str(contract_path), "--output", str(output_root), "--quiet"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            run_dir = next(output_root.iterdir())
            inspected = subprocess.run(
                [sys.executable, "-m", "kona", "contract", "inspect", str(run_dir), "--json"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(inspected.returncode, 0, inspected.stderr)
            self.assertTrue(json.loads(inspected.stdout)["integrity"]["valid"])

            invalid = root / "invalid.json"
            invalid.write_text("{}", encoding="utf-8")
            invalid_result = subprocess.run(
                [sys.executable, "-m", "kona", "contract", "validate", str(invalid)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(invalid_result.returncode, 2)

            failed = root / "failed.json"
            failed.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "command": [sys.executable, "-c", "raise SystemExit(4)"],
                        "assertions": [{"type": "exit_code", "equals": 0}],
                    }
                ),
                encoding="utf-8",
            )
            failed_result = subprocess.run(
                [sys.executable, "-m", "kona", "contract", "run", str(failed), "--output", str(root / "failed-runs"), "--quiet"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(failed_result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
