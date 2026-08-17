from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]


class ScanActionMetadataTests(unittest.TestCase):
    def test_standalone_action_publishes_before_enforcing(self) -> None:
        action = (ROOT / "scan" / "action.yml").read_text(encoding="utf-8")
        self.assertIn("using: composite", action)
        self.assertIn("uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065", action)
        self.assertIn("uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02", action)
        self.assertIn("uses: github/codeql-action/upload-sarif@f3712979fa5f215279b101dd0a2e3bdfb4353324", action)
        self.assertLess(action.index("Upload SARIF artifact"), action.index("Enforce Kona scan"))
        self.assertLess(action.index("Upload to GitHub Code Scanning"), action.index("Enforce Kona scan"))
        self.assertIn("include-hidden-files: true", action)
        self.assertIn("--sarif-prefix", action)
        self.assertIn("relative_to(workspace)", action)
        self.assertIn("path must not be a symlink", action)
        self.assertIn('[ "$code" -le 1 ] && [ -f "$KONA_SARIF_PATH" ]', action)

    def test_action_defaults_to_artifact_only_and_exposes_threshold_outputs(self) -> None:
        action = (ROOT / "scan" / "action.yml").read_text(encoding="utf-8")
        self.assertIn('default: "false"', action)
        self.assertIn("Optional Code Scanning analysis category", action)
        self.assertIn("category: ${{ inputs.category }}", action)
        self.assertIn("Number of findings represented in the SARIF projection.", action)
        self.assertIn("sarif-path must not contain line breaks", action)
        self.assertIn("value: ${{ steps.scan.outputs.exit-code }}", action)
        self.assertIn("value: ${{ steps.scan.outputs.findings }}", action)

    def test_action_supports_workspace_relative_baseline_without_weakening_scan(self) -> None:
        action = (ROOT / "scan" / "action.yml").read_text(encoding="utf-8")
        self.assertIn("kona.baseline/v1", action)
        self.assertIn("baseline-suppressed", action)
        self.assertIn("value: ${{ steps.scan.outputs.baseline-suppressed }}", action)
        self.assertIn('KONA_BASELINE: ${{ inputs.baseline }}', action)
        self.assertIn("baseline must be workspace-relative", action)
        self.assertIn("baseline must not be a symlink", action)
        self.assertIn("baseline_resolved.relative_to(workspace)", action)
        self.assertIn('json.dumps({"scan_root"', action)
        self.assertIn('json.load(sys.stdin)["baseline"]', action)


if __name__ == "__main__":
    unittest.main()
