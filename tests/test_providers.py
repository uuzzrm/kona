from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from kona.providers import ProviderConfig, ProviderError, build_findings_payload, explain_findings


def sample_report() -> dict[str, object]:
    return {
        "schema": "kona.findings/v1",
        "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "total": 1, "verdict": "attention"},
        "findings": [{
            "rule_id": "SEC003", "severity": "high", "category": "secret", "title": "Hard-coded credential assignment",
            "message": "A sensitive variable is assigned.", "remediation": "Use a secret store.",
            "location": {"path": "private/settings.py", "line": 4}, "evidence": {"preview": "API_KEY=[REDACTED]"},
        }],
    }


class FakeResponse:
    def __init__(self, body: dict[str, object]): self.body = json.dumps(body).encode()
    def __enter__(self): return self
    def __exit__(self, *args): return None
    def read(self, size: int): return self.body


class FakeOpener:
    def __init__(self, response: dict[str, object]): self.response = response; self.request = None
    def open(self, request, timeout): self.request = request; return FakeResponse(self.response)


class ProviderTests(unittest.TestCase):
    def test_payload_excludes_source_paths_and_evidence(self) -> None:
        rendered = json.dumps(build_findings_payload(sample_report()))
        self.assertNotIn("private/settings.py", rendered)
        self.assertNotIn("API_KEY", rendered)
        self.assertNotIn("location", rendered)
        self.assertNotIn("evidence", rendered)

    def test_deepseek_contract_and_advisory_boundary(self) -> None:
        opener = FakeOpener({"choices": [{"message": {"content": "Fix the secret."}}]})
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "session-key"}, clear=False), patch("kona.providers.build_opener", return_value=opener):
            result = explain_findings(sample_report(), ProviderConfig("deepseek", model="deepseek-v4-pro"))
        self.assertFalse(result["authoritative"])
        self.assertEqual(result["scan_verdict"], "attention")
        self.assertEqual(opener.request.full_url, "https://api.deepseek.com/chat/completions")
        self.assertEqual(opener.request.get_header("Authorization"), "Bearer session-key")
        sent = json.loads(opener.request.data)
        self.assertEqual(sent["model"], "deepseek-v4-pro")
        self.assertNotIn("private/settings.py", json.dumps(sent))

    def test_anthropic_contract(self) -> None:
        opener = FakeOpener({"content": [{"type": "text", "text": "Prioritize rotation."}]})
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "session-key"}, clear=False), patch("kona.providers.build_opener", return_value=opener):
            result = explain_findings(sample_report(), ProviderConfig("anthropic", model="claude-test"))
        self.assertEqual(result["explanation"], "Prioritize rotation.")
        self.assertEqual(opener.request.full_url, "https://api.anthropic.com/v1/messages")
        self.assertEqual(opener.request.get_header("X-api-key"), "session-key")
        self.assertEqual(opener.request.get_header("Anthropic-version"), "2023-06-01")

    def test_anthropic_non_text_response_is_rejected(self) -> None:
        opener = FakeOpener({"content": [{"type": "tool_use", "id": "tool-1"}]})
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "session-key"}, clear=False), patch("kona.providers.build_opener", return_value=opener):
            with self.assertRaisesRegex(ProviderError, "no supported text"):
                explain_findings(sample_report(), ProviderConfig("anthropic", model="claude-test"))

    def test_terminal_controls_are_removed_from_advisory(self) -> None:
        opener = FakeOpener({"choices": [{"message": {"content": "safe\x1b[31m red\x1b[0m\x00 text"}}]})
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "session-key"}, clear=False), patch("kona.providers.build_opener", return_value=opener):
            result = explain_findings(sample_report(), ProviderConfig("deepseek", model="deepseek-v4-pro"))
        self.assertEqual(result["explanation"], "safe red text")
        self.assertNotIn("\x1b", result["explanation"])

    def test_provider_error_does_not_disclose_key(self) -> None:
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "never-print-this-key"}, clear=False), patch("kona.providers.build_opener", side_effect=OSError("connection failed")):
            with self.assertRaises(ProviderError) as raised:
                explain_findings(sample_report(), ProviderConfig("deepseek", model="deepseek-v4-pro"))
        self.assertNotIn("never-print-this-key", str(raised.exception))

    def test_missing_key_and_custom_url_fail_closed(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ProviderError, "DEEPSEEK_API_KEY"):
                explain_findings(sample_report(), ProviderConfig("deepseek", model="deepseek-v4-pro"))
        with self.assertRaisesRegex(ProviderError, "allow-custom"):
            explain_findings(sample_report(), ProviderConfig("deepseek", base_url="https://example.com"))
        with self.assertRaisesRegex(ProviderError, "HTTPS origin"):
            explain_findings(sample_report(), ProviderConfig("deepseek", base_url="http://127.0.0.1", allow_custom_base_url=True))

    def test_cli_preview_needs_no_key_and_contains_no_source_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.joinpath("settings.py").write_text('API_KEY="real-' + 'secret-value"\n', encoding="utf-8")
            completed = subprocess.run([sys.executable, "-m", "kona", "explain", str(root), "--provider", "deepseek", "--preview"], capture_output=True, text=True, check=False, env={key: value for key, value in os.environ.items() if key != "DEEPSEEK_API_KEY"})
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["findings"][0]["rule_id"], "SEC003")
        self.assertNotIn("settings.py", completed.stdout)
        self.assertNotIn("secret-value", completed.stdout)

    def test_cli_requires_explicit_consent_before_network(self) -> None:
        completed = subprocess.run([sys.executable, "-m", "kona", "explain", ".", "--provider", "deepseek"], capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("--yes", completed.stderr)


if __name__ == "__main__":
    unittest.main()
