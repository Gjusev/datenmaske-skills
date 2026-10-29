"""Tests for scan_diff.py — DSGVO risk signals in unified diffs."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "dsgvo-pr-checklist" / "scripts"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(SCRIPTS))

import scan_diff  # noqa: E402


class AddedLineParsing(unittest.TestCase):
    def test_added_lines_with_line_numbers(self):
        diff = (FIXTURES / "risky.diff").read_text(encoding="utf-8")
        lines = scan_diff._added_lines(diff)
        ts_lines = [(f, l, c) for f, l, c in lines if f.endswith("service.ts")]
        # 3 added lines in the TS file, hunk starts at new line 12+1=13
        self.assertEqual(len(ts_lines), 3)
        self.assertEqual(ts_lines[0][1], 14)

    def test_removed_lines_not_scanned(self):
        diff = (
            "diff --git a/a.txt b/a.txt\n"
            "--- a/a.txt\n"
            "+++ b/a.txt\n"
            "@@ -1,3 +1,3 @@\n"
            "-DE89370400440532013000\n"
            " bleibt\n"
        )
        # The removed IBAN line must not produce a signal
        self.assertEqual(scan_diff.scan_diff(diff), [])


class SignalDetection(unittest.TestCase):
    def test_risky_diff_has_signals(self):
        diff = (FIXTURES / "risky.diff").read_text(encoding="utf-8")
        findings = scan_diff.scan_diff(diff)
        checks = {f["check"] for f in findings}
        self.assertIn("K1-PII-im-Code", checks)       # IBAN in added line
        self.assertIn("K2-Secrets", checks)           # hardcoded apiKey
        self.assertIn("K4-Logging", checks)           # logger with email/geburtsdatum
        self.assertIn("K5-Datenminimierung", checks)  # ADD COLUMN steuernummer/geburtsdatum
        self.assertTrue(any(f["severity"] == "risky" for f in findings))

    def test_clean_diff_no_signals(self):
        diff = (FIXTURES / "clean.diff").read_text(encoding="utf-8")
        self.assertEqual(scan_diff.scan_diff(diff), [])

    def test_findings_hide_raw_pii_by_default(self):
        diff = (FIXTURES / "risky.diff").read_text(encoding="utf-8")
        findings = scan_diff.scan_diff(diff)
        # default scan_diff output never carries the raw IBAN string
        for f in findings:
            blob = str(f)
            self.assertNotIn("DE89 3704", blob)
            self.assertNotIn("sk-live-a8f31c9d2b7e4f6a", blob)


class Cli(unittest.TestCase):
    def _run(self, *args):
        import subprocess
        return subprocess.run(
            [sys.executable, str(SCRIPTS / "scan_diff.py"), *args],
            capture_output=True, text=True,
        )

    def test_exit_code_risky_with_flag(self):
        proc = self._run(str(FIXTURES / "risky.diff"), "--fail-on-risky")
        self.assertEqual(proc.returncode, 1)

    def test_exit_code_zero_without_flag(self):
        proc = self._run(str(FIXTURES / "risky.diff"))
        self.assertEqual(proc.returncode, 0)

    def test_clean_diff_exit_zero(self):
        proc = self._run(str(FIXTURES / "clean.diff"), "--fail-on-risky")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Keine Risiko-Signale", proc.stdout)

    def test_context_hidden_by_default_and_secrets_always_masked(self):
        # Without the flag: no context at all.
        proc = self._run(str(FIXTURES / "risky.diff"))
        self.assertNotIn("sk-live-a8f31c9d2b7e4f6a", proc.stdout)
        self.assertNotIn("logger.info", proc.stdout)
        # With --show-context: code lines appear, but secrets stay masked —
        # they must never leak into CI logs or terminals through this tool.
        proc_ctx = self._run(str(FIXTURES / "risky.diff"), "--show-context")
        self.assertIn("logger.info", proc_ctx.stdout)
        self.assertIn("***MASKED***", proc_ctx.stdout)
        self.assertNotIn("sk-live-a8f31c9d2b7e4f6a", proc_ctx.stdout)

    def test_show_context_masks_pii_values_text_and_json(self):
        # Masking is content-based: a K1 finding's context must not carry
        # the raw PII value either — in text and in JSON output.
        import json
        diff = str(FIXTURES / "risky.diff")
        proc = self._run(diff, "--show-context")
        self.assertNotIn("DE89 3704", proc.stdout)
        self.assertIn("[IBAN]", proc.stdout)
        proc_json = self._run(diff, "--show-context", "--format", "json")
        self.assertNotIn("DE89 3704", proc_json.stdout)
        data = json.loads(proc_json.stdout)
        for f in data:
            self.assertNotIn("sk-live-", f.get("context", ""))

    def test_show_context_masks_secrets_on_any_finding(self):
        # A credential on a line that also matches a non-secret detector
        # (email, IBAN) must not leak through that finding's context.
        import json
        diff = str(FIXTURES / "mixed.diff")
        proc = self._run(diff, "--show-context")
        self.assertIn("K1-PII-im-Code", proc.stdout)
        self.assertIn("K2-Secrets", proc.stdout)
        proc_json = self._run(diff, "--show-context", "--format", "json")
        data = json.loads(proc_json.stdout)
        # Detection fired on the mixed lines …
        self.assertTrue(any(f["check"] == "K1-PII-im-Code" for f in data))
        self.assertTrue(any(f["check"] == "K2-Secrets" for f in data))
        # … but no raw secret or PII value is reachable in any context.
        for blob in (proc.stdout, proc_json.stdout):
            self.assertNotIn("s3cr3t_v4lue_x9_42", blob)
            self.assertNotIn("hunter2secret42x", blob)
            self.assertNotIn("sk-live-a8f31c9d2b7e4f6a", blob)
            self.assertNotIn("DE89 3704", blob)
            self.assertNotIn("kunde+muster@example.org", blob)
            self.assertNotIn("ops@example.org", blob)

    def test_json_format(self):
        import json
        proc = self._run(str(FIXTURES / "risky.diff"), "--format", "json")
        data = json.loads(proc.stdout)
        self.assertIsInstance(data, list)
        self.assertTrue(data)


if __name__ == "__main__":
    unittest.main()
