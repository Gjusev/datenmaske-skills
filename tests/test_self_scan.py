"""Dogfood: the pack's own detectors scan the pack itself.

Contract:
- Shipped scripts (code) carry NO checksum-confirmed PII literals.
- Docs may contain synthetic examples, but only in files that declare
  "synthetic"/"synthetisch" — a real-data paste into a doc without the
  marker fails this test.
- The fixtures demonstrate detection works (scan finds the synthetic PII).
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "skills" / "presidio-de" / "scripts" / "scan_pii.py"

SYNTHETIC_MARKERS = ("synthetic", "synthetisch", "SYNTHETIC")


def run_scan(paths: list[str], *args) -> tuple[int, list[dict]]:
    proc = subprocess.run(
        [sys.executable, str(SCAN), *paths, "--format", "json", "--no-content", *args],
        capture_output=True, text=True,
    )
    return proc.returncode, json.loads(proc.stdout)


class SelfScan(unittest.TestCase):
    def test_scripts_carry_no_confirmed_pii(self):
        scripts = [str(p) for p in (ROOT / "skills").rglob("*.py")]
        self.assertTrue(scripts)
        _, findings = run_scan(scripts)
        confirmed = [f for f in findings if f["confidence"] == "confirmed"]
        self.assertEqual(confirmed, [],
                         "shipped scripts must not contain checksum-valid PII literals")

    def test_docs_declare_synthetic_examples(self):
        docs = [str(p) for p in (ROOT / "skills").rglob("*.md")]
        docs += [str(ROOT / "README.md")]
        self.assertTrue(docs)
        _, findings = run_scan(docs)
        confirmed_files = {f["file"] for f in findings if f["confidence"] == "confirmed"}
        for file in confirmed_files:
            text = Path(file).read_text(encoding="utf-8", errors="ignore")
            self.assertTrue(
                any(marker in text for marker in SYNTHETIC_MARKERS),
                f"{file} contains checksum-valid examples but no synthetic declaration",
            )

    def test_fixtures_show_detection_works(self):
        code, findings = run_scan([str(ROOT / "tests" / "fixtures" / "kundenbrief.txt")])
        types = {f["type"] for f in findings}
        self.assertIn("IBAN", types)
        self.assertIn("STEUER_ID", types)
        self.assertIn("KVNR", types)
        self.assertEqual(code, 0)  # informational scan exits 0


if __name__ == "__main__":
    unittest.main()
