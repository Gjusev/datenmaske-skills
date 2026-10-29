"""Tests for redact_pii.py — placeholder replacement behavior."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "presidio-de" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import redact_pii  # noqa: E402

BRIEF = (
    "Sehr geehrte Frau Dr. Müller,\n"
    "Ihre IBAN DE89 3704 0044 0532 0130 00 wurde geprüft.\n"
    "Steuer-ID: 02538413968\n"
    "Versichertennummer: K127508150\n"
)


class RedactText(unittest.TestCase):
    def test_typed_placeholders(self):
        redacted, count = redact_pii.redact_text(BRIEF)
        self.assertEqual(count, 4)
        self.assertIn("[IBAN]", redacted)
        self.assertIn("[STEUER-ID]", redacted)
        self.assertIn("[KVNR]", redacted)
        self.assertIn("[NAME]", redacted)
        # No raw identifier survives
        self.assertNotIn("DE89", redacted)
        self.assertNotIn("02538413968", redacted)
        self.assertNotIn("K127508150", redacted)

    def test_keep_length_masks(self):
        redacted, count = redact_pii.redact_text(BRIEF, keep_length=True)
        self.assertEqual(count, 4)
        self.assertNotIn("02538413968", redacted)
        self.assertIn("●" * 11, redacted)
        # Same length as original
        self.assertEqual(len(redacted), len(BRIEF))

    def test_no_findings_unchanged(self):
        text = "Rechnung 2024-0417, Betrag 98765 Euro."
        redacted, count = redact_pii.redact_text(text)
        self.assertEqual((redacted, count), (text, 0))

    def test_text_structure_preserved(self):
        redacted, _ = redact_pii.redact_text(BRIEF)
        self.assertEqual(redacted.count("\n"), BRIEF.count("\n"))
        self.assertTrue(redacted.startswith("Sehr geehrte Frau Dr. "))

    def test_weak_entities_only_with_flag(self):
        text = "Max Mustermann war hier"
        _, count_default = redact_pii.redact_text(text)
        self.assertEqual(count_default, 0)
        _, count_weak = redact_pii.redact_text(text, include_weak=True)
        self.assertEqual(count_weak, 1)


class RedactFiles(unittest.TestCase):
    def test_original_never_touched_copy_written(self):
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "brief.txt"
            src.write_text(BRIEF, encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(SCRIPTS / "redact_pii.py"), str(src)],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            # Original untouched
            self.assertEqual(src.read_text(encoding="utf-8"), BRIEF)
            copy = Path(tmp) / "brief.txt.redacted"
            self.assertTrue(copy.exists())
            self.assertNotIn("DE89", copy.read_text(encoding="utf-8"))

    def test_out_dir_and_keep_length(self):
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "data.csv"
            src.write_text("iban;name\nDE89370400440532013000;Anna Schmidt\n", encoding="utf-8")
            out_dir = Path(tmp) / "masked"
            proc = subprocess.run(
                [sys.executable, str(SCRIPTS / "redact_pii.py"), str(src),
                 "--out", str(out_dir), "--keep-length", "--include-weak"],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            masked = out_dir / "data.csv"
            self.assertTrue(masked.exists())
            content = masked.read_text(encoding="utf-8")
            self.assertNotIn("DE89370400440532013000", content)
            self.assertNotIn("Anna Schmidt", content)
            # CSV structure kept
            self.assertEqual(len(content.splitlines()), 2)

    def test_binary_file_skipped(self):
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "blob.bin"
            src.write_bytes(b"\xff\xfe\x00binaryDE89370400440532013000")
            proc = subprocess.run(
                [sys.executable, str(SCRIPTS / "redact_pii.py"), str(src)],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertIn("skipping", proc.stderr)


if __name__ == "__main__":
    unittest.main()
