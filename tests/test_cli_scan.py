"""Tests for scan_pii.py CLI behavior: output formats, exit codes, stdin."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "presidio-de" / "scripts"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def run_scan(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPTS / "scan_pii.py"), *args],
        capture_output=True, text=True,
    )


class ScanCli(unittest.TestCase):
    def test_fixture_finds_all_entities(self):
        proc = run_scan(str(FIXTURES / "kundenbrief.txt"))
        self.assertEqual(proc.returncode, 0)
        for entity in ("IBAN", "STEUER_ID", "KVNR", "PHONE_DE", "EMAIL",
                       "STREET_ADDRESS", "PLZ_ORT", "GEBURTSDATUM",
                       "PERSON_NAME_DE"):
            self.assertIn(entity, proc.stdout)

    def test_fail_on_confirmed_exit_one(self):
        proc = run_scan(str(FIXTURES / "kundenbrief.txt"), "--fail-on", "confirmed")
        self.assertEqual(proc.returncode, 1)

    def test_fail_on_confirmed_clean_file_exit_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "clean.txt"
            f.write_text("Rechnung 2024-0417, Betrag 98765 Euro.\n", encoding="utf-8")
            proc = run_scan(str(f), "--fail-on", "confirmed")
            self.assertEqual(proc.returncode, 0)
            self.assertIn("Keine", proc.stdout)

    def test_json_output_no_content(self):
        proc = run_scan(str(FIXTURES / "kundenbrief.txt"),
                        "--format", "json", "--no-content")
        data = json.loads(proc.stdout)
        self.assertTrue(data)
        for entry in data:
            self.assertNotIn("DE89", entry["text"])
            self.assertTrue(entry["text"].endswith("chars"))

    def test_stdin_mode(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPTS / "scan_pii.py"), "--stdin",
             "--format", "json", "--no-content"],
            input="Steuer-ID: 02538413968\n",
            capture_output=True, text=True,
        )
        data = json.loads(proc.stdout)
        self.assertEqual(data[0]["type"], "STEUER_ID")

    def test_exclude_globs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a").mkdir()
            (root / "a" / "keep.txt").write_text("IBAN DE89370400440532013000\n",
                                                 encoding="utf-8")
            (root / "skip.log").write_text("IBAN DE89370400440532013000\n",
                                           encoding="utf-8")
            proc = run_scan(str(root), "--exclude", "*.log", "--format", "json",
                            "--no-content")
            data = json.loads(proc.stdout)
            files = {entry["file"] for entry in data}
            self.assertEqual(files, {str(root / "a" / "keep.txt")})

    def test_binary_file_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "blob.bin"
            f.write_bytes(b"\x00\xffDE89370400440532013000")
            proc = run_scan(str(f), "--format", "json")
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(json.loads(proc.stdout), [])

    def test_no_paths_is_usage_error(self):
        proc = run_scan()
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
