#!/usr/bin/env python3
"""Scan a unified diff (e.g. a git diff) for DSGVO-relevant risk signals.

Deterministic heuristics only — each signal names a checklist item to look
at, it does not decide compliance. Findings reference the checklist items in
the dsgvo-pr-checklist skill.

Usage:
    git diff main..HEAD | scan_diff.py --stdin
    scan_diff.py changes.diff
    scan_diff.py                    # runs `git diff HEAD` in cwd
    scan_diff.py --fail-on-risky    # exit 1 on confirmed-risk signals (CI)

Exit codes:
    0  no (or only informational) signals
    1  risky signals found (with --fail-on-risky)
    2  usage/IO error
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

# Reuse the German PII core from the presidio-de skill when the pack was
# installed together. Degrade gracefully when installed standalone.
_SKILL_ROOT = Path(__file__).resolve().parents[2]
_DE_PII_PATH = _SKILL_ROOT / "presidio-de" / "scripts" / "de_pii.py"

try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("de_pii", _DE_PII_PATH)
    de_pii = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["de_pii"] = de_pii  # dataclasses resolve classes via sys.modules
    spec.loader.exec_module(de_pii)  # type: ignore[union-attr]
    HAS_DE_PII = True
except Exception:
    HAS_DE_PII = False


def _added_lines(diff_text: str) -> list[tuple[str, int, str]]:
    """Extract (file, line_number, content) for added lines only."""
    results: list[tuple[str, int, str]] = []
    current_file = None
    new_line = 0
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("@@"):
            m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)", line)
            if m:
                new_line = int(m.group(1))
        elif line.startswith("+") and not line.startswith("+++"):
            if current_file:
                results.append((current_file, new_line, line[1:]))
            new_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            pass
        elif not line.startswith(("+", "-")):
            if line.startswith("\\"):
                continue  # "\ No newline at end of file"
            if line.startswith((" ",)) or line == "":
                new_line += 1
    return results


# --- Signal definitions ----------------------------------------------------
# (checklist_item, severity, regex, safe_label)
# safe_label names WHAT matched, never the matched value itself: secrets
# must not leak into CI logs, terminals or PR comments through this tool.

_SIGNALS: list[tuple[str, str, "re.Pattern[str]", str]] = [
    ("K2-Secrets", "risky",
     re.compile(r"AKIA[0-9A-Z]{16}"),
     "aws-access-key-id"),
    ("K2-Secrets", "risky",
     re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
     "github-token"),
    ("K2-Secrets", "risky",
     re.compile(r"xox[bap]-[A-Za-z0-9-]{10,}"),
     "slack-token"),
    ("K2-Secrets", "risky",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
     "private-key-block"),
    ("K2-Secrets", "risky",
     re.compile(r"(?:password|passwd|secret|api_key|apikey|token|auth)\s*[=:]\s*[\"'][^\"']{8,}[\"']",
                re.IGNORECASE),
     "credential-assignment"),
    ("K4-Logging", "risky",
     re.compile(r"(?:console\.log|logger|log\.)[^\n]*(?:email|username|user_name|firstname|lastname|"
                r"geburtsdatum|birthdate|dob|address|telefon|phone|iban|ssn|versichert)",
                re.IGNORECASE),
     "personal-data-in-log-call"),
    ("K5-Datenminimierung", "note",
     re.compile(
         r"(?:ADD COLUMN|addColumn|add_column)"
         r"|^\s*[a-z_]*(?:steuer|geburts|versichert|krankenkasse|iban|email|telefon|"
         r"adresse|address|birth|ssn|firstname|lastname|vorname|nachname)[a-z_0-9]*"
         r"\s+(?:VARCHAR|CHAR|DATE|TEXT|INT|INTEGER|BIGINT|BOOLEAN|TIMESTAMP|NUMERIC)",
         re.IGNORECASE),
     "personal-column-in-migration"),
    ("K6-Drittlandtransfer", "note",
     re.compile(r"(?:requests\.post|axios\.post|fetch\()[^\n]*(?:user|email|customer|patient|kunde)",
                re.IGNORECASE),
     "outbound-user-data-call"),
    ("K7-Cookies", "note",
     re.compile(r"(?:document\.cookie|setCookie|Cookie\(|set_cookie|analytics\.|trackEvent|gtag\()",
                re.IGNORECASE),
     "cookie-tracking-code"),
]

_SECRET_CHECKS = {"K2-Secrets"}


def scan_diff(diff_text: str) -> list[dict]:
    findings: list[dict] = []

    if HAS_DE_PII:
        for file, line, content in _added_lines(diff_text):
            for f in de_pii.find_pii(content, include_weak=False, names=False):
                findings.append({
                    "check": "K1-PII-im-Code",
                    "severity": "risky",
                    "file": file,
                    "line": line,
                    "signal": f"{f.type} [{f.confidence}]",
                })

    for file, line, content in _added_lines(diff_text):
        for check, severity, pattern, label in _SIGNALS:
            if pattern.search(content):
                findings.append({
                    "check": check,
                    "severity": severity,
                    "file": file,
                    "line": line,
                    "signal": label,
                })
    return findings


def _masked_context(content: str) -> str:
    """Code line for --show-context. Masking is content-based, not
    finding-based: any context line that contains a secret or a detected
    PII value is masked the same way, no matter which checklist item
    flagged it. A credential sitting on a line that also matches an
    email/IBAN/phone detector must not leak through that finding's
    context — no raw value is reachable in any output mode.
    """
    for check, _, pattern, _ in _SIGNALS:
        if check in _SECRET_CHECKS:
            content = pattern.sub("***MASKED***", content)
    if HAS_DE_PII:
        for f in reversed(de_pii.find_pii(content, include_weak=True, names=True)):
            content = content[:f.start] + f"[{f.type}]" + content[f.end:]
    return content.strip()[:80]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Risk signals for DSGVO checklist items in a git diff."
    )
    parser.add_argument("diff_file", nargs="?", help="unified diff file; omit to use git diff HEAD")
    parser.add_argument("--stdin", action="store_true", help="read diff from stdin")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--fail-on-risky", action="store_true",
                        help="exit 1 when severity=risky signals exist")
    parser.add_argument("--show-context", action="store_true",
                        help="show the code line in findings (default: hidden)")
    args = parser.parse_args(argv)

    if args.stdin:
        diff_text = sys.stdin.read()
    elif args.diff_file:
        diff_text = Path(args.diff_file).read_text(encoding="utf-8")
    else:
        try:
            diff_text = subprocess.run(
                ["git", "diff", "HEAD"], capture_output=True, text=True, check=True
            ).stdout
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"scan_diff: could not run git diff HEAD: {e}", file=sys.stderr)
            return 2

    findings = scan_diff(diff_text)
    if args.show_context:
        context_by_loc = {}
        for file, line, content in _added_lines(diff_text):
            context_by_loc.setdefault((file, line), content)
        for f in findings:
            content = context_by_loc.get((f["file"], f["line"]), "")
            f["context"] = _masked_context(content)

    if args.format == "json":
        print(json.dumps(findings, ensure_ascii=False, indent=2))
    else:
        if not findings:
            print("Keine Risiko-Signale im Diff gefunden (heuristisch).")
        else:
            for f in findings:
                loc = f"{f.get('file', '?')}:{f.get('line', '?')}"
                print(f"{loc}  [{f['severity']}] {f['check']}: {f['signal']}")
                if "context" in f:
                    print(f"      | {f['context']}")
            risky = sum(1 for f in findings if f["severity"] == "risky")
            notes = len(findings) - risky
            print(f"\n{risky} riskant(e), {notes} Hinweis(e) — Checklist-Items im Detail prüfen.")

    if args.fail_on_risky and any(f["severity"] == "risky" for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
