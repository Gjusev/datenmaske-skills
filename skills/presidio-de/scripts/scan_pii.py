#!/usr/bin/env python3
"""Scan files for German PII.

Usage:
    scan_pii.py FILE [FILE ...|DIR ...] [options]

Examples:
    scan_pii.py kundenbrief.txt --format json
    scan_pii.py src/ --exclude '*.min.js' --fail-on confirmed
    scan_pii.py --stdin < brief.txt

Exit codes:
    0  no findings (or findings below --fail-on threshold)
    1  findings at/above the --fail-on threshold
    2  usage or IO error
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import de_pii  # noqa: E402

TEXT_SUFFIXES = {
    ".txt", ".md", ".markdown", ".csv", ".tsv", ".json", ".yaml", ".yml",
    ".xml", ".html", ".htm", ".log", ".sql", ".py", ".js", ".ts", ".jsx",
    ".tsx", ".java", ".kt", ".go", ".rb", ".php", ".sh", ".env", ".ini",
    ".cfg", ".toml", ".tex", ".rtf", ".eml", ".srt", ".vcf",
}

_CONF_ORDER = {"none": 0, "weak": 1, "likely": 2, "confirmed": 3}


def iter_files(paths: list[Path], excludes: list[str]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            for candidate in sorted(path.rglob("*")):
                if candidate.is_file() and not _excluded(candidate, excludes):
                    files.append(candidate)
        elif path.is_file() and not _excluded(path, excludes):
            files.append(path)
        else:
            print(f"scan_pii: path not found: {path}", file=sys.stderr)
    return files


def _excluded(path: Path, excludes: list[str]) -> bool:
    name = path.name
    parts = path.parts
    for pattern in excludes:
        if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(str(path), pattern):
            return True
        if any(fnmatch.fnmatch(part, pattern) for part in parts):
            return True
    return False


def read_text_limited(path: Path, max_bytes: int) -> str:
    """Read a file as UTF-8 text; return '' for binary/oversized files."""
    if path.stat().st_size > max_bytes:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect German PII (IBAN, Steuer-ID, KVNR, addresses, …) in files."
    )
    parser.add_argument("paths", nargs="*", help="files or directories to scan")
    parser.add_argument("--stdin", action="store_true", help="read text from stdin")
    parser.add_argument("--include-weak", action="store_true",
                        help="also report format-only entities (Personalausweis, name pairs)")
    parser.add_argument("--no-names", action="store_true",
                        help="skip PERSON_NAME_DE heuristics")
    parser.add_argument("--exclude", action="append", default=[],
                        metavar="GLOB", help="glob to exclude (repeatable)")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--no-content", action="store_true",
                        help="hide matched text in output (report spans only)")
    parser.add_argument("--fail-on", choices=("none", "weak", "likely", "confirmed", "any"),
                        default="none",
                        help="exit 1 when findings at/above this confidence exist")
    parser.add_argument("--max-file-bytes", type=int, default=5_000_000,
                        help="skip files larger than this (default 5 MB)")
    args = parser.parse_args(argv)

    if not args.paths and not args.stdin:
        parser.error("give at least one path or --stdin")

    threshold = _CONF_ORDER.get(args.fail_on, 0)

    def scan(text: str, display: str) -> list[dict]:
        findings = de_pii.find_pii(
            text, include_weak=args.include_weak, names=not args.no_names
        )
        results = []
        for f in findings:
            line = text.count("\n", 0, f.start) + 1
            col = f.start - text.rfind("\n", 0, f.start)
            results.append({
                "file": display,
                "line": line,
                "col": col,
                "type": f.type,
                "confidence": f.confidence,
                "text": f.text if not args.no_content else f"{f.end - f.start} chars",
            })
        return results

    all_results: list[dict] = []
    if args.stdin:
        all_results.extend(scan(sys.stdin.read(), "<stdin>"))
    else:
        files = iter_files([Path(p) for p in args.paths], args.exclude)
        for path in files:
            text = read_text_limited(path, args.max_file_bytes)
            if not text:
                continue
            all_results.extend(scan(text, str(path)))

    if args.format == "json":
        print(json.dumps(all_results, ensure_ascii=False, indent=2))
    else:
        if not all_results:
            print("Keine deutschen PII-Treffer gefunden.")
        for r in all_results:
            print(
                f"{r['file']}:{r['line']}:{r['col']}  "
                f"{r['type']}[{r['confidence']}]  {r['text']}"
            )
        by_type: dict[str, int] = {}
        for r in all_results:
            by_type[r["type"]] = by_type.get(r["type"], 0) + 1
        if by_type:
            summary = ", ".join(f"{t}: {n}" for t, n in sorted(by_type.items()))
            print(f"\n{len(all_results)} Treffer — {summary}")

    if args.fail_on == "none":
        hit = False
    elif args.fail_on == "any":
        hit = bool(all_results)
    else:
        hit = any(_CONF_ORDER.get(r["confidence"], 0) >= threshold for r in all_results)
    return 1 if hit else 0


if __name__ == "__main__":
    sys.exit(main())
