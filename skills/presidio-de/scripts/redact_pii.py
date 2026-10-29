#!/usr/bin/env python3
"""Redact German PII in text files — write masked copies, never touch originals.

Usage:
    redact_pii.py FILE [FILE ...|DIR ...] [options]

Examples:
    redact_pii.py brief.txt                          # writes brief.txt.redacted
    redact_pii.py export/ --out masked/ --keep-length
    redact_pii.py data.csv --in-place                # only with an explicit flag

Exit codes:
    0  redaction written (or nothing to do)
    2  usage or IO error

Placeholders are typed ([IBAN], [STEUER_ID], [NAME], …) so the redacted file
stays readable and greppable for what was removed. With --keep-length the
match is replaced by ● characters instead, preserving column widths in CSVs
and layout in text.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import de_pii  # noqa: E402

PLACEHOLDER = {
    "IBAN": "[IBAN]",
    "STEUER_ID": "[STEUER-ID]",
    "KVNR": "[KVNR]",
    "SVNR": "[SVNR]",
    "PERSONALAUSWEIS": "[PERSONALAUSWEIS]",
    "KREDITKARTE": "[KARTENNUMMER]",
    "EMAIL": "[E-MAIL]",
    "PHONE_DE": "[TELEFON]",
    "STREET_ADDRESS": "[ADRESSE]",
    "PLZ_ORT": "[PLZ/ORT]",
    "PERSON_NAME_DE": "[NAME]",
    "GEBURTSDATUM": "[GEBURTSDATUM]",
}


def redact_text(
    text: str,
    *,
    include_weak: bool = False,
    names: bool = True,
    keep_length: bool = False,
) -> tuple[str, int]:
    """Return (redacted_text, number_of_redactions)."""
    findings = de_pii.find_pii(text, include_weak=include_weak, names=names)
    if not findings:
        return text, 0
    parts: list[str] = []
    cursor = 0
    for f in findings:  # already sorted by position, non-overlapping
        parts.append(text[cursor : f.start])
        if keep_length:
            parts.append("●" * (f.end - f.start))
        else:
            parts.append(PLACEHOLDER.get(f.type, "[PII]"))
        cursor = f.end
    parts.append(text[cursor:])
    return "".join(parts), len(findings)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Redact German PII in text files (writes copies by default)."
    )
    parser.add_argument("paths", nargs="+", help="files or directories to redact")
    parser.add_argument("--out", metavar="DIR", help="write redacted copies into DIR")
    parser.add_argument("--in-place", action="store_true",
                        help="overwrite the input files (explicit opt-in)")
    parser.add_argument("--keep-length", action="store_true",
                        help="mask with ● characters instead of typed placeholders")
    parser.add_argument("--include-weak", action="store_true",
                        help="also redact format-only entities (Personalausweis, name pairs)")
    parser.add_argument("--no-names", action="store_true",
                        help="skip PERSON_NAME_DE heuristics")
    parser.add_argument("--suffix", default=".redacted",
                        help="suffix for copy mode (default .redacted)")
    parser.add_argument("--max-file-bytes", type=int, default=5_000_000)
    args = parser.parse_args(argv)

    if args.in_place and args.out:
        parser.error("--in-place and --out are mutually exclusive")

    from scan_pii import iter_files, read_text_limited

    files = iter_files([Path(p) for p in args.paths], [])
    if not files:
        print("redact_pii: nothing to do (no readable text files).", file=sys.stderr)
        return 0

    total = 0
    for path in files:
        text = read_text_limited(path, args.max_file_bytes)
        if not text:
            print(f"redact_pii: skipping (binary, undecodable or oversized): {path}",
                  file=sys.stderr)
            continue
        redacted, count = redact_text(
            text,
            include_weak=args.include_weak,
            names=not args.no_names,
            keep_length=args.keep_length,
        )
        if args.in_place:
            target = path
        elif args.out:
            out_dir = Path(args.out)
            out_dir.mkdir(parents=True, exist_ok=True)
            target = out_dir / path.name
        else:
            target = path.with_name(path.name + args.suffix)
        if count:
            target.write_text(redacted, encoding="utf-8")
            total += count
            print(f"{path} -> {target}  ({count} Redaktionen)")
        else:
            print(f"{path} -> (keine Treffer, keine Datei geschrieben)")
    if total:
        print(f"\nInsgesamt {total} Redaktionen.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
