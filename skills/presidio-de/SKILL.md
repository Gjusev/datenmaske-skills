---
name: presidio-de
description: Detect and redact German PII (person names, addresses, IBAN, Steuer-ID, Krankenkassen-/Versichertennummern, SVNR, phone, email, birthdates) in any file a coding agent touches. Use when reading, editing, generating, committing or fixture-loading files that may contain German personal data (customer letters, invoices, HR data, log exports, CRM dumps), when the user asks for DSGVO/Datenschutz redaction or anonymization, or before adding "realistic" German sample data to a repository. Zero dependencies (Python stdlib), works offline.
license: MIT
---

# Presidio-DE: German PII detect & redact

Deterministic German PII detection for coding agents. Regex + checksum
validation (IBAN mod-97, Steuer-ID/KVNR ISO 7064 MOD 11,10, credit card Luhn),
not statistical NER: every finding is explainable and reproducible, at the
cost of known recall gaps (documented below and in `references/entities.md`).

## When this skill triggers

- You read, edit, create or commit files that may contain **German personal
  data**: customer/patient letters, Rechnungen, HR files, CRM exports, log
  dumps, support tickets, `.eml` files, scraped datasets.
- You are about to generate **"realistic" German sample/fixture/test data**
  (use synthetic values and/or redact before committing).
- The user asks to **schwärzen, anonymisieren, redacten, DSGVO-konform machen**
  a file, export or fixture.
- A diff you are about to propose would add personal data to the repo
  (pair with the `dsgvo-pr-checklist` skill before opening the PR).

## Quick start

Scripts are stdlib-only Python (3.9+ syntax; CI-tested on 3.11-3.13). Run them from this skill's `scripts/`
directory (or with any interpreter):

```bash
# 1. Scan a file (or directory, recursive) — findings with file:line:col
python3 scripts/scan_pii.py path/to/file.txt
python3 scripts/scan_pii.py exports/ --exclude '*.min.js'

# 2. Machine-readable output for your own reasoning
python3 scripts/scan_pii.py file.txt --format json --no-content

# 3. Redact — ALWAYS writes a copy (file.redacted), never touches the original
python3 scripts/redact_pii.py file.txt                 # typed placeholders
python3 scripts/redact_pii.py export/ --out masked/    # copies into masked/
python3 scripts/redact_pii.py data.csv --keep-length   # ●●●●, keeps column widths
python3 scripts/redact_pii.py file.txt --in-place      # overwrite: explicit opt-in only
```

Exit codes (`scan_pii.py`): `0` clean, `1` findings at/above `--fail-on`
(use `--fail-on confirmed` in CI gates), `2` usage/IO error.

## Operating rules

1. **Scan before you commit.** Any file that *could* contain personal data
   gets a scan in the same turn it is created or edited. One command, no
   excuses.
2. **Prefer redaction over deletion.** If a document must stay in the repo
   (fixture, doc example), commit the redacted copy — never the original.
   Keep originals outside version control and say so.
3. **Never paste findings verbatim anywhere.** Scan output can contain the
   PII itself. When reporting to the user, quote only file/line/type, or run
   with `--no-content`.
4. **Respect confidence levels.** `confirmed` = checksum-validated
   (IBAN, KVNR, KREDITKARTE, EMAIL) — treat as certain; the Steuer-ID is
   `confirmed` only when checksum *and* issuance structure pass (a
   checksum-valid number that was never issued that way is `likely`).
   `likely` = structural/context (phone, address, SVNR, Geburtsdatum,
   title-gated names). `weak` = format-only, opt-in via `--include-weak`.
   For a commit gate, act on `confirmed` + `likely`; treat `weak` as a hint,
   not a finding.
5. **Generating German test data?** Generate it *synthetic and flagged as
   such*: use `Mustermann`/`Musterfrau` surnames, `example.org` emails,
   the well-known sample IBAN `DE89 3704 0044 0532 0130 00`, and checksums
   computed from random digits. Then scan your generated file anyway —
   the scan is the proof, not the intention.
6. **PDFs are out of scope here.** This skill handles *text*. For PDFs whose
   redaction boxes may hide extractable text, use the companion
   `redaction-ci` skill (or Gjusev/redaction-ci directly).

## What is detected (and what is not)

| Entity | Confidence | Method |
| --- | --- | --- |
| IBAN (SEPA/DE, spaced or compact) | confirmed | mod-97 checksum |
| Steuer-Identifikationsnummer | confirmed* | ISO 7064 MOD 11,10 + issuance structure (randomly assigned — no Bundesland code); checksum-only matches → likely |
| Krankenkassen-/Versichertennummer (KVNR) | confirmed | ISO 7064 via letter→digits |
| Sozial-/Rentenversicherungsnummer (SVNR) | likely | birthdate plausibility |
| Kreditkarte | confirmed | Luhn |
| E-Mail | confirmed | RFC-style |
| Telefon (DE, +49/0-Prefix) | likely | digit-count validation |
| Straße + Hausnummer / PLZ + Ort | likely | compound-word patterns |
| Geburtsdatum (keyword-gated: geb./geboren/Geburtsdatum) | likely | date validation |
| Person name (title-gated: „Herr“, „Frau Dr.“…) | likely | pattern + particle names |
| Person name (first-name pair: „Max Mustermann“) | weak | small first-name lexicon |
| Personalausweis-Nr. (old format) | weak | format only |

**Not detected:** names without a title/first-name anchor (no NER model),
arbitrary Ausweis-/Führerschein formats beyond the classic pattern, health
data in free prose, PII inside images/scans, and PII inside PDF text layers.
For higher name/address recall, install Microsoft Presidio with the German
spaCy model on top — the upgrade path and entity mapping are in
`references/entities.md`.

Honesty rule for reporting: report scan coverage as "deterministic detectors,
X entities, known recall gaps" — never as "the file is now free of personal
data". Redaction via this skill reduces exposure; it is not a certification.

## Agent-tooling notes

- Importable as a module: `sys.path.insert(0, <this skill>/scripts)` then
  `import de_pii; de_pii.find_pii(text)` → list of `Finding(type, start, end,
  confidence, text)` spans. Useful when you need programmatic redaction inside
  a larger edit instead of whole-file replacement.
- `find_pii` de-overlaps findings (higher confidence wins) and is deterministic:
  same input → same output, no model, no network, no API keys, nothing leaves
  the machine.
- The `dsgvo-pr-checklist` skill reuses this same detector on diffs —
  results are consistent across both skills.
