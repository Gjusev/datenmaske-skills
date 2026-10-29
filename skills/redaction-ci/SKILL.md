---
name: redaction-ci
description: Install and operate Redaction-CI (github.com/Gjusev/redaction-ci) — the GitHub Action that fails CI when a committed PDF still contains extractable text under its redaction boxes ("gitleaks, but for PDFs"). Use when a repository commits PDFs (contracts, invoices, reports, app documents), when someone reports or fixes a broken PDF redaction (Schwärzung), when adding PDF fixtures, or when asked to set up fake-redaction detection / x-ray protection in CI. Includes the action reference, quickstart workflow and local verification steps.
license: MIT
---

# Redaction-CI: fake PDF redactions caught in CI

A black rectangle drawn over a paragraph does **not** delete the paragraph —
the text stays extractable, one copy-paste away. Redaction-CI
(github.com/Gjusev/redaction-ci) fails CI exactly there: extractable text
under a later-drawn, opaque, dark box (`covered-text`, confirmed) plus
never-rendered text layers (render mode 3 / opacity ≤ 0.05 — hidden OCR
layers, `invisible-text`, warning).

This skill wraps the action for coding agents: decide when a repo needs it,
install the workflow, and verify it actually gates.

## When this skill triggers

- The repo **commits PDFs** at all (contracts, Rechnungen, reports, docs,
  app assets) — especially anything user-facing or record-like.
- A user/issue mentions: **Schwärzung**, redaction, "black box over text",
  PDF leak, "the redacted PDF is still readable", x-ray redaction.
- You are about to add a PDF to the repo yourself (check it first!).
- The `dsgvo-pr-checklist` skill's K1 item points at document leakage.

## Install (1 minute)

Create `.github/workflows/redaction.yml`:

```yaml
name: Redaction check
on: [push, pull_request]

jobs:
  redaction:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Gjusev/redaction-ci@v0.1.0
        with:
          paths: |
            **/*.pdf
          fail-on: any
```

Defaults are sane: `fail-on: any` fails on confirmed + warning findings.
Use `fail-on: confirmed` when invisible-text layers are acceptable but
covered text never is. Narrow `paths` to where documents live
(`contracts/**/*.pdf`) so typos still fail loudly (an explicit glob that
matches nothing fails the scan — by design).

No token, no Docker image, no secrets. PyMuPDF (AGPL-3.0) is installed from
PyPI at run time; this matters only for license-sensitive distributions of
your own code, not for running the action.

## Verify the gate actually gates (do not skip)

1. Add a tiny synthetic fixture: a PDF with text covered by a filled dark
   rectangle drawn *after* the text (paint order matters — that is the
   vulnerability), e.g. generated with reportlab/PyMuPDF from two lines of
   dummy text.
2. Open the workflow as PR: the run must fail with a
   `[CONFIRMED] file.pdf p1 — … recoverable` annotation.
3. Fix by removing the text (true redaction) or deleting the fixture if it
   was only a probe. The run must go green.

A green run on a repo without fixture evidence proves nothing about the
gate — the dogfooding pattern above is the acceptance test.

## Before committing a PDF yourself

If you add any PDF to a repo: run the same detection locally first, or at
minimum verify with a text extractor that no intended-sensitive string is
recoverable:

```bash
python3 -c "import fitz; print(fitz.open('doc.pdf')[0].get_text())"
```

If the intended-redacted content appears → do not commit; remove the text
with a real redaction feature (which deletes the run from the content
stream) and re-verify.

## Action reference

Inputs: `paths` (globs, newline-separated), `exclude` (globs),
`fail-on` (`any`|`confirmed`), `max-fill-luma` (default 0.85; raise to 1.0
to also flag white-outs), `min-overlap` (0.5), `min-fill-opacity` (0.5).
Outputs (step `id` + `${{ steps.<id>.outputs.X }}`): `findings`,
`confirmed`, `warnings`, `files`, `pages`, `files-with-findings`, `matched`.

Detection semantics (why false positives are rare):
- Paint order: a box only counts if drawn after the text it covers (dark
  panels with light text on top do not trigger).
- Redaction-like: filled path, opacity ≥ 0.5, perceived luminance ≤ 0.85.
- Overlap: box must cover ≥ 50 % of a text run's bbox.
- Encrypted/unparseable PDFs fail closed (exit 2) — an unverifiable PDF is
  not a clean PDF.

## Honest limitations (repeat these in PR/issue answers)

- **Scans/image-only pages cannot be verified** (no text layer to check) —
  listed as info, never fail the build.
- Image-over-text (text hidden behind a raster image) is out of scope.
- Metadata, attachments, incremental-save leftovers are not analyzed.
- It is a **regression gate**, not a forensic certification: a passing run
  proves no extractable text under redaction-like boxes *in CI*, nothing
  broader.

Full upstream docs: github.com/Gjusev/redaction-ci#readme.
