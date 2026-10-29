---
name: dsgvo-pr-checklist
description: Run a DSGVO/GDPR (and BDSG/RDG-aware) review checklist on a pull request before it is opened or handed to review. Use when a diff touches personal data in any form (user models, logging, analytics, migrations, exports, third-party APIs, cookies/tracking), when the repo processes German/EU user data, or when the user asks for a Datenschutz/DSGVO check of a PR. Produces a structured verdict per checklist item (allow/hold/block) that goes into the PR description. Deterministic diff scanner included; works offline.
license: MIT
---

# DSGVO PR-Checklist:Datenschutz-Review für Pull Requests

A coding-agent checklist that turns DSGVO principles into concrete,
checkable pull-request review steps. Verdict model borrowed from the
allow/hold/block guard pattern of laya-warden (github.com/Gjusev/laya-warden):
every item ends in a typed verdict with a reason, so a human reviewer can
audit *what the agent checked* instead of trusting "looks fine".

**Scope and honesty:** this is an engineering checklist that operationalizes
common Art. 5 / 24 / 25 / 32 DSGVO duties for code changes. It is **not
legal advice** and does not replace the Datenschutz-Folgenabschätzung or the
DPO. It catches the typical engineering mistakes; legal judgement stays with
humans.

## When this skill triggers

- A diff touches: user/customer data models, logging of user actions,
  analytics or tracking, authentication, exports/backups, email/SMS sending,
  third-party API calls with user data, cookies, training data, fixtures
  with realistic data.
- The repo's product processes German or EU personal data.
- Someone asks for a "DSGVO check", "Datenschutz-Review" or privacy review
  of a PR.
- Your repo rules require a DSGVO section in PR descriptions (this skill
  produces exactly that).

## Workflow

### 1. Deterministic pre-scan (always run first)

```bash
git diff main...HEAD | python3 skills/dsgvo-pr-checklist/scripts/scan_diff.py --stdin
# or, from the repo root (scans git diff HEAD):
python3 skills/dsgvo-pr-checklist/scripts/scan_diff.py
# CI gate mode:
python3 skills/dsgvo-pr-checklist/scripts/scan_diff.py --stdin --fail-on-risky
```

Signals map to checklist items (K1–K7, see `references/checklist.md`):
PII in code lines (reuses the presidio-de detectors), hardcoded secrets,
logging of personal data, migration columns that look personal, outbound
transfers with user payloads, cookie/tracking code. `--show-context` prints
the matched code line with every detected secret **and** PII value masked —
masking is content-based, so a credential is masked even when the finding
that surfaced the line points at another checklist item. Without the flag
only file/line/signal are shown.

### 2. Work through the checklist

Read `references/checklist.md` and answer every item K1–K10 against the
actual diff. Read the changed files where the diff alone is ambiguous —
a checklist answered from the diff summary is worth nothing.

### 3. Emit typed verdicts

Per item, end with exactly one verdict:

- **allow** — item checked, no issue, one-line evidence ("no personal
  columns added; migration only adds tenant_id").
- **hold** — plausible concern the agent cannot resolve alone; name the
  question for the reviewer.
- **block** — clear violation found (hardcoded PII/secrets, logging of
  special-category data, transfer without legal basis artifact); name the
  fix and do not hand the PR to review before it is applied.

Never emit `allow` without evidence. An empty evidence string is a `hold`.

### 4. Append the DSGVO section to the PR description

Use this exact shape (human reviewers and CI regexes rely on it):

```markdown
## DSGVO-Check (dsgvo-pr-checklist)
- Scan: N Signale (M riskant) — `scan_diff.py`
- K1 PII im Code: allow — <evidence>
- K2 Secrets: allow — <evidence>
- K3 Rechtsgrundlage/Zweck: hold — <question for reviewer>
- K4 Logging: allow — <evidence>
- K5 Datenminimierung: allow — <evidence>
- K6 Drittland/Externe: allow — <evidence>
- K7 Cookies/Tracking: n/a — keine Tracking-Änderungen
- K8 Betroffenenrechte: allow — <evidence>
- K9 Aufbewahrung/Löschung: allow — <evidence>
- K10 Tests mit echten Daten: allow — <evidence>
Gesamt: allow / hold / block — <one sentence>
```

Items that genuinely do not apply get `n/a` with one reason line, not
silence.

### 5. Gate your own hand-off

If the overall verdict is `block`, fix the code (or split the offending
commits out) before handing the PR to review. If it is `hold`, hand it off
anyway and make sure the hold questions are visible in the PR description
and, where applicable, in the review task.

## Integration notes

- Pair with the `presidio-de` skill: its detector powers the K1 pre-scan,
  and redaction of leaked fixtures is the standard K10 fix.
- Pair with `redaction-ci`: repos that commit PDFs should have the action
  installed; mention its findings under K1.
- CI usage: `scan_diff.py --stdin --fail-on-risky` exits 1 on risky signals
  (secrets, checksummed PII, personal-data logging). Wire it as a required
  check if the project wants a hard gate; expect it to miss things a human
  must still review (K3, K8, K9 are judgement items by design).
