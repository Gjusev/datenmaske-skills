# Datenmaske Skills

**DSGVO-native Skills für Coding-Agents** — deutsche PII-Erkennung und
Schwärzung, DSGVO-Review-Checkliste für Pull Requests und Fake-Redaction-Schutz
für PDFs. Funktioniert mit Claude Code, Codex, Cursor, Windsurf, Cline und
jedem Agenten, der Agent-Skills (SKILL.md + Skripte) laden kann.

> EN abstract: Agent skills that give any coding agent German GDPR-native
> capabilities — detect & redact German PII (IBAN, Steuer-ID, Krankenkassen-
> nummer, addresses, names, …), run a DSGVO/RDG checklist on pull requests
> with typed allow/hold/block verdicts, and catch fake PDF redactions in CI.
> Zero dependencies, offline, deterministic.

Warum dieses Paket existiert: Coding-Agents lesen, erzeugen und committen
heutzutage Dateien mit echten Kundendaten — Briefe, Rechnungen, Exporte,
Logs. Werkzeuge wie Presidio zielen auf Data-Science-Pipelines, gitleaks auf
Secrets. Für den **deutschen** Datenschutz-Alltag im Agenten-Workflow gab es
noch nichts Fertiges. Dieses Paket füllt die Lücke mit drei Skills, die
zusammen (oder einzeln) installiert werden können.

---

## Installation (1 Minute)

```bash
git clone https://github.com/Gjusev/datenmaske-skills.git
mkdir -p .claude/skills
cp -r datenmaske-skills/skills/* .claude/skills/
```

Das war alles — keine Abhängigkeiten, keine API-Keys, kein Netzwerk. Die
Skills sind reine Python-Stdlib-Skripte plus Markdown-Anweisungen
(Python ≥ 3.9-Syntax; CI-geprüft auf 3.11–3.13, denn 3.9/3.10 sind EOL
und auf aktuellen Runner-Images nicht mehr installierbar).

- **Claude Code / Codex / Cline:** Skills unter `.claude/skills/` (projekt)
  oder `~/.claude/skills/` (global) ablegen — der Agent lädt sie automatisch.
- **Cursor / Windsurf / andere:** SKILL.md-Dateien als Rules/Instructions
  einbinden, Skripte liegen daneben und laufen mit jedem Python ≥ 3.9.
- **Nur ein Skill gewünscht?** Jeder Unterordner von `skills/` ist
  in sich geschlossen. `dsgvo-pr-checklist` nutzt die Detektoren aus
  `presidio-de`, wenn beide installiert sind (degradiert sonst sauber).

Updates: `git pull` im Clone, `cp` erneut — fertig.

## Die drei Skills

### 1. `presidio-de` — Deutsche PII erkennen & schwärzen

Deterministische Detektoren (Regex + Prüfsummen: IBAN mod-97, Steuer-ID und
KVNR ISO 7064, Kreditkarte Luhn), kein Modell, keine Cloud:

```bash
$ python3 .claude/skills/presidio-de/scripts/scan_pii.py kundenbrief.txt
kundenbrief.txt:2:23  PERSON_NAME_DE[likely]  Müller
kundenbrief.txt:4:11  IBAN[confirmed]  DE89 3704 0044 0532 0130 00
kundenbrief.txt:5:12  STEUER_ID[confirmed]  02538413968
kundenbrief.txt:6:21  KVNR[confirmed]  K127508150
kundenbrief.txt:7:10  PHONE_DE[likely]  +49 (0)30 12345678
kundenbrief.txt:8:9   EMAIL[confirmed]  max.mustermann@example.org
kundenbrief.txt:9:11  STREET_ADDRESS[likely]  Marienstraße 12
kundenbrief.txt:9:28  PLZ_ORT[likely]  10117 Berlin
kundenbrief.txt:10:1  GEBURTSDATUM[likely]  Geburtsdatum: 15.08.1975

9 Treffer — EMAIL: 1, GEBURTSDATUM: 1, IBAN: 1, KVNR: 1, …
```

```bash
$ python3 .claude/skills/presidio-de/scripts/redact_pii.py kundenbrief.txt
$ cat kundenbrief.txt.redacted
…
Ihre IBAN [IBAN] wurde geprüft.
Steuer-ID: [STEUER-ID]
Versichertennummer: [KVNR]
…
```

Konfidenzstufen: `confirmed` (Prüfsumme gültig — praktisch keine
Fehlalarme), `likely` (Struktur + Kontext), `weak` (nur Format, opt-in).
Alle Beispieldaten hier und in den Fixtures sind **synthetisch** —
Prüfziffern gültig, Inhalte zufällig.

### 2. `dsgvo-pr-checklist` — Datenschutz-Review für PRs

Vor dem Öffnen eines PRs, der personenbezogene Daten berührt: deterministischer
Diff-Scan plus Checkliste K1–K10 (PII im Code, Secrets, Rechtsgrundlage,
Logging, Datenminimierung, Drittlandtransfer, Cookies, Betroffenenrechte,
Aufbewahrung, Testdaten). Jedes Item endet mit einem typisierten Verdict —
**allow / hold / block** mit Beleg, im Muster der Guard-Entscheidungen von
[laya-warden](https://github.com/Gjusev/laya-warden). Das Ergebnis geht als
`## DSGVO-Check`-Abschnitt in die PR-Beschreibung: Reviewer sehen, *was der
Agent geprüft hat*, statt einem „passt schon“ zu vertrauen.

```bash
$ git diff main...HEAD | python3 .claude/skills/dsgvo-pr-checklist/scripts/scan_diff.py --stdin
src/kunden/service.ts:14  [risky] K4-Logging: personal-data-in-log-call
src/kunden/service.ts:15  [risky] K1-PII-im-Code: IBAN [confirmed]
src/kunden/service.ts:16  [risky] K2-Secrets: credential-assignment
db/migrations/0042_add_fields.sql:3  [note] K5-Datenminimierung: personal-column-in-migration

3 riskant(e), 1 Hinweis(e) — Checklist-Items im Detail prüfen.
```

Secrets werden vom Werkzeug nie mitausgegeben (auch nicht mit
`--show-context` — maskiert bleibt maskiert, damit CI-Logs nicht zum
Leck werden). `--fail-on-risky` macht daraus einen CI-Gate.

### 3. `redaction-ci` — Fake-PDF-Schwärzungen in CI abfangen

Wrapper-Skill für [Gjusev/redaction-ci](https://github.com/Gjusev/redaction-ci)
(„gitleaks, but for PDFs“): Ein schwarzes Rechteck über einem Absatz löscht
den Absatz nicht — der Text bleibt kopierbar. Die Action scheitert genau
dort, bevor es in das Repository kommt. Der Skill entscheidet, wann ein Repo
sie braucht, installiert den Workflow in 1 Minute und prüft mit einer
Synthetic-Fixture, dass das Gate wirklich gate't.

---

## Ehrlichkeit zuerst

Was dieses Paket **kann**: deterministische, erklärbare Befunde mit bekannten
Abdeckungslücken (in jedem SKILL.md dokumentiert), schwärzte Kopien statt
Originalen, typisierte Verdicts mit Belegen, Offline-Betrieb ohne Datenabfluss.

Was es **nicht kann**: Rechtsberatung sein (die Checkliste ersetzt keine
DSFA und keinen DPO), vollständige Namenserkennung ohne NER-Modell
(Abwägung dokumentiert; optionaler Microsoft-Presidio-Aufpfropf in
`references/entities.md`), Forensik-Zertifikate für PDFs (Redaction-CI ist
ein Regressions-Gate). Berichte lauten „deterministische Detektoren,
bekannte Lücken“ — niemals „jetzt ist die Datei frei von personenbezogenen
Daten“.

## Für wen

- Teams, die mit deutschen Kunden-/Patienten-/Mitarbeiterdaten arbeiten und
  Coding-Agents im Alltag nutzen (Kanzleien, Steuerbüros, SaaS-Betriebe,
  Agenturen mit DSGVO-Pflichten).
- Agent-Betreiber, die ihre Agenten datenschutzfest machen wollen, bevor
  ein Fixture-Dump in das Repository wandert.
- Compliance-Seiten, die von Agenten-PRs einen prüfbaren Datenschutz-Check
  verlangen statt Bauchgefühl.

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

65 Tests, keine Abhängigkeiten. In CI (GitHub Actions) läuft dasselbe als
`pytest`-kompatible Suite.

## Verwandte Projekte

- [Gjusev/redaction-ci](https://github.com/Gjusev/redaction-ci) — die Action
  hinter Skill 3.
- [Gjusev/laya-warden](https://github.com/Gjusev/laya-warden) —
  allow/hold/block-Guards für Agent-Tool-Calls; das Verdict-Muster der
  Checkliste.
- [microsoft/presidio](https://github.com/microsoft/presidio) — optionale
  NER-Aufpfropfung für Namen/Orte (Anleitung in `references/entities.md`).

## Lizenz

MIT — siehe [LICENSE](LICENSE). Beispieldaten im Repo sind synthetisch.
Kein Rechtsrat.
