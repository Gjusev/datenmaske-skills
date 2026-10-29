# Entity reference: German PII types

All example values below are **synthetic** — checksum-valid where a checksum
exists, but random content, no real accounts, no real people.

## Confirmed entities (checksum/algorithm-validated)

### IBAN
- Format: `DE` + 2 check digits + 8-stellige Bankleitzahl + 10-stellige
  Kontonummer (22 Zeichen gesamt); spaces/hyphens tolerated while scanning.
- Validation: ISO 7064 MOD 97-10. Detections are essentially false-positive-free.
- Example: `DE89 3704 0044 0532 0130 00` (the canonical sample IBAN).
- Note: non-SEPA lengths (5–34 chars) are accepted if the checksum passes.

### STEUER_ID (Steuer-Identifikationsnummer)
- Format: 11 Ziffern, ohne Trennzeichen.
- Validation: ISO 7064 MOD 11,10 over the first 10 digits; additionally the
  current specification encodes the Bundesland in digits 1–2 (`01`–`10`).
  A checksum-valid number outside `01`–`10` is reported as `likely`
  (older numbering schemes still checksum).
- Also excluded from issuance: a digit more than twice in a row, more than
  ten of the same digit — the detector does not enforce these secondary rules;
  the checksum alone keeps precision high.

### KVNR (Krankenversichertennummer / Krankenkassen-Nr.)
- Format: 1 Buchstabe + 9 Ziffern, z. B. `K127508150`.
- Validation: letter → two-digit number (A=01 … Z=26), then ISO 7064 MOD
  11,10 with the 9th digit as Prüfziffer.
- Issued letters exclude the confusables C, I, N, O, Z; a checksum-valid
  match with such a letter is downgraded to `likely`.

### KREDITKARTE
- 13–19 Ziffern (Gruppierung mit Leerzeichen/Bindestrich tolerated),
  Luhn-validated. Placeholder in redaction: `[KARTENNUMMER]`.

### EMAIL
- RFC-style pattern, length-capped at 254. Umlaut domains (IDN) match in
  their ASCII-encoded form only.

## Likely entities (format + context, no public checksum)

### SVNR (Sozialversicherungs-/Rentenversicherungsnummer)
- Format: `2-stelliger Bereichsstelle-Code + JJMMTT + 1 Buchstabe + 3 Ziffern`
  (12 Zeichen), z. B. `12750815A123`.
- Validation: encoded birthdate must be a plausible calendar date. The letter
  is the surname initial; C/I/N/O/Q/Z are not issued and downgrade to `weak`.
- Risk: collides with any 8-digit number followed by a letter — context
  (keyword "Sozialversicherungsnummer", table headers) should confirm.

### PHONE_DE
- `+49` / `0049` / `0` prefix; trunk `0` inside parens (`+49 (0)30 …`)
  supported. Digit-count validation: 6–13 digits after country code,
  7–12 for national format.
- Risk: reference numbers that look like phone numbers ("Bestell-Nr 030
  123456") can match. Check context before treating as PII.

### STREET_ADDRESS
- German compounds without space (`Marienstraße 12`) and separated forms
  (`Am Markt 4`), suffix list: Straße/Straße (also `Str.`), Weg, Allee,
  Platz, Gasse, Ring, Damm, Ufer, Markt, Moor, Brücke(n), Chaussee;
  Hausnummer 1–4 Ziffern + optional Buchstabe (`5a`) or `/1` stockwerk.
- Not detected: addresses whose street type is missing from the suffix list
  (e.g. Steige, Gärten, Höfe) or foreign-format addresses.

### PLZ_ORT
- 5 Ziffern + 1–3 Ortsnamen-Wörter (`10117 Berlin`, `04109 Leipzig`).
  A stoplist of common follow-up words (Jahr, Euro, Zeichen, …) suppresses
  obvious non-places. Remaining risk: "12345 Punkte"-artige Fälschungen —
  Ortsnamen werden nicht gegen eine Städteliste geprüft (keine Datenbeimischung).

### GEBURTSDATUM
- `DD.MM.JJJJ` (or 2-digit year), gated by context keywords:
  `geb.`, `geboren (am)`, `Geburtsdatum`, `dob`. Dates without such a
  keyword are never flagged (too many benign dates in prose).

### PERSON_NAME_DE (title-gated)
- Anchors: `Herr`, `Herrn`, `Frau`, `Fr.`, `Dr.`, `Prof.`, `Dipl.-Ing.`
  (chained: „Frau Dr. med. habil. Weber“). Adelspartikel (von/van/de/zu/
  vom/zur) in Namensketten werden mit erfasst.
- Recall limit: bare surnames („… hat Müller angerufen“) are **not**
  detected. That is the price of low false positives without an NER model.

## Weak entities (opt-in via `--include-weak`)

### PERSON_NAME_DE (first-name pair)
- Small lexicon of very common German first names followed by a capitalized
  token („Max Mustermann“, „Anna Schmidt“). Format-only → high FP risk in
  prose („Maximalwert…” ist ausgeschlossen durch Wortgrenze, aber
  „Max Planck Institut“ matcht). Use as a hint.

### PERSONALAUSWEIS
- Klassisches Format `L01X00T471` (Buchstabe, Ziffern, Testbuchstabe,
  Seriennummer). Format-only; der nPA (2010+) nutzt andere Algorithmen,
  die ohne Datenbank nicht validierbar sind.

## Upgrading recall with Microsoft Presidio

The deterministic detectors trade recall for precision and zero setup. When a
project needs NER-grade name/address detection, layer Microsoft Presidio on
top (this is optional; the skill never requires it):

```bash
pip install presidio-analyzer presidio-anonymizer
python -m spacy download de_core_news_lg
```

```python
from presidio_analyzer import AnalyzerEngine
analyzer = AnalyzerEngine(language="de")  # requires de_core_news_lg
results = analyzer.analyze(text=text, language="de")
# entities: PERSON, LOCATION, DATE_TIME, IBAN_CODE, DE_STEUERID? (see registry)
```

Mapping to this skill's types: Presidio `PERSON`/`LOCATION` complement
`PERSON_NAME_DE`/`STREET_ADDRESS` (higher recall, more false positives —
review before redacting). `IBAN_CODE` duplicates the built-in detector.
Presidio does **not** ship a KVNR recognizer — keep this skill's detector
for Krankenversichertennummern. A composite run (Presidio for names/locations,
de_pii for checksummed IDs) currently gives the best German coverage.

Presidio is Apache-2.0; the spaCy model has its own license terms. Nothing in
this skill depends on it.
