# DSGVO PR-Checkliste für Coding Agents

Technische Review-Checkliste (kein Rechtsrat). Verdict je Item:
**allow** (geprüft, ok, mit Beleg) · **hold** (Frage an Reviewer) ·
**block** (klarer Verstoß, Fix vor Review) · **n/a** (nicht berührt, mit Grund).

Grundlagen: Art. 5 (Grundsätze), Art. 24 (Verantwortung), Art. 25
(Privacy by Design/Default), Art. 32 (Sicherheit) DSGVO; § 64 BDSG;
RDG (Verbraucherdatenschutzrecht) wo Datenmarktteilnahme betroffen ist.

---

## K1 — PII im Code / in Fixtures (Art. 5 Abs. 1 Buchst. c, Art. 32)
- Enthält der Diff echte personenbezogene Daten? (Namen, IBAN, Steuer-ID,
  KVNR, Adressen, E-Mails, Telefonnummern, Geburtsdaten) — deterministisch
  prüfbar mit `scan_diff.py` (nutzt die presidio-de-Detektoren).
- Enthalten Testdaten/Fixtures „realistisch aussehende“ Daten? Muss
  synthetisch sein (Mustermann, example.org, gültige Prüfziffern aus
  Zufallsziffern) — oder redigiert (`presidio-de` skill).
- `block`-Kriterien: bestätigte PII (Prüfsummen-Treffer), echte Kundendaten
  in Fixtures.

## K2 — Secrets & Zugangsdaten (Art. 32)
- API-Keys, Tokens, Passwörter, private Schlüssel im Diff? Auch
  „Platzhalter“-Secrets, die zufällig gültig aussehen.
- Verbindungsstrings mit Credentials (DB-URLs mit Passwort)?
- `block`: jedes reale Secret. Fix: Rotation + Secret-Manager, nicht nur
  Entfernen (Git-Historie!).

## K3 — Rechtsgrundlage & Zweckbindung (Art. 5 Abs. 1 Buchst. b, Art. 6)
- Dient die Änderung dem dokumentierten Verarbeitungszweck oder erweitert
  sie ihn? Neue Verarbeitungsart → braucht dokumentierte Rechtsgrundlage
  (Einwilligung Art. 6 lit. a, Vertrag lit. b, berechtigtes Interesse lit. f).
- Werden Daten für einen neuen, nicht mitgeteilten Zweck wiederverwendet
  (z. B. Support-Daten → Marketing)? Typischer Fall für `hold` mit Frage an
  den Owner/DPO.

## K4 — Logging & Monitoring (Art. 5, Art. 25)
- Landen personenbezogene Daten in Logs? (E-Mail, User-IDs + Kontext,
  Payload-Dumps, Stacktraces mit Userdaten)
- Sonderkategorien (Gesundheit, Herkunft, Religion, Biometrie — Art. 9) im
  Log? → immer `block`, außer explizit freigegeben.
- Log-Retention definiert? (Retention-Konfiguration im selben PR wie das
  neue Log-Statement ist gutes Zeichen)

## K5 — Datenminimierung & Zweckmäßigkeit (Art. 5 Abs. 1 Buchst. c)
- Neue Felder: braucht das Produkt jedes Feld? (Vollständiges Geburtsdatum
  vs. Altersprüfung, vollständige Adresse vs. PLZ)
- Standardwerte datenschutzfreundlich? (Opt-in statt Opt-out, leere
  Standardfelder, keine vorangekreuzten Einwilligungen — Art. 25 Abs. 2)

## K6 — Drittlandtransfer & externe Dienste (Art. 44 ff.)
- Verläufen personenbezogene Daten den Server durch neue externe Calls
  (APIs, Webhooks, SaaS-Tools)? Empfangsland/EU-Adequanz geklärt?
  (Drittland: SCCs/TFHP in Auftrag angelegt?)
- Verarbeitet ein neuer externer Dienst Daten als Auftragsverarbeiter
  (Art. 28 AVV vorhanden)? → `hold` mit Verweis auf Procurement/DPO wenn
  unklar.

## K7 — Cookies & Tracking (Art. 5 Abs. 3 TTDSG/ePrivacy, § 25 TTDSG)
- Neue Cookies/Tokens/Device-Fingerprints ohne Consent-Mechanismus?
  Technisch notwendige Cookies dokumentiert?
- Tracking-IDs generiert ohne Einwilligungs-Flag? → `block` bis Consent
  abgefragt wird.

## K8 — Betroffenenrechte (Art. 15–21)
- Neue Datenart ⇒ können Auskunft/Löschung/Berichtigung sie noch abbilden?
  (Neues Feld in Export/Lösch-Routine berücksichtigt?)
- Wird Löschbarkeit durch neue Verknüpfungen schwieriger (denormalisierte
  Kopien, Caches, Event-Sourcing)? → `hold` wenn unklar.

## K9 — Aufbewahrung & Löschung (Art. 5 Abs. 1 Buchst. e)
- Neue Daten mit Löschfrist/Konzept? Backups/Exports der neuen Daten
  über Aufbewahrungsfrist hinaus?
- Anonymisierung vs. Löschung: anonymisierte Aggregate wirklich anonym?

## K10 — Tests & Uhren-Daten (Art. 25, K1-Anhang)
- Tests gegen echte Produktionsdaten? (Dump-Import, „anonymisierte“ Kopien)
  → `block`; Fix: synthetische Daten oder offizielle Testdatenquellen.
- Läuft der neue Codepfad in CI mit Daten, die in Artefakten landen
  (Coverage-Reports, Logs als CI-Artefakt)?

---

## Verdict-Ermittlung

- Jedes `block`-Item ⇒ Gesamtverdict `block`, PR wird nicht zur Review
  gegeben, Fix zuerst.
- Kein `block`, aber ≥ 1 `hold` ⇒ Gesamtverdict `hold`, Fragen sichtbar in
  die PR-Beschreibung.
- Alles `allow`/`n/a` mit Belegen ⇒ Gesamtverdict `allow`.

## Was diese Checkliste NICHT leistet

Kein Rechtsrat, keine DSFA-Ersatz (Art. 35), keine Entscheidung über
Rechtsgrundlagen (das bleibt beim Owner/DPO), kein Abschlussaudit. Sie
macht die *technischen* DSGVO-Fehler sichtbar, die Agents zuverlässig
prüfen können — mit Belegen statt Behauptungen.
