#!/usr/bin/env python3
"""German PII detection core — deterministic, stdlib-only.

Used by scan_pii.py / redact_pii.py and by the dsgvo-pr-checklist skill's
scan_diff.py. Detection is regex + validation (checksums where a checksum
exists), not statistical NER: what it reports is explainable, but it is not
exhaustive — see references/entities.md for coverage and the optional
Microsoft-Presidio upgrade path.

All entity types:
  IBAN, BIC            — bank identifiers (IBAN validated mod-97)
  STEUER_ID            — Steuer-Identifikationsnummer (ISO 7064 MOD 11,10)
  KVNR                 — Krankenversichertennummer (ISO 7064 MOD 11,10)
  SVNR                 — Sozial-/Rentenversicherungsnummer (plausibility-checked)
  PERSONALAUSWEIS      — old-style Ausweisnummer (format-only, weak)
  KREDITKARTE          — payment card number (Luhn-validated)
  EMAIL
  PHONE_DE             — German landline/mobile, +49 or 0-prefix
  STREET_ADDRESS       — German street + house number
  PLZ_ORT              — 5-digit postcode + city
  PERSON_NAME_DE       — title/first-name heuristics (weak by design)
  GEBURTSDATUM         — date of birth, keyword-gated

Confidence levels:
  confirmed — structural checksum/algorithm validation passed
  likely    — format + context checks passed (no checksum exists)
  weak      — format-only, high false-positive risk (off unless requested)

This file contains no real personal data; fixtures and doctests use
synthetic, checksum-valid but otherwise random identifiers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CONFIRMED = "confirmed"
LIKELY = "likely"
WEAK = "weak"

_CONFIDENCE_RANK = {CONFIRMED: 3, LIKELY: 2, WEAK: 1}


@dataclass(frozen=True)
class Finding:
    """One detected PII span. ``text`` is the raw matched string."""

    type: str
    start: int
    end: int
    confidence: str
    text: str

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "start": self.start,
            "end": self.end,
            "confidence": self.confidence,
            "text": self.text,
        }


# ---------------------------------------------------------------------------
# Checksum algorithms
# ---------------------------------------------------------------------------

def iban_is_valid(iban_compact: str) -> bool:
    """MOD-97-10 (ISO 7064) validation of a compacted IBAN string."""
    if not (5 <= len(iban_compact) <= 34) or not iban_compact[:2].isalpha():
        return False
    if not iban_compact[2:4].isdigit() or not iban_compact[4:].isalnum():
        return False
    rearranged = iban_compact[4:] + iban_compact[:2] + iban_compact[2:4]
    value = 0
    for ch in rearranged.upper():
        if ch.isdigit():
            value = value * 10 + int(ch)
        else:
            value = value * 100 + (ord(ch) - ord("A") + 10)
        value %= 97
    return value == 1


def iso7064_mod1110_check(digits: str) -> bool:
    """Validate a numeric string whose last digit is an ISO 7064 MOD 11,10 check digit.

    Used by both the Steuer-ID (11 digits) and the KVNR (letter -> 2 digits + 9).
    """
    if len(digits) < 2 or not digits.isdigit():
        return False
    p = 10
    for ch in digits[:-1]:
        s = (p + int(ch)) % 10
        if s == 0:
            s = 10
        p = (2 * s) % 11
    return (11 - p) % 10 == int(digits[-1])


def steuer_id_is_valid(steuer_id: str) -> tuple[bool, bool]:
    """Return (checksum_ok, bundesland_code_ok) for an 11-digit Steuer-ID.

    Bundesland codes 01..10 in the first two digits are part of the current
    specification; checksum-valid numbers outside 01..10 are reported as
    ``likely`` because older or foreign-system numbering still checksums.
    """
    if len(steuer_id) != 11 or not steuer_id.isdigit():
        return False, False
    checksum_ok = iso7064_mod1110_check(steuer_id)
    bundesland_ok = steuer_id[:2] in {f"{i:02d}" for i in range(1, 11)}
    return checksum_ok, bundesland_ok


# KVNR: these letters are not issued (confusable letters), matching one
# lowers confidence to ``likely`` even when the checksum is correct.
_KVNR_EXCLUDED_LETTERS = frozenset("CINOZ")

# SVNR: letter is the first letter of the surname; C/I/N/O/Q/Z are not issued.
_SVNR_EXCLUDED_LETTERS = frozenset("CINOQZ")


def kvnr_confidence(kvnr: str) -> str:
    """Checksum-validated KVNR -> confirmed, unless the letter is not issued."""
    letter_idx = ord(kvnr[0].upper()) - ord("A") + 1
    digits = f"{letter_idx:02d}{kvnr[1:]}"
    if not iso7064_mod1110_check(digits):
        return ""
    return LIKELY if kvnr[0].upper() in _KVNR_EXCLUDED_LETTERS else CONFIRMED


def svnr_is_plausible(svnr: str) -> str:
    """SVNR: 2-digit area, JJMMTT birthdate, serial letter, serial + check digit.

    No public checksum; plausibility of the encoded birthdate is the filter.
    """
    digits = svnr[:8]
    month, day = int(digits[4:6]), int(digits[6:8])
    if not (1 <= month <= 12) or not (1 <= day <= 31):
        return ""
    return LIKELY if svnr[8].upper() not in _SVNR_EXCLUDED_LETTERS else WEAK


def luhn_is_valid(number: str) -> bool:
    digits = [int(d) for d in number]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

def _compact_ibans(text: str) -> list[Finding]:
    """IBAN with optional space/hyphen grouping, MOD-97 validated."""
    out: list[Finding] = []
    for m in re.finditer(
        r"\b[A-Z]{2}\d{2}(?:[ -]?(?:[A-Z0-9]{2,4})){2,8}\b",
        text,
    ):
        compact = re.sub(r"[ -]", "", m.group(0))
        # DE IBANs are exactly 22 chars; accept other SEPA lengths but only
        # when the checksum passes, which filters stray uppercase strings.
        if iban_is_valid(compact):
            out.append(Finding("IBAN", m.start(), m.end(), CONFIRMED, m.group(0)))
    return out


def _steuer_ids(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in re.finditer(r"(?<!\d)\d{11}(?!\d)", text):
        checksum_ok, bundesland_ok = steuer_id_is_valid(m.group(0))
        if checksum_ok:
            conf = CONFIRMED if bundesland_ok else LIKELY
            out.append(Finding("STEUER_ID", m.start(), m.end(), conf, m.group(0)))
    return out


def _kvnrs(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in re.finditer(r"(?<![A-Za-z0-9])([A-Z][0-9]{9})(?![A-Za-z0-9])", text):
        conf = kvnr_confidence(m.group(1))
        if conf:
            out.append(Finding("KVNR", m.start(), m.end(), conf, m.group(0)))
    return out


def _svnrs(text: str) -> list[Finding]:
    out: list[Finding] = []
    # 2 area digits + 2 year + 2 month + 2 day + letter + 3 digits.
    for m in re.finditer(
        r"(?<!\d)(\d{2})(\d{2})(\d{2})(\d{2})([A-Z][0-9]{3})(?![A-Za-z0-9])",
        text,
    ):
        conf = svnr_is_plausible(m.group(0))
        if conf:
            out.append(Finding("SVNR", m.start(), m.end(), conf, m.group(0)))
    return out


def _personalausweise(text: str) -> list[Finding]:
    # Old (pre-nPA) format, e.g. L01X00T471. Format-only, hence weak.
    out: list[Finding] = []
    for m in re.finditer(
        r"(?<![A-Za-z0-9])[A-ZÇ][0-9]{2}[A-Z0-9][0-9]{2}[A-Z][0-9]{3}(?![A-Za-z0-9])",
        text,
    ):
        out.append(Finding("PERSONALAUSWEIS", m.start(), m.end(), WEAK, m.group(0)))
    return out


def _kreditkarten(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in re.finditer(r"(?<!\d)(?:\d[ -]?){12,19}\d(?!\d)", text):
        compact = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(compact) <= 19 and luhn_is_valid(compact):
            out.append(
                Finding("KREDITKARTE", m.start(), m.end(), CONFIRMED, m.group(0))
            )
    return out


def _emails(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in re.finditer(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", text
    ):
        if len(m.group(0)) <= 254:
            out.append(Finding("EMAIL", m.start(), m.end(), CONFIRMED, m.group(0)))
    return out


def _phone_digits_ok(number: str) -> bool:
    digits = re.sub(r"\D", "", number)
    if number.startswith("+49"):
        rest = digits[2:]
        if rest.startswith("0"):  # +49 (0)30 …
            rest = rest[1:]
        return 6 <= len(rest) <= 13
    if number.startswith("0"):
        return 7 <= len(digits) <= 12
    return False


def _phones(text: str) -> list[Finding]:
    # National numbers require a separator after the Vorwahl — bare digit
    # runs are IDs/order numbers (checksummed IDs that fail their checksum
    # must not resurface as phones).
    pattern = (
        r"(?:\+49|0049)[\s\-/(]*(?:\(0\))?[\s\-)]*\d{2,5}[\s\-/)]*\d{3,}(?:[\s\-/]\d{1,5}){0,3}"
        r"|\b0\d{2,5}[\s\-/]\d{3,}(?:[\s\-/]?\d{1,5}){0,2}\b"
    )
    out: list[Finding] = []
    for m in re.finditer(pattern, text):
        raw = m.group(0)
        # Trim trailing separators swallowed from prose like "Tel. 030 12345678."
        raw = raw.rstrip(".,;:!?")
        if _phone_digits_ok(raw):
            out.append(
                Finding("PHONE_DE", m.start(), m.start() + len(raw), LIKELY, raw)
            )
    return out


_STREET_SUFFIX = (
    r"(?:[Ss]tr(?:aße|asse)?\.?|[Ww]eg|[Aa]llee|[Pp]latz|[Gg]asse|[Rr]ing|"
    r"[Dd]amm|[Uu]fer|[Mm]arkt|[Mm]oor|[Bb]rücken?|[Cc]haussee)"
)
# German street names are compounds without a space ("Marien" + "straße"),
# but separated forms exist too ("Am Markt 4") — hence the optional space.
_STREET_CORE = (
    r"(?P<street>"
    r"[A-ZÄÖÜ][a-zäöüß]{1,30}(?:[-/][A-ZÄÖÜ][a-zäöüß]{1,30})?"  # name part
    r"[\s]?(?:[a-zäöüß]{1,3}[\s])?"                              # optional separator, von/zu/im
    + _STREET_SUFFIX +
    r"\.?\s+\d{1,4}\s*(?:[a-zA-Z]|/[0-9]{1,4})?)"                # house number
)


def _street_addresses(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in re.finditer(_STREET_CORE, text):
        out.append(Finding("STREET_ADDRESS", m.start("street"), m.end("street"), LIKELY, m.group("street")))
    return out


# Common German words that often follow a bare 5-digit number but are not
# towns ("12345 Zeichen"). Keeps PLZ_ORT false positives tolerable.
_ORT_STOPWORDS = frozenset(
    """jahr jahre jahren euro zeichen punkte stück seiten prozent mal beispiel
    doc pdf jpg png http https mail mails daten satz sätze code liste liste
    version schritt schritte tage tagen wochen stunden minuten euro betrag""".split()
)


def _plz_orte(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in re.finditer(
        r"(?<![\d.])\d{5}(?![\d])\s+([A-ZÄÖÜ][a-zäöüß]+(?:[-][A-ZÄÖÜ][a-zäöüß]+){0,2})",
        text,
    ):
        ort = m.group(1)
        if ort.lower() in _ORT_STOPWORDS:
            continue
        out.append(Finding("PLZ_ORT", m.start(), m.end(), LIKELY, m.group(0)))
    return out


_GEB_KEYWORD = r"(?:geb(?:oren|urtsdatum)?\.?|dob)"

def _geburtsdaten(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in re.finditer(
        _GEB_KEYWORD + r"[\s:.\-]*(?:am\s+|um\s+)?(\d{1,2})\.(\d{1,2})\.(\d{4}|\d{2})",
        text,
        re.IGNORECASE,
    ):
        day, month = int(m.group(1)), int(m.group(2))
        year = int(m.group(3))
        if 1 <= day <= 31 and 1 <= month <= 12 and (1900 <= year <= 2100 or year <= 99):
            out.append(Finding("GEBURTSDATUM", m.start(), m.end(), LIKELY, m.group(0)))
    return out


_TITLE_RE = re.compile(r"\b(?:Herrn|Herr|Frau|Fr\.|Prof\.|Dr\.|Dipl\.-Ing\.)\b\.?,?")
# Whitespace plus any further title tokens ("Frau Dr. …", "Dr. med. habil. …")
_TITLE_CHAIN_RE = re.compile(
    r"\s*(?:(?:Prof\.|Dr\.|med\.|dent\.|habil\.|h\.c\.|rer\.|nat\.|pol\.|Dipl\.-Ing\.)\s+)*"
)
# Name token: capitalized word with optional capitalized hyphenated parts
# ("Meyer-Landrut"). Umlauts and ß included.
_NAME_TOKEN = r"[A-ZÄÖÜ][a-zäöüß]+(?:-[A-ZÄÖÜ][a-zäöüß]+)*"
_NAME_RE = re.compile(
    _NAME_TOKEN
    + r"(?:\s+(?:von|van|de|zu|vom|zur)\s+" + _NAME_TOKEN + r")?"
)


def _person_names(text: str) -> list[Finding]:
    """Title-gated heuristics. Only anchored names are reported.

    „Herr Müller“, „Frau Dr. med. Schmidt“, „Herrn Karl von Beffen“ are
    detected; bare surnames without a title or a known first name are not —
    that keeps false positives low at the cost of recall, which
    references/entities.md documents up front.
    """
    out: list[Finding] = []
    for title in _TITLE_RE.finditer(text):
        tail = _TITLE_CHAIN_RE.match(text, title.end())
        name = _NAME_RE.match(text, tail.end())
        if name:
            out.append(
                Finding(
                    "PERSON_NAME_DE",
                    name.start(),
                    name.end(),
                    LIKELY,
                    name.group(0),
                )
            )
    return out


_FIRST_NAMES = frozenset(
    """anna lukas max emma hannah sophia mia elias paul noah leon henry finn
    jonas felix louis julia marie laura lena lea anna-lena lisa sarah julian
    ben jakob erik niklas tim david moritz fabian simon florian jan philipp
    tobias matthias daniel michael andreas stefan christoph martin klaus
    thomas frank jens mario markus alexander sebastian christina sabine
    petra claudia nicole andrea karin ute monika susanne brigitte ulrike
    gabriele renate sabrina dennis kevin justin marcel torsten olaf ralf
    jens katrin anja nadine franziska johanna theresa charlotte elisabeth
    margarete ines ruth marlene violetta""".split()
)


def _first_name_pairs(text: str) -> list[Finding]:
    out: list[Finding] = []
    for name in _FIRST_NAMES:
        for m in re.finditer(
            r"\b(" + name.capitalize() + r")\s+(" + _NAME_TOKEN + r")\b", text
        ):
            # "Max Mustermann" style pairs only; surname capitalized.
            start = m.start(1)
            out.append(Finding("PERSON_NAME_DE", start, m.end(), WEAK, m.group(0)))
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def find_pii(
    text: str,
    *,
    include_weak: bool = False,
    names: bool = True,
) -> list[Finding]:
    """Find German PII spans in ``text``.

    Returns de-overlapped findings sorted by position. ``include_weak`` also
    reports format-only entity types (PERSONALAUSWEIS, first-name pairs);
    ``names`` toggles the PERSON_NAME_DE heuristics in general.
    """
    detectors = [
        _compact_ibans,
        _steuer_ids,
        _kvnrs,
        _svnrs,
        _kreditkarten,
        _emails,
        _phones,
        _street_addresses,
        _plz_orte,
        _geburtsdaten,
    ]
    if names:
        detectors.append(_person_names)
    if include_weak:
        detectors.append(_personalausweise)
        if names:
            detectors.append(_first_name_pairs)

    findings: list[Finding] = []
    for detector in detectors:
        findings.extend(detector(text))

    # De-overlap: higher confidence wins, then the earlier match.
    findings.sort(key=lambda f: (-_CONFIDENCE_RANK[f.confidence], f.start, f.end))
    kept: list[Finding] = []
    for finding in findings:
        if any(f.start < finding.end and finding.start < f.end for f in kept):
            continue
        kept.append(finding)
    kept.sort(key=lambda f: (f.start, f.end))
    return kept


def scan_text(
    text: str,
    *,
    include_weak: bool = False,
    names: bool = True,
    with_content: bool = False,
) -> list[dict]:
    """Findings as plain dicts, optionally without the matched raw text."""
    results = []
    for f in find_pii(text, include_weak=include_weak, names=names):
        entry = f.to_dict()
        if not with_content:
            entry["text"] = f"{f.end - f.start} chars"
        results.append(entry)
    return results
