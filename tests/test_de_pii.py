"""Tests for the German PII detection core (de_pii.py).

All identifiers in this file are synthetic: checksum-valid where a checksum
exists, but random content — no real accounts, no real people.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills" / "presidio-de" / "scripts"))

import de_pii  # noqa: E402


class ChecksumAlgorithms(unittest.TestCase):
    def test_iban_valid(self):
        self.assertTrue(de_pii.iban_is_valid("DE89370400440532013000"))

    def test_iban_invalid_checksum(self):
        self.assertFalse(de_pii.iban_is_valid("DE88370400440532013000"))

    def test_iban_spaced_equals_compact(self):
        findings = de_pii.find_pii("IBAN: DE89 3704 0044 0532 0130 00")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "IBAN")
        self.assertEqual(findings[0].confidence, de_pii.CONFIRMED)
        self.assertEqual(findings[0].text, "DE89 3704 0044 0532 0130 00")

    def test_iban_uppercase_word_not_flagged(self):
        # A random uppercase alnum blob must not pass mod-97.
        self.assertEqual(de_pii.find_pii("Code ABCD1234EFGH5678IJ"), [])

    def test_iso7064_known_vectors(self):
        # Check digits computed with an independent implementation.
        self.assertTrue(de_pii.iso7064_mod1110_check("02538413968"))
        self.assertTrue(de_pii.iso7064_mod1110_check("65929994533"))
        self.assertFalse(de_pii.iso7064_mod1110_check("02538413969"))

    def test_steuer_id_confirmed_with_bundesland(self):
        findings = de_pii.find_pii("Steuer-ID: 02538413968")
        self.assertEqual([(f.type, f.confidence) for f in findings],
                         [("STEUER_ID", "confirmed")])

    def test_steuer_id_invalid_not_detected(self):
        self.assertEqual(de_pii.find_pii("Steuer-ID: 02538413969"), [])

    def test_steuer_id_embedded_in_longer_digits_not_detected(self):
        self.assertEqual(de_pii.find_pii("Bestellnr 1025384139681"), [])

    def test_kvnr_confirmed(self):
        findings = de_pii.find_pii("Versichertennr.: K127508150")
        self.assertEqual(findings[0].type, "KVNR")
        self.assertEqual(findings[0].confidence, "confirmed")

    def test_kvnr_excluded_letter_downgraded(self):
        # 'I' is not issued (confusable); checksum still valid -> likely.
        findings = de_pii.find_pii("KVNR: I127508151")
        self.assertEqual(findings[0].confidence, "likely")

    def test_kvnr_invalid_not_detected(self):
        self.assertEqual(de_pii.find_pii("KVNR: K127508151"), [])

    def test_luhn(self):
        self.assertTrue(de_pii.luhn_is_valid("4111111111111111"))
        self.assertFalse(de_pii.luhn_is_valid("4111111111111112"))


class LikelyEntities(unittest.TestCase):
    def test_svnr_plausible(self):
        findings = de_pii.find_pii("SVNR: 12750815A123")
        self.assertEqual(findings[0].type, "SVNR")
        self.assertEqual(findings[0].confidence, "likely")

    def test_svnr_implausible_month_not_detected(self):
        self.assertEqual(de_pii.find_pii("SVNR: 12759915A123"), [])

    def test_phone_international_with_trunk_zero(self):
        findings = de_pii.find_pii("Tel. +49 (0)30 12345678")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].text, "+49 (0)30 12345678")

    def test_phone_national(self):
        findings = de_pii.find_pii("Mobil: 0170 1234567")
        self.assertEqual(findings[0].type, "PHONE_DE")

    def test_street_compound(self):
        findings = de_pii.find_pii("Wohnhaft: Marienstraße 12")
        self.assertEqual(findings[0].type, "STREET_ADDRESS")
        self.assertEqual(findings[0].text, "Marienstraße 12")

    def test_street_abbreviated(self):
        findings = de_pii.find_pii("Hauptstr. 5a")
        self.assertEqual(findings[0].type, "STREET_ADDRESS")
        self.assertEqual(findings[0].text, "Hauptstr. 5a")

    def test_street_separated(self):
        findings = de_pii.find_pii("Am Markt 4")
        self.assertEqual(findings[0].type, "STREET_ADDRESS")
        self.assertEqual(findings[0].text, "Am Markt 4")

    def test_plz_ort(self):
        findings = de_pii.find_pii("10117 Berlin")
        self.assertEqual(findings[0].type, "PLZ_ORT")

    def test_plz_ort_stoplist_not_detected(self):
        self.assertEqual(de_pii.find_pii("Der Text hat 12345 Zeichen"), [])

    def test_geburtsdatum_keyword_gated(self):
        findings = de_pii.find_pii("Geburtsdatum: 15.08.1975")
        self.assertEqual(findings[0].type, "GEBURTSDATUM")

    def test_geburtsdatum_geb_am(self):
        findings = de_pii.find_pii("geb. am 03.12.1980")
        self.assertEqual(len(findings), 1)

    def test_date_without_keyword_not_detected(self):
        self.assertEqual(de_pii.find_pii("Erstellt am 15.08.1975"), [])

    def test_person_name_title_gated(self):
        findings = de_pii.find_pii("Sehr geehrte Frau Müller")
        self.assertEqual(findings[0].type, "PERSON_NAME_DE")
        self.assertEqual(findings[0].text, "Müller")

    def test_person_name_chained_titles(self):
        findings = de_pii.find_pii("Herr Prof. Dr. med. Weber ist im Urlaub")
        self.assertEqual(findings[0].text, "Weber")

    def test_person_name_particle(self):
        findings = de_pii.find_pii("Herr Karl von Beffen schreibt:")
        self.assertEqual(findings[0].text, "Karl von Beffen")

    def test_bare_surname_not_detected(self):
        self.assertEqual(de_pii.find_pii("Wir haben Müller angerufen"), [])


class WeakEntities(unittest.TestCase):
    def test_first_name_pair_opt_in(self):
        text = "Max Mustermann wohnt hier"
        self.assertEqual(de_pii.find_pii(text), [])
        findings = de_pii.find_pii(text, include_weak=True)
        self.assertEqual(findings[0].confidence, "weak")

    def test_personalausweis_opt_in(self):
        text = "Ausweis: L01X00T471"
        self.assertEqual(de_pii.find_pii(text), [])
        findings = de_pii.find_pii(text, include_weak=True)
        self.assertEqual(findings[0].type, "PERSONALAUSWEIS")

    def test_names_disabled(self):
        text = "Sehr geehrte Frau Müller"
        self.assertEqual(de_pii.find_pii(text, names=False), [])


class OverlapAndOrdering(unittest.TestCase):
    def test_de_overlap_prefers_confirmed(self):
        # An IBAN contains digit runs; the IBAN wins, no inner duplicates.
        text = "IBAN DE89 3704 0044 0532 0130 00 bitte prüfen"
        findings = de_pii.find_pii(text)
        self.assertEqual([f.type for f in findings], ["IBAN"])

    def test_sorted_by_position(self):
        text = (
            "max.mustermann@example.org schreibt, IBAN DE89370400440532013000, "
            "Tel. 030 12345678"
        )
        findings = de_pii.find_pii(text)
        positions = [f.start for f in findings]
        self.assertEqual(positions, sorted(positions))

    def test_deterministic(self):
        text = "K127508150, 02538413968, DE89370400440532013000"
        first = de_pii.find_pii(text)
        second = de_pii.find_pii(text)
        self.assertEqual(first, second)


class FalsePositiveHygiene(unittest.TestCase):
    def test_neutral_text_is_clean(self):
        text = (
            "Der Bericht umfasst 12345 Zeichen und wurde am 15.03.2024 erstellt.\n"
            "Kapitel 3 beschreibt den Prozess. Rechnungsnr 2024-0417, Betrag 98765 Euro.\n"
            "Die Gruppe B2D4 trifft sich um 10 Uhr. Projektnummer 4711 ist abgeschlossen.\n"
            "Version 2.4.0 wurde veröffentlicht. Bestellmenge: 300 Stück.\n"
        )
        self.assertEqual(de_pii.find_pii(text, include_weak=True), [])

    def test_credit_card_luhn_gated(self):
        self.assertEqual(de_pii.find_pii("4111 1111 1111 1112"), [])
        findings = de_pii.find_pii("Visa 4111 1111 1111 1111")
        self.assertEqual(findings[0].type, "KREDITKARTE")


if __name__ == "__main__":
    unittest.main()
