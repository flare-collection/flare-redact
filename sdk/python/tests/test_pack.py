"""Packs are data, and a pack this engine cannot execute exactly must not load."""

from __future__ import annotations

import copy
import json
import unittest

import flare_redact as fr
from flare_redact.pack import PackError, load_pack

_MINIMAL = {
    "spec": "FRS-1",
    "id": "test/pack",
    "version": "1",
    "detectors": [
        {
            "id": "ticket",
            "label": "Ticket id",
            "why": "Internal ticket identifiers are not for third parties.",
            "pattern": "TICKET-[0-9]{4,8}",
            "boundary": {"before": "word", "after": "word"},
            "mask": {"type": "fixed", "text": "[TICKET]"},
            "default": True,
            "risk": "medium",
            "confidence": 0.9,
        }
    ],
}


def _with_detector(**overrides):
    document = copy.deepcopy(_MINIMAL)
    document["detectors"][0].update(overrides)
    return document


class PackLoadingTest(unittest.TestCase):
    def test_loads_a_custom_pack(self) -> None:
        pack = load_pack(_MINIMAL)
        self.assertEqual(pack.id, "test/pack")
        self.assertEqual(fr.redact("see TICKET-12345 please", pack=pack), "see [TICKET] please")

    def test_accepts_a_json_string(self) -> None:
        self.assertEqual(load_pack(json.dumps(_MINIMAL)).id, "test/pack")

    def test_rejects_an_unknown_revision(self) -> None:
        document = copy.deepcopy(_MINIMAL)
        document["spec"] = "FRS-2"
        with self.assertRaises(PackError):
            load_pack(document)

    def test_rejects_lookahead(self) -> None:
        with self.assertRaises(PackError):
            load_pack(_with_detector(pattern="TICKET-(?!0)[0-9]{4}"))

    def test_rejects_shorthand_classes(self) -> None:
        for pattern in (r"TICKET-\d{4}", r"\bTICKET-[0-9]{4}", r"TICKET-\w{4}"):
            with self.subTest(pattern=pattern), self.assertRaises(PackError):
                load_pack(_with_detector(pattern=pattern))

    def test_rejects_anchors(self) -> None:
        with self.assertRaises(PackError):
            load_pack(_with_detector(pattern="^TICKET-[0-9]{4}"))

    def test_rejects_an_empty_match(self) -> None:
        with self.assertRaises(PackError):
            load_pack(_with_detector(pattern="[0-9]*"))

    def test_rejects_an_unknown_validator(self) -> None:
        with self.assertRaises(PackError):
            load_pack(_with_detector(validators=[{"name": "not_a_real_checksum"}]))

    def test_rejects_an_unknown_mask(self) -> None:
        with self.assertRaises(PackError):
            load_pack(_with_detector(mask={"type": "encrypt"}))

    def test_rejects_an_unknown_boundary_class(self) -> None:
        with self.assertRaises(PackError):
            load_pack(_with_detector(boundary={"before": "vowel"}))

    def test_rejects_duplicate_detector_ids(self) -> None:
        document = copy.deepcopy(_MINIMAL)
        document["detectors"].append(copy.deepcopy(document["detectors"][0]))
        with self.assertRaises(PackError):
            load_pack(document)

    def test_rejects_a_missing_capture_group(self) -> None:
        with self.assertRaises(PackError):
            load_pack(_with_detector(capture=3))


class CorePackTest(unittest.TestCase):
    def test_every_detector_is_addressable(self) -> None:
        pack = fr.core_pack()
        self.assertGreater(len(pack.detectors), 60)
        for detector in pack.detectors:
            with self.subTest(detector=detector.id):
                self.assertTrue(detector.label)
                self.assertTrue(detector.why.endswith("."))
                self.assertIn(detector.risk, ("low", "medium", "high", "critical"))

    def test_tokens_are_expanded_not_literal(self) -> None:
        self.assertNotIn("{{ANY}}", fr.core_pack().by_id["private_key"].regex.pattern)

    def test_prefilters_do_not_hide_matches(self) -> None:
        """A prefilter must be implied by every string its pattern can match."""
        pack = fr.core_pack()
        samples = {
            "private_key": "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----",
            "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
            "bearer_token": "Bearer abcdefghijklmnop",
            "basic_auth": "Basic YWRtaW46aHVudGVyMg==",
            "email": "ada@example.com",
            "aws_secret_key": "aws_secret_access_key = " + "A" * 40,
            "url_credentials": "postgres://u:p@h/d",
        }
        for detector_id, sample in samples.items():
            detector = pack.by_id[detector_id]
            with self.subTest(detector=detector_id):
                lowered = sample.lower()
                self.assertTrue(
                    any(literal in lowered for literal in detector.prefilter),
                    f"{detector_id} prefilter would skip a matching input",
                )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
