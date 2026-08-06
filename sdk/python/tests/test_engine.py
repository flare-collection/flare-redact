"""Behaviour of the core engine that the conformance corpus does not pin down."""

from __future__ import annotations

import re
import unittest

import flare_redact as fr
from flare_redact.engine import Options


class RedactTest(unittest.TestCase):
    def test_returns_input_unchanged_when_nothing_matches(self) -> None:
        text = "nothing sensitive here"
        self.assertIs(fr.redact(text), text)

    def test_preserves_structure_and_scalars(self) -> None:
        source = {"n": 1, "f": 1.5, "b": True, "none": None, "s": "ada@example.com"}
        result = fr.redact(source)
        self.assertEqual(result["n"], 1)
        self.assertIs(result["b"], True)
        self.assertIsNone(result["none"])
        self.assertEqual(result["s"], "a***@***")

    def test_does_not_mutate_the_input(self) -> None:
        source = {"email": "ada@example.com"}
        fr.redact(source)
        self.assertEqual(source, {"email": "ada@example.com"})

    def test_survives_a_cycle(self) -> None:
        node: dict = {"email": "ada@example.com"}
        node["self"] = node
        result = fr.redact(node)
        self.assertEqual(result["email"], "a***@***")
        self.assertIs(result["self"], result)

    def test_shared_references_stay_shared(self) -> None:
        shared = {"email": "ada@example.com"}
        result = fr.redact({"a": shared, "b": shared})
        self.assertIs(result["a"], result["b"])

    def test_redacts_exception_messages(self) -> None:
        result = fr.redact(ValueError("token ghp_1234567890abcdefghijklmnopqrstuvwxyz rejected"))
        self.assertIsInstance(result, ValueError)
        self.assertEqual(str(result), "token ghp_***" + " rejected")

    def test_tuple_and_set_containers(self) -> None:
        self.assertEqual(fr.redact(("ada@example.com",)), ("a***@***",))
        self.assertEqual(fr.redact({"ada@example.com"}), {"a***@***"})

    def test_callable_mask_receives_value_and_detector(self) -> None:
        seen = []

        def mask(value: str, detector) -> str:
            seen.append((value, detector.id))
            return f"<{detector.id}>"

        self.assertEqual(fr.redact("ada@example.com", mask=mask), "<email>")
        self.assertEqual(seen, [("ada@example.com", "email")])

    def test_allow_accepts_a_compiled_pattern(self) -> None:
        options = Options(allow=re.compile(r"@example\.com$"))
        self.assertEqual(fr.redact("ada@example.com", options), "ada@example.com")

    def test_redact_keys_accepts_an_explicit_list(self) -> None:
        result = fr.redact({"custom": "value", "password": "hunter2"}, redact_keys=["custom"])
        self.assertEqual(result, {"custom": "***", "password": "hunter2"})

    def test_unknown_mode_is_rejected(self) -> None:
        with self.assertRaises(fr.FlareRedactError):
            fr.redact("x", mode="encrypt")

    def test_fpe_is_accepted_as_a_pseudonym_alias(self) -> None:
        keyed = {"transform_secret": "k"}
        self.assertEqual(
            fr.redact("ada@example.com", mode="fpe", **keyed),
            fr.redact("ada@example.com", mode="pseudonym", **keyed),
        )

    def test_keyed_modes_require_a_secret(self) -> None:
        with self.assertRaises(ValueError):
            fr.redact("ada@example.com", mode="hash")


class ScanTest(unittest.TestCase):
    def test_reports_line_and_column(self) -> None:
        findings = fr.scan("first line\nsecond has ada@example.com here")
        self.assertEqual(len(findings), 1)
        self.assertEqual((findings[0].line, findings[0].column), (2, 12))

    def test_omits_values_by_default(self) -> None:
        self.assertIsNone(fr.scan("ada@example.com")[0].value)
        self.assertEqual(fr.scan("ada@example.com", include_values=True)[0].value, "ada@example.com")

    def test_summary_counts_by_detector_and_risk(self) -> None:
        result = fr.summary("ada@example.com and AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(result["total"], 2)
        self.assertEqual(result["by_detector"]["email"], 1)
        self.assertEqual(result["by_risk"]["critical"], 1)

    def test_is_clean(self) -> None:
        self.assertTrue(fr.is_clean("nothing here"))
        self.assertFalse(fr.is_clean("ada@example.com"))


class LimitTest(unittest.TestCase):
    def test_oversized_input_fails_closed(self) -> None:
        with self.assertRaises(fr.RedactionLimitError):
            fr.redact("x" * 100, max_input_length=10)

    def test_too_many_findings_fails_closed(self) -> None:
        text = " ".join(["ada@example.com"] * 50)
        with self.assertRaises(fr.RedactionLimitError):
            fr.redact(text, max_findings=5)


class PolicyTest(unittest.TestCase):
    def test_one_policy_is_reusable(self) -> None:
        policy = fr.compile_policy(enable=["pii"], mode="label")
        self.assertEqual(policy.redact_str("ada@example.com"), "[REDACTED:email]")
        self.assertEqual(policy.redact({"e": "ada@example.com"}), {"e": "[REDACTED:email]"})
        self.assertEqual(policy.summary("ada@example.com")["total"], 1)

    def test_policy_exposes_vault_and_session(self) -> None:
        policy = fr.compile_policy()
        self.assertIsInstance(policy.vault(), fr.Vault)
        self.assertIsInstance(policy.session(), fr.Session)


class OverlapTest(unittest.TestCase):
    def test_higher_risk_span_wins(self) -> None:
        # The whole assignment is critical; the bare token inside it is too, but
        # the assignment covers more ground, so it is the one that survives.
        self.assertEqual(
            fr.redact("api_key=ghp_1234567890abcdefghijklmnopqrstuvwxyz"),
            "api_key=***",
        )

    def test_adjacent_matches_both_survive(self) -> None:
        self.assertEqual(
            fr.redact("ada@example.com grace@example.org"),
            "a***@*** g***@***",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
