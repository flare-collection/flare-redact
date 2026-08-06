"""Reversible redaction: placeholders, restoration and streaming."""

from __future__ import annotations

import unittest

import flare_redact as fr


class VaultTest(unittest.TestCase):
    def test_round_trip(self) -> None:
        vault = fr.create_vault()
        redacted = vault.redact("write to ada@example.com today")
        self.assertNotIn("ada@example.com", redacted)
        self.assertEqual(vault.restore(redacted), "write to ada@example.com today")

    def test_same_value_gets_the_same_placeholder(self) -> None:
        vault = fr.create_vault()
        redacted = vault.redact("ada@example.com and ada@example.com")
        placeholders = set(redacted.replace(" and ", " ").split())
        self.assertEqual(len(placeholders), 1)
        self.assertEqual(len(vault), 1)

    def test_opaque_placeholders_carry_no_counter(self) -> None:
        first = fr.create_vault().redact("ada@example.com")
        second = fr.create_vault().redact("ada@example.com")
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("[FR_EMAIL_"))

    def test_readable_placeholders_are_numbered(self) -> None:
        vault = fr.create_vault(placeholder_style="readable")
        self.assertEqual(vault.redact("ada@example.com"), "[EMAIL_1]")

    def test_custom_placeholder_generator(self) -> None:
        vault = fr.create_vault(placeholder=lambda detector, index: f"<<{detector}:{index}>>")
        self.assertEqual(vault.redact("ada@example.com"), "<<email:1>>")

    def test_duplicate_placeholders_are_rejected(self) -> None:
        vault = fr.create_vault(placeholder=lambda _detector, _index: "[SAME]")
        with self.assertRaises(ValueError):
            vault.redact("ada@example.com and grace@example.org")

    def test_restores_structures(self) -> None:
        vault = fr.create_vault()
        redacted = vault.redact({"to": ["ada@example.com"], "password": "hunter2"})
        self.assertEqual(
            vault.restore(redacted),
            {"to": ["ada@example.com"], "password": "hunter2"},
        )

    def test_module_level_restore_accepts_a_mapping(self) -> None:
        self.assertEqual(fr.restore("hello [X]", {"[X]": "world"}), "hello world")

    def test_longer_placeholders_win(self) -> None:
        restore = fr.build_restore([("[A]", "short"), ("[AB]", "long")])
        self.assertEqual(restore("[AB] [A]"), "long short")


class SessionTest(unittest.TestCase):
    def test_placeholders_are_stable_across_turns(self) -> None:
        session = fr.create_session(placeholder_style="readable")
        first = session.redact("my email is ada@example.com")
        second = session.redact("send it to ada@example.com again")
        self.assertIn("[EMAIL_1]", first)
        self.assertIn("[EMAIL_1]", second)

    def test_reset_starts_a_new_conversation(self) -> None:
        session = fr.create_session()
        session.redact("ada@example.com")
        self.assertEqual(len(session), 1)
        session.reset()
        self.assertEqual(len(session), 0)

    def test_redact_messages(self) -> None:
        session = fr.create_session(placeholder_style="readable")
        messages = session.redact_messages([
            {"role": "user", "content": "mail ada@example.com"},
        ])
        self.assertEqual(messages[0]["content"], "mail [EMAIL_1]")


class StreamRestoreTest(unittest.TestCase):
    def test_restores_a_placeholder_split_across_chunks(self) -> None:
        session = fr.create_session(placeholder_style="readable")
        session.redact("ada@example.com")
        restorer = session.stream()
        out = restorer.push("reply to [EMA")
        out += restorer.push("IL_1] soon")
        out += restorer.flush()
        self.assertEqual(out, "reply to ada@example.com soon")

    def test_emits_text_that_cannot_be_a_placeholder_immediately(self) -> None:
        session = fr.create_session(placeholder_style="readable")
        session.redact("ada@example.com")
        restorer = session.stream()
        self.assertEqual(restorer.push("hello there"), "hello there")

    def test_flush_is_idempotent(self) -> None:
        restorer = fr.create_vault().stream()
        self.assertEqual(restorer.push("plain"), "plain")
        self.assertEqual(restorer.flush(), "")
        self.assertEqual(restorer.flush(), "")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
