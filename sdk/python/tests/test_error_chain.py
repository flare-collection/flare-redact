"""An exception's ``__cause__`` and ``__context__`` are part of the traceback a
logger prints; redaction keeps them, redacted, instead of dropping the real
reason for a failure."""

from __future__ import annotations

import unittest

import flare_redact as fr

SECRET = "bob@example.com"


def raised_from() -> BaseException:
    try:
        try:
            raise ConnectionRefusedError(f"connect refused for {SECRET}")
        except ConnectionRefusedError as cause:
            raise RuntimeError("fetch failed") from cause
    except RuntimeError as error:
        return error


def raised_during() -> BaseException:
    try:
        try:
            raise KeyError(SECRET)
        except KeyError:
            raise ValueError("lookup failed")
    except ValueError as error:
        return error


class ErrorChainTest(unittest.TestCase):
    def test_cause_is_kept_and_redacted(self) -> None:
        error = raised_from()
        out = fr.redact(error)
        self.assertIsInstance(out.__cause__, ConnectionRefusedError)
        self.assertNotIn(SECRET, str(out.__cause__))
        self.assertTrue(out.__suppress_context__)
        self.assertIn(SECRET, str(error.__cause__), "the input is not mutated")

    def test_context_is_kept_and_redacted(self) -> None:
        out = fr.redact(raised_during())
        self.assertIsInstance(out.__context__, KeyError)
        self.assertNotIn(SECRET, str(out.__context__))
        self.assertFalse(out.__suppress_context__)

    def test_a_chain_that_loops_back_terminates(self) -> None:
        first, second = RuntimeError("first"), RuntimeError("second")
        first.__cause__, second.__cause__ = second, first
        out = fr.redact(first)
        self.assertIs(out.__cause__.__cause__, out)

    def test_scan_reports_a_secret_in_the_cause(self) -> None:
        self.assertEqual([finding.path for finding in fr.scan(raised_from())], ["__cause__.args[0]"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
