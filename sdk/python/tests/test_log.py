"""Logging integration: nothing sensitive should reach a handler."""

from __future__ import annotations

import dataclasses
import io
import logging
import unittest

from flare_redact.log import RedactingFilter, RedactingFormatter, install


def _logger(name: str) -> "tuple[logging.Logger, io.StringIO, logging.Handler]":
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = logging.getLogger(name)
    logger.handlers = []
    logger.filters = []
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    return logger, stream, handler


class RedactingFilterTest(unittest.TestCase):
    def test_redacts_the_message(self) -> None:
        logger, stream, _ = _logger("flare.filter.message")
        logger.addFilter(RedactingFilter())
        logger.info("user ada@example.com signed in")
        self.assertEqual(stream.getvalue().strip(), "user a***@*** signed in")

    def test_redacts_lazy_format_arguments(self) -> None:
        logger, stream, _ = _logger("flare.filter.args")
        logger.addFilter(RedactingFilter())
        logger.warning("token for %s is %s", "ada@example.com", "ghp_1234567890abcdefghijklmnopqrstuvwxyz")
        output = stream.getvalue()
        self.assertIn("a***@***", output)
        self.assertNotIn("ghp_1234567890", output)

    def test_redacts_structured_payloads(self) -> None:
        logger, stream, _ = _logger("flare.filter.structured")
        logger.addFilter(RedactingFilter())
        logger.info({"email": "ada@example.com"})
        self.assertIn("a***@***", stream.getvalue())

    def test_redacts_named_extra_attributes(self) -> None:
        logger, stream, handler = _logger("flare.filter.extra")
        handler.setFormatter(logging.Formatter("%(message)s %(context)s"))
        logger.addFilter(RedactingFilter(extra_attributes=["context"]))
        logger.info("event", extra={"context": {"email": "ada@example.com"}})
        self.assertIn("a***@***", stream.getvalue())

    def test_redacts_objects_that_become_text_when_formatted(self) -> None:
        dsn = "postgres://admin:s3cr3tPassw0rd@db.internal:5432/app"

        @dataclasses.dataclass
        class Config:
            name: str
            password: str
            dsn: str

        class Target:
            def __str__(self) -> str:
                return "target " + dsn

        logger, stream, _ = _logger("flare.filter.objects")
        logger.addFilter(RedactingFilter())
        error = RuntimeError("db down: " + dsn)
        logger.error("cfg %s", Config("api", "hunter2", dsn))
        logger.error("target %s rows %s", Target(), [{"dsn": dsn}])
        logger.error("raw %s", b"key AKIAIOSFODNN7EXAMPLE")
        logger.error("err %s", error)
        logger.error(error)
        logger.error(Target())
        logger.error("mismatch %s %s", Config("api", "hunter2", dsn))
        output = stream.getvalue()
        for secret in ("s3cr3tPassw0rd", "AKIAIOSFODNN7EXAMPLE"):
            self.assertNotIn(secret, output)
        for kept in ("Config(name='api'", "target postgres://admin:***@db.internal", "AKIA***", "mismatch %s %s ("):
            self.assertIn(kept, output)

    def test_keeps_the_template_when_every_argument_is_plain(self) -> None:
        logger, _, _ = _logger("flare.filter.template")
        records: "list[logging.LogRecord]" = []
        logger.addFilter(RedactingFilter())
        logger.addFilter(lambda record: records.append(record) or True)
        logger.info("user %s has %d items", "ada@example.com", 3)
        self.assertEqual(records[0].msg, "user %s has %d items")
        self.assertEqual(records[0].args, ("a***@***", 3))

    def test_the_record_still_gets_logged(self) -> None:
        logger, stream, _ = _logger("flare.filter.passthrough")
        logger.addFilter(RedactingFilter())
        logger.info("nothing sensitive")
        self.assertEqual(stream.getvalue().strip(), "nothing sensitive")


class RedactingFormatterTest(unittest.TestCase):
    def test_redacts_a_traceback(self) -> None:
        logger, stream, handler = _logger("flare.formatter.traceback")
        handler.setFormatter(RedactingFormatter(logging.Formatter("%(message)s")))
        try:
            raise ValueError("bad token ghp_1234567890abcdefghijklmnopqrstuvwxyz")
        except ValueError:
            logger.exception("request failed")
        output = stream.getvalue()
        self.assertIn("request failed", output)
        self.assertIn("ghp_***", output)
        self.assertNotIn("ghp_1234567890abcdefghijklmnopqrstuvwxyz", output)


class InstallTest(unittest.TestCase):
    def test_installs_a_filter_and_wraps_formatters(self) -> None:
        logger, stream, handler = _logger("flare.install")
        added = install(logger)
        self.assertIn(added, logger.filters)
        self.assertIsInstance(handler.formatter, RedactingFormatter)
        logger.info("mail ada@example.com")
        self.assertIn("a***@***", stream.getvalue())

    def test_is_idempotent_for_formatters(self) -> None:
        logger, _, handler = _logger("flare.install.twice")
        install(logger)
        first = handler.formatter
        install(logger)
        self.assertIs(handler.formatter, first)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
