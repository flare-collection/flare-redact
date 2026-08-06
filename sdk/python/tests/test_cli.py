"""The command line behaves like the JavaScript one, exit codes included."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from flare_redact.cli import main


def _run(argv, stdin: str = "") -> "tuple[int, str, str]":
    out, err = io.StringIO(), io.StringIO()
    import sys

    original_stdin = sys.stdin
    sys.stdin = io.StringIO(stdin)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
    finally:
        sys.stdin = original_stdin
    return code, out.getvalue(), err.getvalue()


class CliTest(unittest.TestCase):
    def test_redacts_stdin(self) -> None:
        code, out, _ = _run([], "mail ada@example.com\n")
        self.assertEqual(code, 0)
        self.assertEqual(out, "mail a***@***\n")

    def test_scan_exits_one_when_something_is_found(self) -> None:
        code, out, _ = _run(["--scan"], "ada@example.com")
        self.assertEqual(code, 1)
        self.assertIn("Email address", out)

    def test_scan_exits_zero_when_clean(self) -> None:
        code, out, _ = _run(["--scan"], "nothing here")
        self.assertEqual(code, 0)
        self.assertIn("No secrets found.", out)

    def test_json_report(self) -> None:
        code, out, _ = _run(["--scan", "--format", "json"], "ada@example.com")
        report = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(report["summary"]["total"], 1)
        self.assertEqual(report["tool"]["runtime"], "python")
        self.assertNotIn("value", report["findings"][0])

    def test_sarif_report(self) -> None:
        code, out, _ = _run(["--sarif"], "ada@example.com")
        report = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(report["version"], "2.1.0")
        self.assertEqual(report["runs"][0]["results"][0]["ruleId"], "email")

    def test_json_mode_redacts_recursively(self) -> None:
        code, out, _ = _run(["--json", "--mode", "label"], '{"user":{"email":"ada@example.com"}}')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), {"user": {"email": "[REDACTED:email]"}})

    def test_invalid_json_is_reported(self) -> None:
        code, _, err = _run(["--json"], "{not json")
        self.assertEqual(code, 2)
        self.assertIn("invalid JSON", err)

    def test_summary(self) -> None:
        code, out, _ = _run(["--summary"], "ada@example.com")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["total"], 1)

    def test_list_detectors(self) -> None:
        code, out, _ = _run(["--list"])
        self.assertEqual(code, 0)
        self.assertIn("email", out)

    def test_reads_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "app.log")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("mail ada@example.com")
            code, out, _ = _run(["--scan", "--format", "json", path])
            report = json.loads(out)
            self.assertEqual(code, 1)
            self.assertEqual(report["findings"][0]["file"], path)

    def test_terms_and_allow(self) -> None:
        code, out, _ = _run(["--term", "Bluebird", "--allow", "ada@example.com"], "Bluebird ada@example.com")
        self.assertEqual(code, 0)
        self.assertEqual(out, "*** ada@example.com")

    def test_missing_file_exits_two(self) -> None:
        code, _, err = _run(["/nonexistent/flare-redact-test"])
        self.assertEqual(code, 2)
        self.assertTrue(err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
