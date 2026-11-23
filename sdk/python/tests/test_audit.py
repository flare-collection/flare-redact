"""Shadow mode: count what a policy would redact, never keeping a matched value."""

from __future__ import annotations

import io
import json
import logging
import unittest

from flare_redact.audit import Audit, AuditFilter

TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


class AuditTests(unittest.TestCase):
    def test_observe_counts_and_returns_unchanged(self):
        audit = Audit()
        event = {"users": [{"email": "ada@example.com"}, {"email": "bob@example.com"}], "password": "x", "ok": True}
        self.assertIs(audit.observe(event, "webhook"), event)
        audit.observe(f"key {TOKEN}", "cli")
        audit.observe("nothing here", "cli")
        r = audit.report()
        self.assertEqual((r["scanned"], r["with_findings"], r["total"]), (3, 2, 4))
        self.assertEqual(r["by_detector"], {"email": 2, "github_token": 1, "sensitive_key": 1})
        self.assertEqual(r["by_path"], {"users[].email": 2, "password": 1})
        self.assertEqual(r["by_source"]["cli"], {"scanned": 2, "total": 1, "by_detector": {"github_token": 1}})
        text = json.dumps(r) + audit.format()
        for value in ("ada@example.com", "bob@example.com", TOKEN):
            self.assertNotIn(value, text)
        self.assertTrue(audit.format().startswith("4 findings in 2 of 3 values (66.7%) since "))

    def test_risk_counts(self):
        # Two emails are high risk; a value under a password field is critical.
        audit = Audit()
        audit.observe({"users": [{"email": "ada@example.com"}, {"email": "bob@example.com"}], "password": "x"}, "w")
        self.assertEqual(audit.report()["by_risk"], {"critical": 1, "high": 2})

    def test_redact_values_never_kept_and_meter(self):
        seen, adds = [], {}

        class Counter:
            def __init__(self, name):
                self.name = name

            def add(self, n, attrs):
                adds.setdefault(self.name, []).append((n, attrs))

        class Meter:
            def create_counter(self, name, **_):
                return Counter(name)

        audit = Audit(include_values=True, meter=Meter(), on_finding=seen.append)
        self.assertEqual(audit.redact({"note": f"key {TOKEN}"}, "job"), {"note": "key ghp_***"})
        self.assertEqual(seen, [{"detector": "github_token", "risk": "critical", "source": "job", "path": "note"}])
        self.assertEqual(adds["flare_redact.findings"], [(1, {"detector": "github_token", "risk": "critical", "source": "job"})])
        self.assertEqual(adds["flare_redact.scanned"], [(1, {"source": "job"})])
        self.assertNotIn(TOKEN, json.dumps(audit.report()))
        audit.reset()
        self.assertEqual(audit.report()["total"], 0)

    def test_paths_are_capped(self):
        audit = Audit(max_paths=2)
        audit.observe({"a": "ada@example.com", "b": "ada@example.com", "c": "ada@example.com", "d": "ada@example.com"})
        self.assertEqual(audit.report()["by_path"], {"(other)": 2, "a": 1, "b": 1})


class AuditFilterTests(unittest.TestCase):
    def _logger(self, name, flt):
        stream = io.StringIO()
        logger = logging.getLogger(name)
        logger.handlers[:] = [logging.StreamHandler(stream)]
        logger.propagate = False
        logger.addFilter(flt)
        return logger, stream

    def test_shadow_leaves_records_alone(self):
        flt = AuditFilter()
        logger, stream = self._logger("svc.shadow", flt)
        logger.warning("login %s", "ada@example.com")
        self.assertIn("ada@example.com", stream.getvalue())
        self.assertEqual(flt.audit.report()["by_source"]["svc.shadow"]["by_detector"], {"email": 1})

    def test_enforce_redacts_and_counts(self):
        flt = AuditFilter(enforce=True)
        logger, stream = self._logger("svc.enforce", flt)
        logger.warning("login %s", "ada@example.com")
        self.assertIn("a***@***", stream.getvalue())
        self.assertNotIn("ada@example.com", stream.getvalue())
        self.assertEqual(flt.audit.report()["total"], 1)


if __name__ == "__main__":
    unittest.main()
