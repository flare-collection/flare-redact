"""The Python engine must agree with every other FRS-1 engine, case for case."""

from __future__ import annotations

import json
import os
import unittest

from flare_redact.conformance import run_case

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_CORPUS = os.path.join(_REPO_ROOT, "spec", "conformance")


def _load(name: str) -> dict:
    with open(os.path.join(_CORPUS, name), "r", encoding="utf-8") as handle:
        return json.load(handle)


class ConformanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = _load("cases.json")
        cls.expected = _load("expected.json")

    def test_corpus_is_covered(self) -> None:
        names = [case["name"] for case in self.corpus["cases"]]
        self.assertEqual(len(names), len(set(names)), "duplicate case names in cases.json")
        self.assertEqual(
            sorted(names),
            sorted(self.expected),
            "cases.json and expected.json disagree; regenerate with npm run spec:conformance",
        )

    def test_every_case_matches(self) -> None:
        for case in self.corpus["cases"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(run_case(case), self.expected[case["name"]])

    def test_bundled_pack_matches_the_specification(self) -> None:
        with open(os.path.join(_REPO_ROOT, "spec", "detectors.json"), "r", encoding="utf-8") as handle:
            canonical = json.load(handle)
        import flare_redact

        vendored_path = os.path.join(os.path.dirname(flare_redact.__file__), "detectors.json")
        with open(vendored_path, "r", encoding="utf-8") as handle:
            vendored = json.load(handle)
        self.assertEqual(
            canonical,
            vendored,
            "the vendored pack has drifted from spec/detectors.json; run `npm run spec:sync`",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
