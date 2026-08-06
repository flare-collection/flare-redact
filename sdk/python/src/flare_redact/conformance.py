"""Runner for the shared cross-language conformance corpus.

``spec/conformance/cases.json`` holds inputs and options; ``expected.json`` holds
the output every FRS-1 engine must produce for them. This module executes a case
and normalises the result, so the Python test suite and the expectation
generator cannot disagree about what "the answer" means.

    python -m flare_redact.conformance --cases spec/conformance/cases.json --check
    python -m flare_redact.conformance --cases ... --expected ... --write
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Mapping, Sequence

from .engine import Finding, Options, compile_policy
from .vault import Vault
from .wire import options_from_wire

__all__ = ["run_case", "run_corpus", "normalise_finding", "DEFAULT_CHECKS"]

DEFAULT_CHECKS = ("redact", "scan")

#: Confidence is a computed double. Six decimals is far finer than any decision
#: the library makes with the value and coarse enough that four languages'
#: floating-point formatting cannot disagree about the text.
_PRECISION = 6


def normalise_finding(finding: Finding) -> Dict[str, Any]:
    """The corpus view of a finding: location and classification, never prose."""
    out: Dict[str, Any] = {
        "detector": finding.detector,
        "risk": finding.risk,
        "confidence": round(finding.confidence, _PRECISION),
    }
    for name in ("start", "end", "line", "column", "path", "value"):
        value = getattr(finding, name)
        if value is not None:
            out[name] = value
    return out


def run_case(case: Mapping[str, Any]) -> Dict[str, Any]:
    """Execute one corpus case and return its normalised result."""
    options: Options = options_from_wire(case.get("options") or {})
    checks: Sequence[str] = case.get("checks") or DEFAULT_CHECKS
    payload = case["input"]
    result: Dict[str, Any] = {}

    if "redact" in checks:
        result["redact"] = compile_policy(options).redact(payload)
    if "scan" in checks:
        result["findings"] = [normalise_finding(f) for f in compile_policy(options).scan(payload)]
    if "vault" in checks:
        settings = case.get("vault") or {}
        vault = Vault(options, placeholder_style=settings.get("placeholderStyle", "opaque"))
        redacted = vault.redact(payload)
        result["vault"] = {
            "redacted": redacted,
            "restored": vault.restore(redacted),
            "entries": [list(pair) for pair in vault.entries()],
        }
    return result


def run_corpus(corpus: Mapping[str, Any]) -> Dict[str, Any]:
    """Execute every case, keyed by case name."""
    results: Dict[str, Any] = {}
    for case in corpus["cases"]:
        name = case["name"]
        if name in results:
            raise ValueError(f"duplicate conformance case name: {name}")
        results[name] = run_case(case)
    return results


def _diff(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> List[str]:
    problems: List[str] = []
    for name in expected:
        if name not in actual:
            problems.append(f"{name}: missing from this engine's results")
        elif expected[name] != actual[name]:
            problems.append(
                f"{name}:\n    expected {json.dumps(expected[name], ensure_ascii=False, sort_keys=True)}"
                f"\n    actual   {json.dumps(actual[name], ensure_ascii=False, sort_keys=True)}"
            )
    for name in actual:
        if name not in expected:
            problems.append(f"{name}: has no expectation; regenerate expected.json")
    return problems


def main(argv: Sequence[str] | None = None) -> int:  # pragma: no cover - tooling
    parser = argparse.ArgumentParser(prog="flare_redact.conformance")
    parser.add_argument("--cases", required=True, help="path to cases.json")
    parser.add_argument("--expected", help="path to expected.json")
    parser.add_argument("--write", action="store_true", help="write expectations instead of checking them")
    args = parser.parse_args(list(argv) if argv is not None else None)

    with open(args.cases, "r", encoding="utf-8") as handle:
        corpus = json.load(handle)
    results = run_corpus(corpus)

    if args.write:
        target = args.expected or args.cases.replace("cases.json", "expected.json")
        with open(target, "w", encoding="utf-8") as handle:
            json.dump(results, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        sys.stdout.write(f"wrote {len(results)} expectations to {target}\n")
        return 0

    if not args.expected:
        parser.error("--expected is required unless --write is given")
    with open(args.expected, "r", encoding="utf-8") as handle:
        expected = json.load(handle)
    problems = _diff(expected, results)
    if problems:
        sys.stderr.write("\n".join(problems) + "\n")
        sys.stderr.write(f"\n{len(problems)} conformance failure(s)\n")
        return 1
    sys.stdout.write(f"{len(results)} conformance cases passed\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
