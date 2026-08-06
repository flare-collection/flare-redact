"""``flare-redact`` for Python — the same command line, without a Node runtime.

    tail -f app.log | python -m flare_redact
    python -m flare_redact --scan --format json config.env
    python -m flare_redact --json --mode label < event.json

Exit codes match the JavaScript CLI so the two are interchangeable in a pipeline
or a pre-commit hook: ``0`` clean, ``1`` findings present, ``2`` usage or I/O
error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
from .engine import Finding, FlareRedactError, Options, compile_policy
from .pack import core_pack, load_pack

__all__ = ["main"]

_EPILOG = """\
examples:
  tail -f app.log | flare-redact
  flare-redact --scan config.env
  flare-redact --scan --format json .env app.log
  flare-redact --json --mode label < event.json
  flare-redact --enable high_entropy --refine-confidence --min-confidence 0.5 app.log
"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="flare-redact",
        description="Hide secrets and PII before they hit a log.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("files", nargs="*", help="files to process; stdin when omitted")
    parser.add_argument("--scan", action="store_true", help="list what would be redacted, and why")
    parser.add_argument("--format", choices=("pretty", "json", "sarif"), default="pretty", help="scan output format")
    parser.add_argument("--sarif", action="store_true", help="shorthand for --scan --format sarif")
    parser.add_argument("--summary", action="store_true", help="print a count of findings per detector")
    parser.add_argument("--json", dest="json_mode", action="store_true", help="parse input as JSON and redact recursively")
    parser.add_argument("--mode", default="mask", help="mask | label | hash | pseudonym | surrogate")
    parser.add_argument("--secret-env", default="FLARE_REDACT_SECRET", help="env var holding the transform key")
    parser.add_argument("--min-confidence", type=float, default=0.0, help="drop findings below this confidence (0-1)")
    parser.add_argument("--refine-confidence", action="store_true", help="use the learned classifier to refine confidence")
    parser.add_argument("--include-values", action="store_true", help="include raw matched values in --scan output")
    parser.add_argument("--only", help="use only these detectors (comma-separated ids or tags)")
    parser.add_argument("--enable", help="turn on extra detectors")
    parser.add_argument("--disable", help="turn off detectors")
    parser.add_argument("--mask", help="replace every secret with this string")
    parser.add_argument("--allow", help="never redact these exact values (comma-separated)")
    parser.add_argument("--term", action="append", default=[], help="also catch this exact word (repeatable)")
    parser.add_argument("--terms", help="also catch every word in this file, one per line")
    parser.add_argument("--pack", help="load an alternative FRS-1 detector pack")
    parser.add_argument("--list", dest="list_mode", action="store_true", help="show all detectors and exit")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _split(value: Optional[str]) -> Optional[List[str]]:
    if not value:
        return None
    items = [item.strip() for item in value.split(",")]
    return [item for item in items if item] or None


def _options_from(args: argparse.Namespace) -> Options:
    terms: List[str] = list(args.term)
    if args.terms:
        with open(args.terms, "r", encoding="utf-8") as handle:
            terms.extend(line.strip() for line in handle if line.strip())
    return Options(
        only=_split(args.only),
        enable=_split(args.enable),
        disable=_split(args.disable),
        mode=args.mode,
        mask=args.mask,
        allow=_split(args.allow),
        terms=terms or None,
        min_confidence=args.min_confidence,
        refine_confidence=args.refine_confidence,
        include_values=args.include_values,
        transform_secret=os.environ.get(args.secret_env),
        pack=load_pack(args.pack) if args.pack else None,
    )


def _read(path: Optional[str]) -> str:
    if path is None:
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _format_pretty(findings: Sequence["_Located"]) -> str:
    if not findings:
        return "No secrets found."
    blocks = []
    for located in findings:
        finding = located.finding
        where = located.where()
        location = f"\n   at {where}" if where else ""
        value = f"\n   value: {finding.value}" if finding.value is not None else ""
        blocks.append(
            f"⚠  {finding.label} ({finding.detector}) "
            f"[{finding.risk}, {finding.confidence * 100:.0f}%]{location}{value}\n   {finding.why}"
        )
    noun = "finding" if len(findings) == 1 else "findings"
    return f"{len(findings)} {noun}:\n\n" + "\n\n".join(blocks)


def _format_json(findings: Sequence["_Located"], scanned: Sequence[str]) -> str:
    return json.dumps(
        {
            "schemaVersion": 2,
            "tool": {"name": "flare-redact", "version": __version__, "runtime": "python"},
            "summary": {"total": len(findings), "filesScanned": len(scanned)},
            "findings": [located.to_dict() for located in findings],
        },
        indent=2,
        ensure_ascii=False,
    )


def _format_sarif(findings: Sequence["_Located"]) -> str:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for located in findings:
        finding = located.finding
        rules.setdefault(
            finding.detector,
            {
                "id": finding.detector,
                "name": finding.label,
                "shortDescription": {"text": finding.label},
                "help": {"text": finding.why},
            },
        )
        result: Dict[str, Any] = {
            "ruleId": finding.detector,
            "level": "error" if finding.risk == "critical" else "warning" if finding.risk == "high" else "note",
            "message": {"text": f"{finding.label}: {finding.why}"},
            "properties": {"risk": finding.risk, "confidence": finding.confidence},
        }
        if finding.path:
            result["properties"]["path"] = finding.path
        if located.file:
            physical: Dict[str, Any] = {"artifactLocation": {"uri": located.file}}
            if finding.line is not None:
                physical["region"] = {"startLine": finding.line, "startColumn": finding.column or 1}
            result["locations"] = [{"physicalLocation": physical}]
        results.append(result)
    return json.dumps(
        {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "flare-redact",
                            "version": __version__,
                            "informationUri": "https://github.com/flare-collection/flare-redact",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        },
        indent=2,
        ensure_ascii=False,
    )


class _Located:
    """A finding plus the file it came from."""

    __slots__ = ("finding", "file")

    def __init__(self, finding: Finding, file: Optional[str]) -> None:
        self.finding = finding
        self.file = file

    def where(self) -> str:
        finding = self.finding
        if self.file and finding.line is not None:
            return f"{self.file}:{finding.line}:{finding.column or 1}"
        if self.file and finding.path:
            return f"{self.file} @ {finding.path}"
        if self.file:
            return self.file
        if finding.path:
            return finding.path
        if finding.line is not None:
            return f"{finding.line}:{finding.column or 1}"
        return f"offset {finding.start}" if finding.start is not None else ""

    def to_dict(self) -> Dict[str, Any]:
        out = self.finding.to_dict()
        if self.file:
            out["file"] = self.file
        return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI. Returns the process exit code."""
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.sarif:
        args.scan = True
        args.format = "sarif"

    try:
        options = _options_from(args)
    except (FlareRedactError, OSError, ValueError) as exc:
        sys.stderr.write(f"{exc}\n")
        return 2

    if args.list_mode:
        pack = options.pack or core_pack()
        for detector in pack.detectors:
            marker = "●" if detector.default else "○"
            sys.stdout.write(f"{marker} {detector.id.ljust(24)} {detector.label} — {detector.why}\n")
        return 0

    policy = compile_policy(options)
    sources: List[Optional[str]] = list(args.files) or [None]

    try:
        if args.scan or args.summary:
            findings: List[_Located] = []
            for source in sources:
                data: Any = _read(source)
                if args.json_mode:
                    data = json.loads(data)
                findings.extend(_Located(finding, source) for finding in policy.scan(data))
            if args.summary:
                counts: Dict[str, Any] = {"total": len(findings), "by_detector": {}, "by_risk": {}}
                for located in findings:
                    counts["by_detector"][located.finding.detector] = (
                        counts["by_detector"].get(located.finding.detector, 0) + 1
                    )
                    counts["by_risk"][located.finding.risk] = counts["by_risk"].get(located.finding.risk, 0) + 1
                sys.stdout.write(json.dumps(counts, indent=2) + "\n")
            elif args.format == "json":
                sys.stdout.write(_format_json(findings, [s for s in sources if s]) + "\n")
            elif args.format == "sarif":
                sys.stdout.write(_format_sarif(findings) + "\n")
            else:
                sys.stdout.write(_format_pretty(findings) + "\n")
            return 1 if findings else 0

        for source in sources:
            raw = _read(source)
            if args.json_mode:
                sys.stdout.write(json.dumps(policy.redact(json.loads(raw)), indent=2, ensure_ascii=False) + "\n")
            else:
                sys.stdout.write(policy.redact_str(raw))
        return 0
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"invalid JSON: {exc}\n")
        return 2
    except (FlareRedactError, OSError) as exc:
        sys.stderr.write(f"{exc}\n")
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
