"""Shadow mode: measure what a policy would redact before it is enforced.

An audit counts findings by detector, risk, source and field path while the
data passes through unchanged, so the decision to enforce redaction rests on
numbers. It never stores a matched value.

    from flare_redact.audit import Audit, AuditFilter

    audit = Audit(preset="gdpr")
    audit.observe(event, source="webhook")   # returned unchanged, counted
    print(audit.format())                    # counts only, safe to log

    logging.getLogger().addFilter(AuditFilter(audit))   # count what logs would lose

An OpenTelemetry meter, when given, gets ``flare_redact.findings`` and
``flare_redact.scanned`` counters, the same names the JavaScript engine uses.
"""

from __future__ import annotations

import logging
import re
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Union

from .engine import Finding, Options, compile_policy

__all__ = ["Audit", "AuditFilter"]

_INDEX = re.compile(r"\[\d+\]")


def _fold(path: str) -> str:
    """``users[3].email`` and ``users[7].email`` are the same field."""
    return _INDEX.sub("[]", path)


def _sorted(counts: Dict[str, int]) -> Dict[str, int]:
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


class Audit:
    """Counts what a policy finds, without ever keeping a matched value."""

    def __init__(
        self,
        options: Union[Options, Mapping[str, Any], None] = None,
        *,
        meter: Any = None,
        on_finding: Optional[Callable[[Dict[str, str]], None]] = None,
        max_paths: int = 500,
        **overrides: Any,
    ) -> None:
        # An audit must never keep a matched value, whatever the caller passed.
        overrides["include_values"] = False
        self.policy = compile_policy(options, **overrides)
        self._on_finding = on_finding
        self._max_paths = max_paths
        self._lock = threading.Lock()
        self._findings = self._scanned = None
        if meter is not None:
            self._findings = meter.create_counter(
                "flare_redact.findings", unit="{finding}",
                description="Values flare-redact found, by detector, risk and source",
            )
            self._scanned = meter.create_counter(
                "flare_redact.scanned", unit="{value}", description="Values flare-redact checked, by source",
            )
        self.reset()

    def reset(self) -> None:
        """Start counting again."""
        with self._lock:
            self._since = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            self._count = 0
            self._with_findings = 0
            self._total = 0
            self._by_detector: Dict[str, int] = {}
            self._by_risk: Dict[str, int] = {}
            self._by_source: Dict[str, Dict[str, Any]] = {}
            self._by_path: Dict[str, int] = {}

    def _record(self, findings: List[Finding], source: str) -> None:
        events: List[Dict[str, str]] = []
        with self._lock:
            self._count += 1
            per = self._by_source.setdefault(source, {"scanned": 0, "total": 0, "by_detector": {}})
            per["scanned"] += 1
            if findings:
                self._with_findings += 1
            for finding in findings:
                self._total += 1
                per["total"] += 1
                self._by_detector[finding.detector] = self._by_detector.get(finding.detector, 0) + 1
                self._by_risk[finding.risk] = self._by_risk.get(finding.risk, 0) + 1
                per["by_detector"][finding.detector] = per["by_detector"].get(finding.detector, 0) + 1
                event = {"detector": finding.detector, "risk": finding.risk, "source": source}
                if finding.path:
                    path = _fold(finding.path)
                    key = path if path in self._by_path or len(self._by_path) < self._max_paths else "(other)"
                    self._by_path[key] = self._by_path.get(key, 0) + 1
                    event["path"] = path
                events.append(event)
        if self._scanned is not None:
            self._scanned.add(1, {"source": source})
        for event in events:
            if self._findings is not None:
                self._findings.add(1, {k: event[k] for k in ("detector", "risk", "source")})
            if self._on_finding is not None:
                self._on_finding(event)

    def observe(self, value: Any, source: str = "default") -> Any:
        """Count what ``value`` would have redacted and return it unchanged."""
        self._record(self.policy.scan(value), source)
        return value

    def redact(self, value: Any, source: str = "default") -> Any:
        """Redact ``value`` and count what was redacted."""
        self._record(self.policy.scan(value), source)
        return self.policy.redact(value)

    def report(self) -> Dict[str, Any]:
        """The counts so far. Safe to log: no values."""
        with self._lock:
            return {
                "since": self._since,
                "scanned": self._count,
                "with_findings": self._with_findings,
                "total": self._total,
                "by_detector": _sorted(self._by_detector),
                "by_risk": _sorted(self._by_risk),
                "by_source": {
                    name: {**per, "by_detector": _sorted(per["by_detector"])} for name, per in self._by_source.items()
                },
                "by_path": _sorted(self._by_path),
            }

    def format(self) -> str:
        """The report as a short table."""
        r = self.report()
        share = f" ({r['with_findings'] / r['scanned'] * 100:.1f}%)" if r["scanned"] else ""
        noun = "finding" if r["total"] == 1 else "findings"
        lines = [f"{r['total']} {noun} in {r['with_findings']} of {r['scanned']} values{share} since {r['since']}"]
        lines += [f"  {detector:<24} {count}" for detector, count in r["by_detector"].items()]
        paths = list(r["by_path"].items())[:10]
        if paths:
            lines.append("  top fields:")
            lines += [f"    {path:<22} {count}" for path, count in paths]
        return "\n".join(lines)


class AuditFilter(logging.Filter):
    """Count what a logger's records would lose to redaction, and let them pass unchanged.

    Each logger name is its own source. With ``enforce=True`` the records are
    redacted as well, and still counted.
    """

    def __init__(self, audit: Optional[Audit] = None, *, enforce: bool = False, **options: Any) -> None:
        super().__init__()
        self.audit = audit if audit is not None else Audit(**options)
        self.enforce = enforce

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage() if isinstance(record.msg, str) else record.msg
            if self.enforce:
                redacted = self.audit.redact(message, record.name)
                record.msg, record.args = redacted, None
            else:
                self.audit.observe(message, record.name)
        except Exception:  # counting must never break logging
            if self.enforce:
                raise
        return True
