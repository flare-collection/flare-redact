"""The FRS-1 scan and redact engine.

Everything the library does reduces to one function: given a string, produce the
set of spans that must not survive, then rewrite the string once. The rest —
structured data, vaults, logging filters, the gateway client — is plumbing
around this file.

The two decisions worth knowing about:

* **Overlap resolution is maximum-weight interval scheduling**, not first-match.
  A value that is both an OpenRouter key and a high-entropy string gets masked
  the same way regardless of what else is on the line.
* **Limits fail closed.** Oversized input raises instead of returning partially
  redacted text, because a caller cannot tell a partially redacted string from a
  clean one.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass
from typing import (
    Any, Callable, Dict, List, Mapping, Optional, Pattern, Sequence, Tuple, Union,
)

from .crypto import hmac_fingerprint
from .keywords import MULTILANG_KEY_SET, SENSITIVE_KEY_PATTERN
from .ml import secret_probability
from .pack import Detector, Pack, core_pack, is_unicode_word_char
from .transforms import pseudonymize, surrogate

__all__ = [
    "Options", "Finding", "Policy", "FlareRedactError", "RedactionLimitError",
    "compile_policy", "redact", "scan", "is_clean", "summary",
    "MODES", "DEFAULT_MAX_INPUT_LENGTH", "DEFAULT_MAX_FINDINGS",
]

DEFAULT_MAX_INPUT_LENGTH = 16 * 1024 * 1024
DEFAULT_MAX_FINDINGS = 50_000

MODES = ("mask", "label", "hash", "pseudonym", "surrogate")

#: Invisible characters an attacker can sprinkle through a secret to defeat a
#: naive matcher. Stripped before matching; see :func:`_normalized_view`.
_ZERO_WIDTH_SET = frozenset("​‌‍⁠﻿")

_RISK_WEIGHT = {"critical": 1e9, "high": 1e6, "medium": 1e3, "low": 1.0}

#: How far the learned model may move a base confidence score, up or down.
_REFINE_STRENGTH = 0.4

_SENSITIVE_KEY_RE = re.compile(SENSITIVE_KEY_PATTERN, re.IGNORECASE)

_SENSITIVE_KEY_DETECTOR = Detector(
    id="sensitive_key",
    label="Sensitive field",
    why="A value stored under a field name that is sensitive by convention.",
    regex=re.compile(r"[^\s\S]"),  # matches nothing; this detector is key-driven
    mask=lambda _value: "***",
    risk="critical",
    confidence=0.98,
    default=True,
)


class FlareRedactError(Exception):
    """Base class for errors raised by this library."""

    code = "ERR_FLARE_REDACT"


class RedactionLimitError(FlareRedactError):
    """A configured input or finding limit was exceeded; nothing was redacted."""

    code = "ERR_REDACTION_LIMIT"


@dataclass(frozen=True)
class Finding:
    """One thing the scanner would redact, and why."""

    detector: str
    label: str
    why: str
    risk: str
    confidence: float
    start: Optional[int] = None
    end: Optional[int] = None
    line: Optional[int] = None
    column: Optional[int] = None
    path: Optional[str] = None
    #: Only populated when ``include_values`` is set. Unsafe for logs and reports.
    value: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """A JSON-ready dict that omits absent locations and the raw value."""
        out: Dict[str, Any] = {
            "detector": self.detector,
            "label": self.label,
            "why": self.why,
            "risk": self.risk,
            "confidence": self.confidence,
        }
        for name in ("start", "end", "line", "column", "path", "value"):
            value = getattr(self, name)
            if value is not None:
                out[name] = value
        return out


MaskFn = Callable[[str, Detector], str]


@dataclass
class Options:
    """Everything that shapes a redaction, in one reusable object."""

    #: Use only these detector ids or tags, ignoring defaults.
    only: Optional[Sequence[str]] = None
    #: Turn on non-default detectors by id or tag.
    enable: Optional[Sequence[str]] = None
    #: Turn off detectors by id or tag.
    disable: Optional[Sequence[str]] = None
    #: ``mask`` | ``label`` | ``hash`` | ``pseudonym`` | ``surrogate``.
    mode: str = "mask"
    #: A fixed replacement string, or ``fn(value, detector) -> str``. Wins over ``mode``.
    mask: Union[str, MaskFn, None] = None
    #: Key for ``hash``, ``pseudonym`` and ``surrogate``. Never hard-code it.
    transform_secret: Optional[str] = None
    #: ``True`` for the built-in sensitive-name test, or a regex, or an exact list.
    redact_keys: Union[bool, "Pattern[str]", Sequence[str]] = True
    #: Values that are never redacted — an exact list, or a regex.
    allow: Union["Pattern[str]", Sequence[str], None] = None
    #: Your own words to always catch: a list, or ``{term: replacement}``.
    terms: Union[Sequence[Any], Mapping[str, str], None] = None
    terms_case_sensitive: bool = False
    #: Drop findings scored below this.
    min_confidence: float = 0.0
    #: Let the learned classifier refine confidence for generic detectors.
    refine_confidence: bool = False
    #: Include raw matched values in scan results. Unsafe for logs.
    include_values: bool = False
    max_input_length: int = DEFAULT_MAX_INPUT_LENGTH
    max_findings: int = DEFAULT_MAX_FINDINGS
    #: An alternative FRS-1 detector pack. Defaults to the bundled core pack.
    pack: Optional[Pack] = None

    def __post_init__(self) -> None:
        if self.mode == "fpe":  # historical alias; never represented encryption
            self.mode = "pseudonym"
        if self.mode not in MODES:
            raise FlareRedactError(f"unknown mode {self.mode!r}; expected one of {', '.join(MODES)}")

    @classmethod
    def coerce(cls, options: Union["Options", Mapping[str, Any], None] = None, **overrides: Any) -> "Options":
        """Build options from an ``Options``, a mapping, keyword arguments, or all three."""
        if isinstance(options, Options):
            if not overrides:
                return options
            merged = {f.name: getattr(options, f.name) for f in dataclasses.fields(options)}
            merged.update(overrides)
            return cls(**merged)
        merged = dict(options or {})
        merged.update(overrides)
        return cls(**merged)


# --------------------------------------------------------------------------- #
# Detector resolution
# --------------------------------------------------------------------------- #


def _normalize_terms(terms: Union[Sequence[Any], Mapping[str, str], None]) -> List[Tuple[str, Optional[str]]]:
    if not terms:
        return []
    if isinstance(terms, Mapping):
        pairs = [(str(term), str(replacement)) for term, replacement in terms.items()]
    else:
        pairs = []
        for entry in terms:
            if isinstance(entry, str):
                pairs.append((entry, None))
            elif isinstance(entry, Mapping):
                pairs.append((str(entry["term"]), entry.get("replace")))
            else:
                raise FlareRedactError(f"terms entries must be strings or mappings, got {type(entry).__name__}")
    return [(term, replacement) for term, replacement in pairs if term]


def build_terms_detector(
    terms: Union[Sequence[Any], Mapping[str, str], None],
    case_sensitive: bool = False,
) -> Optional[Detector]:
    """A detector for host-supplied words, matched longest-first on word boundaries."""
    pairs = _normalize_terms(terms)
    if not pairs:
        return None

    alternation = "|".join(re.escape(term) for term, _ in sorted(pairs, key=lambda p: -len(p[0])))
    regex = re.compile(f"(?:{alternation})", 0 if case_sensitive else re.IGNORECASE)

    def key(text: str) -> str:
        return text if case_sensitive else text.lower()

    replacements = {key(term): (replacement if replacement is not None else "***") for term, replacement in pairs}

    return Detector(
        id="custom_term",
        label="Custom term",
        why="A term you configured as sensitive.",
        regex=regex,
        mask=lambda value: replacements.get(key(value), "***"),
        risk="high",
        confidence=0.92,
        default=True,
        before=is_unicode_word_char,
        after=is_unicode_word_char,
        tags=("custom",),
    )


def resolve_detectors(options: Options) -> Tuple[Detector, ...]:
    """The ordered detector list implied by ``only`` / ``enable`` / ``disable`` / ``terms``."""
    pack = options.pack or core_pack()
    if options.only:
        chosen = [d for d in pack.detectors if any(d.matches_selector(s) for s in options.only)]
    else:
        enable = tuple(options.enable or ())
        disable = tuple(options.disable or ())
        chosen = [
            d
            for d in pack.detectors
            if (d.default or any(d.matches_selector(s) for s in enable))
            and not any(d.matches_selector(s) for s in disable)
        ]
    terms = build_terms_detector(options.terms, options.terms_case_sensitive)
    return tuple([terms, *chosen]) if terms else tuple(chosen)


def key_matcher(options: Options) -> Callable[[str], bool]:
    """The test for "this field name is sensitive by convention"."""
    rule = options.redact_keys
    if rule is False:
        return lambda _key: False
    if rule is True or rule is None:
        return lambda name: bool(_SENSITIVE_KEY_RE.fullmatch(name)) or name.lower() in MULTILANG_KEY_SET
    if isinstance(rule, re.Pattern):
        return lambda name: rule.search(name) is not None
    names = frozenset(str(name).lower() for name in rule)
    return lambda name: name.lower() in names


def allow_matcher(options: Options) -> Callable[[str], bool]:
    """The test for "never redact this exact value"."""
    rule = options.allow
    if rule is None:
        return lambda _value: False
    if isinstance(rule, re.Pattern):
        return lambda value: rule.search(value) is not None
    allowed = frozenset(rule)
    return lambda value: value in allowed


def make_replacer(options: Options) -> MaskFn:
    """How a matched value becomes its replacement, given the mode and mask."""
    mask = options.mask
    if isinstance(mask, str):
        return lambda _value, _detector: mask
    if callable(mask):
        return lambda value, detector: mask(value, detector)

    secret = options.transform_secret or ""
    mode = options.mode
    if mode == "label":
        return lambda _value, detector: f"[REDACTED:{detector.id}]"
    if mode == "hash":
        return lambda value, detector: f"{detector.id}_{hmac_fingerprint(secret, value)}"
    if mode == "pseudonym":
        return lambda value, _detector: pseudonymize(value, secret)
    if mode == "surrogate":
        return lambda value, detector: surrogate(value, detector.id, secret)
    return lambda value, detector: detector.mask(value)


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #


class Hit:
    """An accepted candidate span, before overlap resolution."""

    __slots__ = ("detector", "start", "end", "value", "confidence", "weight")

    def __init__(self, detector: Detector, start: int, end: int, value: str, confidence: float) -> None:
        self.detector = detector
        self.start = start
        self.end = end
        self.value = value
        self.confidence = confidence
        self.weight = (
            _RISK_WEIGHT[detector.risk]
            + 10.0 * detector.priority
            + confidence
            + (end - start) / 1_000_000.0
        )


def _normalized_view(text: str) -> Tuple[str, Optional[List[int]]]:
    """Strip zero-width characters, keeping a map back to the original offsets.

    Splicing U+200B between the letters of ``password`` defeats a naive matcher.
    Matching therefore happens on the stripped text, while every reported offset
    and every replacement refers to the original — so the invisible characters
    are removed along with the secret, not left behind as a fingerprint.
    """
    if not _ZERO_WIDTH_SET.intersection(text):
        return text, None
    kept: List[str] = []
    index_map: List[int] = []
    for index, ch in enumerate(text):
        if ch in _ZERO_WIDTH_SET:
            continue
        kept.append(ch)
        index_map.append(index)
    return "".join(kept), index_map


def _score_confidence(detector: Detector, text: str, start: int, end: int, options: Options, pack: Pack) -> float:
    score = detector.confidence
    if detector.context_positive is not None or detector.context_negative is not None:
        radius = detector.context_window
        nearby = text[max(0, start - radius) : min(len(text), end + radius)]
        if detector.context_positive is not None and detector.context_positive.search(nearby):
            score += 0.06
        if detector.context_negative is not None and detector.context_negative.search(nearby):
            score -= 0.25
    if options.refine_confidence and detector.refine and pack.confidence_model is not None:
        window = text[max(0, start - 64) : min(len(text), end + 64)]
        probability = secret_probability(text[start:end], window, pack.confidence_model)
        score += (probability - 0.5) * _REFINE_STRENGTH
    return max(0.0, min(1.0, score))


def scan_string(
    text: str,
    detectors: Sequence[Detector],
    allow: Callable[[str], bool],
    options: Options,
) -> List[Hit]:
    """Every span in ``text`` that survives filtering and overlap resolution."""
    if len(text) > options.max_input_length:
        raise RedactionLimitError(
            f"Input length {len(text)} exceeds the configured limit of {options.max_input_length}."
        )

    pack = options.pack or core_pack()
    subject, index_map = _normalized_view(text)
    lowered: Optional[str] = None
    hits: List[Hit] = []

    for detector in detectors:
        if detector.prefilter:
            if lowered is None:
                lowered = subject.lower()
            if not any(literal in lowered for literal in detector.prefilter):
                continue

        for match in detector.regex.finditer(subject):
            span_start, span_end = match.span(detector.capture)
            if span_start < 0 or span_end <= span_start:
                continue
            if detector.before is not None and span_start > 0 and detector.before(subject[span_start - 1]):
                continue
            if detector.after is not None and span_end < len(subject) and detector.after(subject[span_end]):
                continue

            normalized_value = subject[span_start:span_end]
            if any(pattern.match(normalized_value) for pattern in detector.reject):
                continue
            if not all(validator(normalized_value) for validator in detector.validators):
                continue

            if index_map is None:
                start, end = span_start, span_end
            else:
                start, end = index_map[span_start], index_map[span_end - 1] + 1
            value = text[start:end]
            if allow(value) or (value != normalized_value and allow(normalized_value)):
                continue

            confidence = _score_confidence(detector, text, start, end, options, pack)
            if confidence < options.min_confidence:
                continue

            hits.append(Hit(detector, start, end, value, confidence))
            if len(hits) > options.max_findings:
                raise RedactionLimitError(
                    f"Finding count exceeds the configured limit of {options.max_findings}."
                )

    if len(hits) < 2:
        return hits
    return _select_non_overlapping(hits)


def _select_non_overlapping(hits: List[Hit]) -> List[Hit]:
    """Maximum-weight set of non-overlapping spans (weighted interval scheduling)."""
    ordered = sorted(hits, key=lambda hit: (hit.end, hit.start))
    count = len(ordered)

    previous = [0] * count
    for i in range(count):
        low, high, found = 0, i - 1, -1
        while low <= high:
            mid = (low + high) // 2
            if ordered[mid].end <= ordered[i].start:
                found = mid
                low = mid + 1
            else:
                high = mid - 1
        previous[i] = found

    best = [0.0] * (count + 1)
    for i in range(1, count + 1):
        include = ordered[i - 1].weight + best[previous[i - 1] + 1]
        best[i] = max(best[i - 1], include)

    selected: List[Hit] = []
    i = count
    while i > 0:
        include = ordered[i - 1].weight + best[previous[i - 1] + 1]
        if include > best[i - 1]:
            selected.append(ordered[i - 1])
            i = previous[i - 1] + 1
        else:
            i -= 1
    selected.reverse()
    selected.sort(key=lambda hit: (hit.start, hit.end))
    return selected


def redact_string(
    text: str,
    detectors: Sequence[Detector],
    allow: Callable[[str], bool],
    replace: MaskFn,
    options: Options,
) -> str:
    """One pass: copy the safe text, substitute each hit, never rescan output."""
    hits = scan_string(text, detectors, allow, options)
    if not hits:
        return text
    out: List[str] = []
    cursor = 0
    for hit in hits:
        out.append(text[cursor : hit.start])
        out.append(replace(hit.value, hit.detector))
        cursor = hit.end
    out.append(text[cursor:])
    return "".join(out)


# --------------------------------------------------------------------------- #
# Structured data
# --------------------------------------------------------------------------- #

_ATOMIC = (bool, int, float, complex, bytes, bytearray, memoryview, type(None))


def map_graph(
    value: Any,
    map_string: Callable[[str], str],
    map_sensitive: Optional[Callable[[str, str], str]] = None,
) -> Any:
    """Rebuild a structure with every reachable string transformed.

    Cycles are visited once and shared references stay shared, so redacting a
    log record that points at itself terminates and still round-trips.
    """
    seen: Dict[int, Any] = {}

    def walk(node: Any) -> Any:
        if isinstance(node, str):
            return map_string(node)
        if isinstance(node, _ATOMIC):
            return node

        identity = id(node)
        if identity in seen:
            return seen[identity]

        if isinstance(node, Mapping):
            out: Dict[Any, Any] = {}
            seen[identity] = out
            for key, item in node.items():
                mapped_key = walk(key) if isinstance(key, str) else key
                if map_sensitive is not None and isinstance(key, str) and isinstance(item, str):
                    out[mapped_key] = map_sensitive(key, item)
                else:
                    out[mapped_key] = walk(item)
            return out

        if isinstance(node, list):
            out_list: List[Any] = []
            seen[identity] = out_list
            for item in node:
                out_list.append(walk(item))
            return out_list

        if isinstance(node, (set, frozenset)):
            # A hashable container cannot contain itself, so no cycle guard is needed.
            return type(node)(walk(item) for item in node)

        if isinstance(node, tuple):
            mapped = tuple(walk(item) for item in node)
            seen[identity] = mapped
            return mapped

        if isinstance(node, BaseException):
            mapped_args = tuple(walk(arg) for arg in node.args)
            try:
                return type(node)(*mapped_args)
            except TypeError:
                # An exception with a bespoke __init__ cannot be rebuilt safely;
                # returning a plain Exception keeps the message redacted, which
                # matters more than preserving the class.
                return Exception(*mapped_args)

        return node

    return walk(value)


def _locate(text: str, offset: int) -> Tuple[int, int]:
    """One-based (line, column) of ``offset`` within ``text``."""
    line_start = text.rfind("\n", 0, offset) + 1
    line = text.count("\n", 0, offset) + 1
    return line, offset - line_start + 1


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #


class Policy:
    """One compiled set of options, reusable everywhere.

    Building a policy resolves the detector list, the mask function and the key
    and allow tests once. Reuse it across requests: the same secret is then
    masked the same way in your logs, your HTTP layer and your prompts, which is
    the property that makes redaction auditable.
    """

    __slots__ = ("options", "detectors", "_allow", "_replace", "_match_key")

    def __init__(self, options: Options) -> None:
        self.options = options
        self.detectors = resolve_detectors(options)
        self._allow = allow_matcher(options)
        self._replace = make_replacer(options)
        self._match_key = key_matcher(options)

    # -- redaction ---------------------------------------------------------- #

    def redact_str(self, text: str) -> str:
        """Redact a single string."""
        return redact_string(text, self.detectors, self._allow, self._replace, self.options)

    def redact(self, value: Any) -> Any:
        """Redact every string reachable from ``value``, preserving its shape."""
        def sensitive(key: str, item: str) -> str:
            if self._match_key(key) and not self._allow(item):
                return self._replace(item, _SENSITIVE_KEY_DETECTOR)
            return self.redact_str(item)

        return map_graph(value, self.redact_str, sensitive)

    # -- inspection --------------------------------------------------------- #

    def scan(self, value: Any) -> List[Finding]:
        """Every finding in ``value``, with paths and line/column locations."""
        findings: List[Finding] = []
        seen: set = set()
        include_values = self.options.include_values

        def scan_text(text: str, path: Optional[str]) -> None:
            for hit in scan_string(text, self.detectors, self._allow, self.options):
                line, column = _locate(text, hit.start)
                findings.append(
                    Finding(
                        detector=hit.detector.id,
                        label=hit.detector.label,
                        why=hit.detector.why,
                        risk=hit.detector.risk,
                        confidence=hit.confidence,
                        start=hit.start,
                        end=hit.end,
                        line=line,
                        column=column,
                        path=path,
                        value=hit.value if include_values else None,
                    )
                )

        def walk(node: Any, path: str) -> None:
            if isinstance(node, str):
                scan_text(node, path or None)
                return
            if isinstance(node, _ATOMIC):
                return
            identity = id(node)
            if identity in seen:
                return
            seen.add(identity)

            if isinstance(node, Mapping):
                for key, item in node.items():
                    name = key if isinstance(key, str) else f"<key:{key!r}>"
                    child = f"{path}.{name}" if path else str(name)
                    if isinstance(key, str) and isinstance(item, str) and self._match_key(key) and not self._allow(item):
                        findings.append(
                            Finding(
                                detector="sensitive_key",
                                label="Sensitive field",
                                why=f'Value stored under a sensitive field name ("{key}").',
                                risk="critical",
                                confidence=0.98,
                                path=child,
                                value=item if include_values else None,
                            )
                        )
                    else:
                        walk(item, child)
                return

            if isinstance(node, (list, tuple, set, frozenset)):
                for index, item in enumerate(node):
                    walk(item, f"{path}[{index}]")
                return

            if isinstance(node, BaseException):
                for index, arg in enumerate(node.args):
                    walk(arg, f"{path}.args[{index}]" if path else f"args[{index}]")
                return

        walk(value, "")
        return findings

    def is_clean(self, value: Any) -> bool:
        """True when nothing in ``value`` would be redacted."""
        return not self.scan(value)

    def summary(self, value: Any) -> Dict[str, Any]:
        """Counts by detector and by risk — safe to log, contains no values."""
        return summarize(self.scan(value))

    def vault(self) -> Any:
        """A reversible vault bound to this policy's options."""
        from .vault import Vault

        return Vault(self.options)

    def session(self) -> Any:
        """A conversation-scoped vault for chat and agent loops."""
        from .vault import Session

        return Session(self.options)


def summarize(findings: Sequence[Finding]) -> Dict[str, Any]:
    """Aggregate findings into counts by detector and by risk."""
    by_detector: Dict[str, int] = {}
    by_risk: Dict[str, int] = {}
    for finding in findings:
        by_detector[finding.detector] = by_detector.get(finding.detector, 0) + 1
        by_risk[finding.risk] = by_risk.get(finding.risk, 0) + 1
    return {"total": len(findings), "by_detector": by_detector, "by_risk": by_risk}


# --------------------------------------------------------------------------- #
# Module-level convenience API
# --------------------------------------------------------------------------- #


def compile_policy(options: Union[Options, Mapping[str, Any], None] = None, **overrides: Any) -> Policy:
    """Compile options once and reuse the result — the recommended entry point."""
    return Policy(Options.coerce(options, **overrides))


def redact(value: Any, options: Union[Options, Mapping[str, Any], None] = None, **overrides: Any) -> Any:
    """Redact every string reachable from ``value``."""
    return compile_policy(options, **overrides).redact(value)


def scan(value: Any, options: Union[Options, Mapping[str, Any], None] = None, **overrides: Any) -> List[Finding]:
    """List what would be redacted, and why."""
    return compile_policy(options, **overrides).scan(value)


def is_clean(value: Any, options: Union[Options, Mapping[str, Any], None] = None, **overrides: Any) -> bool:
    """True when nothing in ``value`` would be redacted."""
    return compile_policy(options, **overrides).is_clean(value)


def summary(value: Any, options: Union[Options, Mapping[str, Any], None] = None, **overrides: Any) -> Dict[str, Any]:
    """Counts by detector and by risk."""
    return compile_policy(options, **overrides).summary(value)
