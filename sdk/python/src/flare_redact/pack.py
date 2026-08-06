"""Loading and compiling FRS-1 detector packs.

A pack is data: patterns written in a restricted, engine-neutral subset plus
named validators and mask strategies. This module turns that data into compiled
Python objects, and refuses to load anything it cannot execute exactly as the
spec describes — an unknown validator name or a lookahead in a pattern is a
load-time error, never a silently weakened check.

See ``spec/SPEC.md`` for the normative description of every field.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

from .checksums import VALIDATORS, luhn, shannon_entropy
from .ml import ConfidenceModel

__all__ = ["Pack", "Detector", "PackError", "load_pack", "core_pack", "BOUNDARY_CLASSES"]

SPEC_REVISION = "FRS-1"

_HERE = os.path.dirname(os.path.abspath(__file__))
_CORE_PACK_PATH = os.path.join(_HERE, "detectors.json")

#: Neighbour characters a captured span may not touch. See spec §3.1.
BOUNDARY_CLASSES: Dict[str, FrozenSet[str]] = {
    "word": frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"),
    "alnum": frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
    "digit": frozenset("0123456789"),
    "hex": frozenset("0123456789abcdefABCDEF"),
    "base64": frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="),
    "base64url": frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+/=-"),
    "word_dash": frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"),
}

_RISKS = ("low", "medium", "high", "critical")

# Engine-side expansion of the two portable tokens. `[\s\S]` is "any character"
# regardless of the Unicode semantics of `\s`, because a class unioned with its
# own complement is total; `[^\W\d_]` is the standard Python idiom for "Unicode
# letter", which is why {{L}} may never appear inside a character class.
_ANY = r"[\s\S]"
_LETTER = r"[^\W\d_]"


class PackError(ValueError):
    """Raised when a pack is malformed or uses a construct this engine cannot honour."""


def _expand_tokens(pattern: str) -> str:
    return pattern.replace("{{ANY}}", _ANY).replace("{{L}}", _LETTER)


_FORBIDDEN_ESCAPES = frozenset("bBdDwWsSpP123456789AZzGkK")


def _assert_portable(pattern: str, where: str) -> None:
    """Reject constructs whose meaning differs between the FRS-1 target engines."""
    index = 0
    in_class = False
    length = len(pattern)
    while index < length:
        ch = pattern[index]
        if ch == "\\":
            if index + 1 >= length:
                raise PackError(f"{where}: pattern ends with a dangling backslash")
            nxt = pattern[index + 1]
            if nxt in _FORBIDDEN_ESCAPES:
                raise PackError(
                    f"{where}: '\\{nxt}' is not portable across FRS-1 engines; "
                    "write the character class out, or use {{ANY}} / {{L}}"
                )
            index += 2
            continue
        if in_class:
            if ch == "]":
                in_class = False
            index += 1
            continue
        if ch == "[":
            in_class = True
            index += 1
            # A leading '^' or ']' is literal inside a class.
            if index < length and pattern[index] == "^":
                index += 1
            if index < length and pattern[index] == "]":
                index += 1
            continue
        if ch == "(" and index + 1 < length and pattern[index + 1] == "?":
            group = pattern[index + 2 : index + 3]
            if group != ":":
                raise PackError(
                    f"{where}: '(?{group}' is not portable across FRS-1 engines; "
                    "only '(...)' and '(?:...)' groups are allowed"
                )
            index += 3
            continue
        if ch in "^$":
            raise PackError(f"{where}: anchors are not allowed inside a detector pattern")
        index += 1
    if in_class:
        raise PackError(f"{where}: unterminated character class")


def _compile(pattern: str, flags: str, where: str, *, portable: bool = True) -> "re.Pattern[str]":
    if portable:
        _assert_portable(pattern, where)
    try:
        return re.compile(_expand_tokens(pattern), re.IGNORECASE if flags == "i" else 0)
    except re.error as exc:  # pragma: no cover - guarded by the corpus
        raise PackError(f"{where}: invalid pattern ({exc})") from exc


def _expand_replacement(template: str, match: "re.Match[str]") -> str:
    """Substitute ``$1``–``$9`` (and ``$$``) in a mask replacement template."""
    out: List[str] = []
    index = 0
    length = len(template)
    while index < length:
        ch = template[index]
        if ch == "$" and index + 1 < length:
            nxt = template[index + 1]
            if nxt == "$":
                out.append("$")
                index += 2
                continue
            if nxt.isdigit() and nxt != "0":
                group = int(nxt)
                if group <= (match.re.groups or 0):
                    out.append(match.group(group) or "")
                    index += 2
                    continue
        out.append(ch)
        index += 1
    return "".join(out)


def _build_mask(spec: Mapping[str, Any], where: str) -> Callable[[str], str]:
    kind = spec.get("type")

    if kind == "fixed":
        text = str(spec["text"])
        return lambda _value: text

    if kind == "keepPrefix":
        n = int(spec["n"])
        return lambda value: "***" if len(value) <= n else value[:n] + "***"

    if kind == "keepLast":
        n = int(spec["n"])

        def keep_last(value: str) -> str:
            digits = re.sub(r"[^0-9]", "", value)
            tail = digits[-n:] if n else ""
            groups = max(0, -(-(len(digits) - n) // 4))
            return ("**** " * groups + tail).strip()

        return keep_last

    if kind == "keepThroughSeparator":
        separator = str(spec["separator"])
        count = int(spec["count"])

        def keep_through(value: str) -> str:
            index = -len(separator)
            for _ in range(count):
                index = value.find(separator, index + len(separator))
                if index < 0:
                    return "***"
            return value[: index + len(separator)] + "***"

        return keep_through

    if kind == "replace":
        regex = _compile(str(spec["pattern"]), str(spec.get("flags", "")), f"{where} mask", portable=False)
        replacement = str(spec["replacement"])

        def replace(value: str) -> str:
            match = regex.fullmatch(value)
            return _expand_replacement(replacement, match) if match else value

        return replace

    raise PackError(f"{where}: unknown mask type {kind!r}")


def _build_validator(spec: Mapping[str, Any], where: str) -> Callable[[str], bool]:
    name = spec.get("name")

    if name == "normalized_match":
        strip = spec.get("strip")
        strip_re = _compile(str(strip), "", f"{where} validator strip", portable=False) if strip else None
        target = _compile(str(spec["pattern"]), "", f"{where} validator", portable=False)

        def normalized_match(value: str) -> bool:
            candidate = strip_re.sub("", value) if strip_re else value
            return target.fullmatch(candidate) is not None

        return normalized_match

    if name == "luhn":
        min_digits = int(spec.get("minDigits", 2))
        max_digits = int(spec.get("maxDigits", 0))
        return lambda value: luhn(value, min_digits, max_digits)

    if name == "entropy":
        minimum = float(spec["min"])
        return lambda value: shannon_entropy(value) >= minimum

    validator = VALIDATORS.get(str(name))
    if validator is None:
        raise PackError(
            f"{where}: unknown validator {name!r}. Refusing to load a pack whose checks "
            "this engine cannot perform."
        )
    return validator


def is_unicode_word_char(ch: str) -> bool:
    """Boundary test used by host-supplied terms: any letter, digit or underscore.

    Terms are words in a natural language, not tokens, so ``Ünvan`` must not match
    inside ``Ünvanlar``. That needs a Unicode-aware boundary, which the ASCII
    classes in :data:`BOUNDARY_CLASSES` deliberately are not.
    """
    return ch == "_" or ch.isalpha() or ch.isdigit()


BoundaryTest = Callable[[str], bool]


class Detector:
    """A compiled detector, ready to run against a subject string."""

    __slots__ = (
        "id", "label", "why", "regex", "capture", "before", "after", "reject",
        "validators", "mask", "default", "tags", "risk", "priority", "confidence",
        "refine", "prefilter", "context_positive", "context_negative", "context_window",
    )

    def __init__(
        self,
        *,
        id: str,
        label: str,
        why: str,
        regex: "re.Pattern[str]",
        mask: Callable[[str], str],
        risk: str,
        confidence: float,
        default: bool,
        capture: int = 0,
        before: Optional[BoundaryTest] = None,
        after: Optional[BoundaryTest] = None,
        reject: Sequence["re.Pattern[str]"] = (),
        validators: Sequence[Callable[[str], bool]] = (),
        tags: Sequence[str] = (),
        priority: int = 0,
        refine: bool = False,
        prefilter: Sequence[str] = (),
        context_positive: Optional["re.Pattern[str]"] = None,
        context_negative: Optional["re.Pattern[str]"] = None,
        context_window: int = 80,
    ) -> None:
        self.id = id
        self.label = label
        self.why = why
        self.regex = regex
        self.mask = mask
        self.risk = risk
        self.confidence = confidence
        self.default = default
        self.capture = capture
        self.before = before
        self.after = after
        self.reject = tuple(reject)
        self.validators = tuple(validators)
        self.tags = tuple(tags)
        self.priority = priority
        self.refine = refine
        self.prefilter = tuple(prefilter)
        self.context_positive = context_positive
        self.context_negative = context_negative
        self.context_window = context_window

    @classmethod
    def from_spec(cls, spec: Mapping[str, Any]) -> "Detector":
        """Compile one detector entry of an FRS-1 pack."""
        try:
            identifier = str(spec["id"])
            raw_pattern = str(spec["pattern"])
            risk = str(spec["risk"])
            confidence = float(spec["confidence"])
            mask_spec = spec["mask"]
            label = str(spec["label"])
            why = str(spec["why"])
            default = bool(spec["default"])
        except KeyError as exc:
            raise PackError(f"detector is missing required field {exc.args[0]!r}") from exc

        where = f"detector {identifier!r}"
        if risk not in _RISKS:
            raise PackError(f"{where}: risk must be one of {_RISKS}")
        if not 0.0 <= confidence <= 1.0:
            raise PackError(f"{where}: confidence must be between 0 and 1")

        flags = str(spec.get("flags", ""))
        if flags not in ("", "i"):
            raise PackError(f"{where}: only the 'i' flag is portable")

        regex = _compile(raw_pattern, flags, where)
        if regex.match("") is not None:
            raise PackError(f"{where}: pattern matches the empty string")

        capture = int(spec.get("capture", 0))
        if capture > (regex.groups or 0):
            raise PackError(f"{where}: capture group {capture} does not exist")

        boundary = spec.get("boundary") or {}
        context = spec.get("context") or {}

        return cls(
            id=identifier,
            label=label,
            why=why,
            regex=regex,
            mask=_build_mask(mask_spec, where),
            risk=risk,
            confidence=confidence,
            default=default,
            capture=capture,
            before=_boundary_test(boundary.get("before"), where),
            after=_boundary_test(boundary.get("after"), where),
            reject=[_compile(str(p), flags, f"{where} reject", portable=False) for p in spec.get("reject", ())],
            validators=[_build_validator(v, where) for v in spec.get("validators", ())],
            tags=[str(t) for t in spec.get("tags", ())],
            priority=int(spec.get("priority", 0)),
            refine=bool(spec.get("refine", False)),
            prefilter=[str(p).lower() for p in spec.get("prefilter", ())],
            context_positive=(
                _compile(str(context["positive"]), "i", f"{where} context", portable=False)
                if context.get("positive")
                else None
            ),
            context_negative=(
                _compile(str(context["negative"]), "i", f"{where} context", portable=False)
                if context.get("negative")
                else None
            ),
            context_window=int(context.get("window", 80)),
        )

    def matches_selector(self, selector: str) -> bool:
        """True when ``selector`` names this detector directly or one of its tags."""
        return selector == self.id or selector in self.tags

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Detector {self.id} risk={self.risk} default={self.default}>"


def _boundary_test(name: Optional[str], where: str) -> Optional[BoundaryTest]:
    if name is None:
        return None
    members = BOUNDARY_CLASSES.get(name)
    if members is None:
        raise PackError(f"{where}: unknown boundary class {name!r}")
    return members.__contains__


class Pack:
    """A loaded, compiled detector pack."""

    __slots__ = ("id", "version", "title", "detectors", "by_id", "confidence_model")

    def __init__(self, document: Mapping[str, Any]) -> None:
        spec = document.get("spec")
        if spec != SPEC_REVISION:
            raise PackError(
                f"unsupported pack revision {spec!r}; this engine implements {SPEC_REVISION}"
            )
        self.id = str(document.get("id", "anonymous"))
        self.version = str(document.get("version", "0"))
        self.title = str(document.get("title", self.id))

        raw_detectors = document.get("detectors")
        if not isinstance(raw_detectors, Sequence) or not raw_detectors:
            raise PackError("a pack must declare at least one detector")

        detectors: List[Detector] = []
        seen: Dict[str, int] = {}
        for position, raw in enumerate(raw_detectors):
            detector = Detector.from_spec(raw)
            if detector.id in seen:
                raise PackError(f"duplicate detector id {detector.id!r}")
            seen[detector.id] = position
            detectors.append(detector)
        self.detectors: Tuple[Detector, ...] = tuple(detectors)
        self.by_id: Dict[str, Detector] = {d.id: d for d in detectors}

        model = document.get("confidenceModel")
        self.confidence_model: Optional[ConfidenceModel] = (
            ConfidenceModel(
                version=int(model["version"]),
                features=tuple(model["features"]),
                weights=tuple(model["weights"]),
                bias=float(model["bias"]),
            )
            if model
            else None
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Pack {self.id}@{self.version} detectors={len(self.detectors)}>"


def load_pack(source: Any) -> Pack:
    """Load a pack from a path, an open file, a JSON string, or a mapping."""
    if isinstance(source, Pack):
        return source
    if isinstance(source, Mapping):
        return Pack(source)
    if hasattr(source, "read"):
        return Pack(json.load(source))
    text = os.fspath(source) if isinstance(source, os.PathLike) else str(source)
    if text.lstrip().startswith("{"):
        return Pack(json.loads(text))
    with open(text, "r", encoding="utf-8") as handle:
        return Pack(json.load(handle))


_CORE: Optional[Pack] = None


def core_pack() -> Pack:
    """The bundled ``flare-redact/core`` pack, compiled once per process."""
    global _CORE
    if _CORE is None:
        _CORE = load_pack(_CORE_PACK_PATH)
    return _CORE
