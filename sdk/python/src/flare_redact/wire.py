"""Translation between Python options and the gateway's JSON wire format.

The gateway speaks the JavaScript library's option names (camelCase). Keeping the
translation in one small module means the Python API can stay Pythonic without
the two drifting.

One deliberate omission: ``transform_secret`` is never serialised. A keyed
transform's whole value is that the key stays where it was configured; shipping
it to a sidecar on every request would defeat that. Configure the secret on the
gateway instead.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Mapping, Union

from .engine import Finding, Options

__all__ = [
    "options_to_wire", "options_from_wire", "finding_from_wire", "finding_to_wire",
    "UnserializableOptionError",
]

_SIMPLE_FIELDS = (
    ("only", "only"),
    ("enable", "enable"),
    ("disable", "disable"),
    ("mode", "mode"),
    ("terms", "terms"),
    ("terms_case_sensitive", "termsCaseSensitive"),
    ("min_confidence", "minConfidence"),
    ("refine_confidence", "refineConfidence"),
    ("include_values", "includeValues"),
)

_DEFAULTS = Options()


class UnserializableOptionError(TypeError):
    """Raised when an option cannot cross a process boundary."""


def options_to_wire(options: Union[Options, Mapping[str, Any], None]) -> Dict[str, Any]:
    """Serialise options for ``POST /v1/redact``, omitting anything at its default."""
    resolved = Options.coerce(options)
    wire: Dict[str, Any] = {}

    for python_name, wire_name in _SIMPLE_FIELDS:
        value = getattr(resolved, python_name)
        if value != getattr(_DEFAULTS, python_name):
            wire[wire_name] = list(value) if isinstance(value, tuple) else value

    if isinstance(resolved.mask, str):
        wire["mask"] = resolved.mask
    elif callable(resolved.mask):
        raise UnserializableOptionError(
            "A callable mask cannot be sent to the gateway; redact locally or use a mask string."
        )

    if resolved.redact_keys is not True:
        if isinstance(resolved.redact_keys, re.Pattern):
            raise UnserializableOptionError(
                "A compiled redact_keys pattern cannot be sent to the gateway; pass an exact list."
            )
        wire["redactKeys"] = (
            list(resolved.redact_keys) if not isinstance(resolved.redact_keys, bool) else resolved.redact_keys
        )

    if resolved.allow is not None:
        if isinstance(resolved.allow, re.Pattern):
            raise UnserializableOptionError(
                "A compiled allow pattern cannot be sent to the gateway; pass an exact list."
            )
        wire["allow"] = list(resolved.allow)

    limits: Dict[str, int] = {}
    if resolved.max_input_length != _DEFAULTS.max_input_length:
        limits["maxInputLength"] = resolved.max_input_length
    if resolved.max_findings != _DEFAULTS.max_findings:
        limits["maxFindings"] = resolved.max_findings
    if limits:
        wire["limits"] = limits

    return wire


def options_from_wire(payload: Mapping[str, Any]) -> Options:
    """Build options from the JSON wire format used by the gateway and the corpus.

    Unlike :func:`options_to_wire`, this *does* accept ``transformSecret``: a
    gateway may be configured with one, and the conformance corpus needs fixed
    keyed-transform vectors.
    """
    limits = payload.get("limits") or {}
    known = {
        "only", "enable", "disable", "mode", "mask", "transformSecret", "redactKeys",
        "allow", "terms", "termsCaseSensitive", "minConfidence", "refineConfidence",
        "includeValues", "limits",
    }
    unknown = set(payload) - known
    if unknown:
        raise ValueError(f"unknown options: {', '.join(sorted(unknown))}")

    defaults = Options()
    return Options(
        only=payload.get("only"),
        enable=payload.get("enable"),
        disable=payload.get("disable"),
        mode=payload.get("mode", defaults.mode),
        mask=payload.get("mask"),
        transform_secret=payload.get("transformSecret"),
        redact_keys=payload.get("redactKeys", defaults.redact_keys),
        allow=payload.get("allow"),
        terms=payload.get("terms"),
        terms_case_sensitive=bool(payload.get("termsCaseSensitive", defaults.terms_case_sensitive)),
        min_confidence=float(payload.get("minConfidence", defaults.min_confidence)),
        refine_confidence=bool(payload.get("refineConfidence", defaults.refine_confidence)),
        include_values=bool(payload.get("includeValues", defaults.include_values)),
        max_input_length=int(limits.get("maxInputLength", defaults.max_input_length)),
        max_findings=int(limits.get("maxFindings", defaults.max_findings)),
    )


def finding_to_wire(finding: Finding) -> Dict[str, Any]:
    """Serialise a finding using the wire field names."""
    return finding.to_dict()


def finding_from_wire(payload: Mapping[str, Any]) -> Finding:
    """Rebuild a :class:`Finding` from the gateway's JSON representation."""
    return Finding(
        detector=str(payload.get("detector", "")),
        label=str(payload.get("label", "")),
        why=str(payload.get("why", "")),
        risk=str(payload.get("risk", "high")),
        confidence=float(payload.get("confidence", 0.0)),
        start=payload.get("start"),
        end=payload.get("end"),
        line=payload.get("line"),
        column=payload.get("column"),
        path=payload.get("path"),
        value=payload.get("value"),
    )
