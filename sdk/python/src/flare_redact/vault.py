"""Reversible redaction: vaults, sessions and stream restoration.

Masking is one-way, which is the right default for logs and the wrong one for a
model call. A vault swaps each secret for a stable opaque placeholder and
remembers the mapping, so you can send the redacted text to a model and put the
originals back into its answer. The model never sees the data; your user still
gets the right reply.

Placeholders are opaque by default — random, not numbered — so the text that
leaves your process does not also disclose how many distinct people or secrets
the conversation involves.
"""

from __future__ import annotations

import json as _json
import re
import secrets
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from .engine import (
    Options, allow_matcher, key_matcher, map_graph, resolve_detectors, scan_string,
)

__all__ = [
    "Vault", "Session", "StreamRestorer", "build_restore", "build_json_aware_restore",
    "escape_entries_for_json", "is_json_document", "requests_json_output", "restore",
]

PlaceholderFn = Callable[[str, int], str]


def _opaque_placeholder(detector_id: str, _index: int) -> str:
    return f"[FR_{detector_id.upper()}_{secrets.token_hex(12)}]"


def _readable_placeholder(detector_id: str, index: int) -> str:
    return f"[{detector_id.upper()}_{index}]"


def build_restore(entries: Sequence[Tuple[str, str]]) -> Callable[[str], str]:
    """A single-pass restorer for placeholder → original pairs.

    Longer placeholders are matched first, so a token that is a prefix of another
    cannot clobber its peer and restore the wrong secret.
    """
    if not entries:
        return lambda text: text
    ordered = sorted(entries, key=lambda pair: -len(pair[0]))
    lookup = dict(ordered)
    pattern = re.compile("|".join(re.escape(placeholder) for placeholder, _ in ordered))
    return lambda text: pattern.sub(lambda m: lookup.get(m.group(0), m.group(0)), text)


_JSON_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}
_NEEDS_ESCAPE = re.compile(r'["\\\x00-\x1f\ud800-\udfff]')
_JSON_WHITESPACE = " \t\n\r"


def _json_escape(value: str) -> str:
    """``value`` as it must appear inside a JSON string literal (FRS-1 §11)."""
    return _NEEDS_ESCAPE.sub(lambda m: _JSON_ESCAPES.get(m.group(0)) or f"\\u{ord(m.group(0)):04x}", value)


def escape_entries_for_json(entries: Sequence[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Each original escaped for the inside of a JSON string literal.

    A placeholder can only sit inside a string in valid JSON, so an original
    spliced in this form keeps the JSON valid, and quotes, backslashes or control
    characters in it cannot end the string and add or replace fields.
    """
    return [(placeholder, _json_escape(original)) for placeholder, original in entries]


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def is_json_document(text: str) -> bool:
    """True when ``text`` is a complete JSON object or array."""
    if text.lstrip(_JSON_WHITESPACE)[:1] not in ("{", "["):
        return False
    try:
        _json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        return False
    return True


def build_json_aware_restore(entries: Sequence[Tuple[str, str]]) -> Callable[[str], str]:
    """:func:`build_restore`, except that a string which is a JSON object or array
    (tool-call arguments, JSON-mode output) gets its originals JSON-escaped, so it
    is still valid JSON with the same structure after the restore."""
    if not entries:
        return lambda text: text
    plain = build_restore(entries)
    escaped: List[Callable[[str], str]] = []

    def restore_text(text: str) -> str:
        restored = plain(text)
        if restored == text or not is_json_document(text):
            return restored
        if not escaped:
            escaped.append(build_restore(escape_entries_for_json(entries)))
        return escaped[0](text)

    return restore_text


def _format_type(value: Any) -> Any:
    if isinstance(value, Mapping):
        return value.get("type")
    return getattr(value, "type", None)


def _field(value: Any, name: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(name)
    return getattr(value, name, None)


def requests_json_output(request: Any) -> bool:
    """Whether a model request asks for JSON output, so the answer text is JSON.

    OpenAI ``response_format`` (Chat Completions) or ``text.format`` (Responses),
    Anthropic ``output_config.format`` or the beta ``output_format``.
    """
    if request is None:
        return False
    openai = (_format_type(_field(request, "response_format")), _format_type(_field(_field(request, "text"), "format")))
    anthropic = (_format_type(_field(_field(request, "output_config"), "format")), _format_type(_field(request, "output_format")))
    return any(kind in ("json_object", "json_schema") for kind in openai) or "json_schema" in anthropic


class StreamRestorer:
    """Restores placeholders in a stream, even when one is split across chunks.

    The restorer holds back the longest suffix of what it has buffered that could
    still turn out to be the start of a placeholder. Everything before that is
    safe to emit immediately, so a token streamed as ``[FR_EMA`` + ``IL_ab…]``
    is still restored exactly once.

    ``json=True`` is for a stream whose text is JSON (tool-call arguments,
    partial tool input, JSON-mode output): the originals go in JSON-escaped, so
    the assembled text stays valid JSON and a restored value cannot add or
    replace fields in it.
    """

    __slots__ = ("_restore", "_placeholders", "_buffer")

    def __init__(self, entries: Sequence[Tuple[str, str]], *, json: bool = False) -> None:
        if json:
            entries = escape_entries_for_json(entries)
        self._restore = build_restore(entries)
        self._placeholders = [placeholder for placeholder, _ in entries]
        self._buffer = ""

    def _pending_prefix_length(self) -> int:
        keep = 0
        for placeholder in self._placeholders:
            limit = min(len(self._buffer), len(placeholder) - 1)
            for length in range(limit, keep, -1):
                if self._buffer.endswith(placeholder[:length]):
                    keep = length
                    break
        return keep

    def push(self, chunk: str) -> str:
        """Feed a chunk; get back the text that is safe to display now."""
        self._buffer += chunk
        keep = self._pending_prefix_length()
        cut = len(self._buffer) - keep
        emit, self._buffer = self._buffer[:cut], self._buffer[cut:]
        return self._restore(emit)

    def flush(self) -> str:
        """Emit whatever is still held back once the stream ends."""
        out = self._restore(self._buffer)
        self._buffer = ""
        return out

    @property
    def pending(self) -> bool:
        """Whether text is held back waiting for the rest of a placeholder."""
        return bool(self._buffer)


class Vault:
    """A reversible redactor: ``redact`` mints placeholders, ``restore`` undoes it.

    The same value always maps to the same placeholder within one vault, so
    references survive a round trip: "email the address in message 1" still works
    after redaction.
    """

    __slots__ = (
        "options", "_detectors", "_allow", "_match_key", "_format",
        "_by_value", "_by_placeholder", "_counts",
    )

    def __init__(
        self,
        options: Union[Options, Mapping[str, Any], None] = None,
        *,
        placeholder: Optional[PlaceholderFn] = None,
        placeholder_style: str = "opaque",
        **overrides: Any,
    ) -> None:
        if placeholder_style not in ("opaque", "readable"):
            raise ValueError("placeholder_style must be 'opaque' or 'readable'")
        self.options = Options.coerce(options, **overrides)
        self._detectors = resolve_detectors(self.options)
        self._allow = allow_matcher(self.options)
        self._match_key = key_matcher(self.options)
        self._format: PlaceholderFn = placeholder or (
            _readable_placeholder if placeholder_style == "readable" else _opaque_placeholder
        )
        self._by_value: Dict[str, str] = {}
        self._by_placeholder: Dict[str, str] = {}
        self._counts: Dict[str, int] = {}

    # -- minting ------------------------------------------------------------ #

    def _mint(self, value: str, detector_id: str) -> str:
        existing = self._by_value.get(value)
        if existing is not None:
            return existing
        index = self._counts.get(detector_id, 0) + 1
        self._counts[detector_id] = index
        placeholder = self._format(detector_id, index)
        collision = self._by_placeholder.get(placeholder)
        if collision is not None and collision != value:
            raise ValueError(f"Placeholder generator produced a duplicate token for {detector_id}.")
        self._by_value[value] = placeholder
        self._by_placeholder[placeholder] = value
        return placeholder

    def _redact_str(self, text: str) -> str:
        hits = scan_string(text, self._detectors, self._allow, self.options)
        if not hits:
            return text
        out: List[str] = []
        cursor = 0
        for hit in hits:
            out.append(text[cursor : hit.start])
            out.append(self._mint(hit.value, hit.detector.id))
            cursor = hit.end
        out.append(text[cursor:])
        return "".join(out)

    # -- public API --------------------------------------------------------- #

    def redact(self, value: Any) -> Any:
        """Replace every secret with a stable placeholder, remembering the mapping."""
        def sensitive(key: str, item: str) -> str:
            if self._match_key(key) and not self._allow(item):
                return self._mint(item, "sensitive_key")
            return self._redact_str(item)

        return map_graph(value, self._redact_str, sensitive)

    def restore(self, value: Any) -> Any:
        """Put the originals back into any text or structure.

        A string that is a JSON object or array gets the originals JSON-escaped.
        """
        restorer = build_json_aware_restore(list(self._by_placeholder.items()))
        return map_graph(value, restorer)

    def stream(self, *, json: bool = False) -> StreamRestorer:
        """A restorer for streamed output, safe across chunk boundaries.

        Pass ``json=True`` when the streamed text is JSON, such as tool-call
        arguments.
        """
        return StreamRestorer(list(self._by_placeholder.items()), json=json)

    def entries(self) -> List[Tuple[str, str]]:
        """The placeholder → original pairs minted so far."""
        return list(self._by_placeholder.items())

    def __len__(self) -> int:
        return len(self._by_placeholder)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Vault entries={len(self._by_placeholder)}>"


class Session:
    """A conversation-scoped vault for chat and agent loops.

    One session keeps one vault, so the same value maps to the same placeholder
    across every turn. Mask the user's message on the way in, restore the model's
    answer on the way out; it is model-agnostic and synchronous, and the cost
    disappears next to inference.
    """

    __slots__ = ("_options", "_kwargs", "_vault")

    def __init__(
        self,
        options: Union[Options, Mapping[str, Any], None] = None,
        **kwargs: Any,
    ) -> None:
        self._options = options
        self._kwargs = kwargs
        self._vault = Vault(options, **kwargs)

    @property
    def vault(self) -> Vault:
        """The underlying placeholder ↔ original map."""
        return self._vault

    def redact(self, value: Any) -> Any:
        """Mask a message before it reaches the model."""
        return self._vault.redact(value)

    def restore(self, value: Any) -> Any:
        """Restore the model's reply before showing it to the user."""
        return self._vault.restore(value)

    def redact_messages(self, messages: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        """Mask a whole ``[{"role": …, "content": …}]`` chat array in one call."""
        return self._vault.redact([dict(message) for message in messages])

    def stream(self, *, json: bool = False) -> StreamRestorer:
        """A restorer for a streamed reply; ``json=True`` when the text is JSON."""
        return self._vault.stream(json=json)

    def reset(self) -> None:
        """Start a fresh conversation — a new vault, no carried-over mappings."""
        self._vault = Vault(self._options, **self._kwargs)

    def __len__(self) -> int:
        return len(self._vault)


def restore(value: Any, source: Union[Vault, Mapping[str, str], Sequence[Tuple[str, str]]]) -> Any:
    """Put originals back using a vault, a mapping, or placeholder → value pairs.

    A string that is a JSON object or array gets the originals JSON-escaped.
    """
    if isinstance(source, Vault):
        entries = source.entries()
    elif isinstance(source, Mapping):
        entries = list(source.items())
    else:
        entries = list(source)
    if not entries:
        return value
    return map_graph(value, build_json_aware_restore(entries))
