"""Drop-in wrappers for the clients AI and ML teams already use.

Each wrapper redacts what leaves the process and restores what comes back, using
one session per call, so the model sees placeholders and your code sees the real
values. Nothing else about the client changes: the same methods, the same
parameters, the same return types, streaming included.

    from openai import OpenAI
    from flare_redact.integrations import wrap_openai

    client = wrap_openai(OpenAI(), enable=["pii"])
    client.chat.completions.create(model="gpt-4o", messages=[...])

These wrappers are duck-typed on purpose: they never import the vendor SDK, so
this package stays dependency-free and keeps working across client versions.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Set, Tuple, Union

from .engine import Options
from .vault import StreamRestorer, Vault, requests_json_output

__all__ = ["wrap_openai", "wrap_anthropic", "redact_messages"]

_WRAPPED = "__flare_redact_wrapped__"


def redact_messages(
    messages: Any,
    options: Union[Options, Mapping[str, Any], None] = None,
    **overrides: Any,
) -> Any:
    """Redact a chat message array and return it with the vault that can undo it."""
    vault = Vault(options, **overrides)
    return vault.redact(messages), vault


def _get(owner: Any, name: str) -> Any:
    if isinstance(owner, Mapping):
        return owner.get(name)
    return getattr(owner, name, None)


def _set(owner: Any, name: str, value: Any) -> bool:
    try:
        if isinstance(owner, dict):
            owner[name] = value
        else:
            setattr(owner, name, value)
    except (AttributeError, TypeError):  # frozen model objects
        return False
    return True


#: A text field of one stream event: (owner, attribute, restorer key, JSON text?).
Field = Tuple[Any, str, str, bool]


def _restore_stream(stream: Any, vault: Vault, fields_of: Callable[[Any], List[Field]]) -> Iterator[Any]:
    """Yield stream events with their text fields restored, span-safe across chunks.

    Each field (a choice's content, one tool call's arguments, a content block's
    text or partial JSON) has its own restorer, so a placeholder split across
    events is rebuilt. Fields whose text is JSON get the originals JSON-escaped.
    An event whose field ends in what could be the start of a placeholder is
    held until the next event; if that one does not continue the field, the
    held-back text is put back into the held event before it is yielded, so
    nothing is lost and events keep their order.
    """
    restorers: Dict[str, StreamRestorer] = {}
    held: Optional[Tuple[Any, List[Tuple[Any, str, str]]]] = None

    def release(continuing: Set[str]) -> Any:
        nonlocal held
        if held is None:
            return None
        event, fields = held
        held = None
        for owner, name, key in fields:
            if key in continuing:
                continue
            tail = restorers[key].flush()
            if tail:
                _set(owner, name, (_get(owner, name) or "") + tail)
        return event

    for event in stream:
        fields = fields_of(event)
        previous = release({key for _, _, key, _ in fields})
        if previous is not None:
            yield previous
        restored: List[Tuple[Any, str, str]] = []
        for owner, name, key, json in fields:
            restorer = restorers.get(key)
            if restorer is None:
                restorer = restorers[key] = vault.stream(json=json)
            if _set(owner, name, restorer.push(_get(owner, name))):
                restored.append((owner, name, key))
        if any(restorers[key].pending for _, _, key in restored):
            held = (event, restored)
        else:
            yield event
    previous = release(set())
    if previous is not None:
        yield previous


def _openai_fields(json_output: bool) -> Callable[[Any], List[Field]]:
    """Content deltas (JSON in JSON mode) and tool-call argument deltas (always JSON)."""
    def fields(event: Any) -> List[Field]:
        out: List[Field] = []
        for position, choice in enumerate(_get(event, "choices") or ()):
            delta = _get(choice, "delta")
            if delta is None:
                continue
            index = _get(choice, "index")
            index = position if index is None else index
            if isinstance(_get(delta, "content"), str) and _get(delta, "content"):
                out.append((delta, "content", f"choice:{index}:content", json_output))
            for call_position, call in enumerate(_get(delta, "tool_calls") or ()):
                function = _get(call, "function")
                if function is not None and isinstance(_get(function, "arguments"), str) and _get(function, "arguments"):
                    call_index = _get(call, "index")
                    call_index = call_position if call_index is None else call_index
                    out.append((function, "arguments", f"choice:{index}:tool:{call_index}", True))
        return out

    return fields


def _anthropic_fields(json_output: bool) -> Callable[[Any], List[Field]]:
    """Text deltas (JSON for structured output) and partial tool input (always JSON)."""
    def fields(event: Any) -> List[Field]:
        delta = _get(event, "delta")
        if delta is None:
            return []
        index = _get(event, "index") or 0
        out: List[Field] = []
        if isinstance(_get(delta, "text"), str) and _get(delta, "text"):
            out.append((delta, "text", f"text:{index}", json_output))
        if isinstance(_get(delta, "partial_json"), str) and _get(delta, "partial_json"):
            out.append((delta, "partial_json", f"json:{index}", True))
        return out

    return fields


def wrap_openai(client: Any, options: Union[Options, Mapping[str, Any], None] = None, **overrides: Any) -> Any:
    """Redact prompts and restore replies for an OpenAI-compatible client.

    Mutates and returns ``client``. Wrapping twice is a no-op, so this is safe to
    call from library code that cannot know whether the caller already did.
    """
    completions = getattr(getattr(client, "chat", None), "completions", None)
    if completions is None or not callable(getattr(completions, "create", None)):
        raise TypeError("wrap_openai: expected a client with chat.completions.create")
    if getattr(completions, _WRAPPED, False):
        return client

    original = completions.create

    def create(*args: Any, **kwargs: Any) -> Any:
        vault = Vault(options, **overrides)
        if "messages" in kwargs:
            kwargs["messages"] = vault.redact(kwargs["messages"])
        result = original(*args, **kwargs)
        if kwargs.get("stream"):
            return _restore_stream(result, vault, _openai_fields(requests_json_output(kwargs)))
        return vault.restore(result) if isinstance(result, (str, list, dict)) else _restore_object(result, vault)

    completions.create = create
    setattr(completions, _WRAPPED, True)
    return client


def wrap_anthropic(client: Any, options: Union[Options, Mapping[str, Any], None] = None, **overrides: Any) -> Any:
    """Redact prompts and restore replies for an Anthropic-compatible client.

    Mutates and returns ``client``. Wrapping twice is a no-op.
    """
    messages = getattr(client, "messages", None)
    if messages is None or not callable(getattr(messages, "create", None)):
        raise TypeError("wrap_anthropic: expected a client with messages.create")
    if getattr(messages, _WRAPPED, False):
        return client

    original = messages.create

    def create(*args: Any, **kwargs: Any) -> Any:
        vault = Vault(options, **overrides)
        if "messages" in kwargs:
            kwargs["messages"] = vault.redact(kwargs["messages"])
        if "system" in kwargs:
            kwargs["system"] = vault.redact(kwargs["system"])
        result = original(*args, **kwargs)
        if kwargs.get("stream"):
            return _restore_stream(result, vault, _anthropic_fields(requests_json_output(kwargs)))
        return vault.restore(result) if isinstance(result, (str, list, dict)) else _restore_object(result, vault)

    messages.create = create
    setattr(messages, _WRAPPED, True)
    return client


def _restore_object(result: Any, vault: Vault) -> Any:
    """Restore inside a vendor response object without assuming its shape.

    Vendor SDKs return pydantic-ish models. Where one exposes ``model_dump`` we
    restore the plain data and hand that back; otherwise we walk its ``__dict__``
    in place. Either way the caller gets their real values, and an unknown shape
    degrades to "unchanged" rather than to an exception in the request path.
    """
    dump = getattr(result, "model_dump", None)
    if callable(dump):
        try:
            return vault.restore(dump())
        except Exception:  # pragma: no cover - vendor-specific failure modes
            pass
    state = getattr(result, "__dict__", None)
    if isinstance(state, dict):
        for key, value in list(state.items()):
            if isinstance(value, (str, list, dict)):
                state[key] = vault.restore(value)
    return result
