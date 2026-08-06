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

from typing import Any, Iterator, Mapping, Union

from .engine import Options
from .vault import Vault

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


def _restore_stream(stream: Any, vault: Vault, text_paths: Any) -> Iterator[Any]:
    """Yield stream events with any text delta restored, span-safe across chunks."""
    restorers: dict = {}

    def restore(key: str, text: str) -> str:
        restorer = restorers.get(key)
        if restorer is None:
            restorer = vault.stream()
            restorers[key] = restorer
        return restorer.push(text)

    for event in stream:
        yield text_paths(event, restore)
    # Anything held back for a possible split placeholder is dropped here rather
    # than silently lost: callers that need it should use the non-streaming path.
    for restorer in restorers.values():
        restorer.flush()


def _openai_restore_event(event: Any, restore: Any) -> Any:
    choices = getattr(event, "choices", None)
    if not choices:
        return event
    for position, choice in enumerate(choices):
        delta = getattr(choice, "delta", None)
        if delta is None:
            continue
        index = getattr(choice, "index", position)
        content = getattr(delta, "content", None)
        if isinstance(content, str) and content:
            try:
                delta.content = restore(f"choice:{index}:content", content)
            except (AttributeError, TypeError):  # frozen model objects
                pass
    return event


def _anthropic_restore_event(event: Any, restore: Any) -> Any:
    delta = getattr(event, "delta", None)
    if delta is None:
        return event
    index = getattr(event, "index", 0)
    text = getattr(delta, "text", None)
    if isinstance(text, str) and text:
        try:
            delta.text = restore(f"text:{index}", text)
        except (AttributeError, TypeError):
            pass
    return event


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
            return _restore_stream(result, vault, _openai_restore_event)
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
            return _restore_stream(result, vault, _anthropic_restore_event)
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
