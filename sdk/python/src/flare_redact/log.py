"""Logging integration: a filter for structured logs, a formatter for tracebacks.

Two tools, because one is not enough:

* :class:`RedactingFilter` rewrites ``record.msg`` and ``record.args`` before any
  handler sees them. It is cheap, it keeps structured fields structured, and it
  protects every handler on the logger at once.
* :class:`RedactingFormatter` wraps another formatter and redacts the final
  string. A traceback is only rendered at format time, and a secret passed to a
  function that raised is *in* that traceback — a filter alone cannot see it.

Use the filter for normal logs and add the formatter to any handler that renders
exceptions. Both share one compiled policy, so they agree on what is sensitive.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping, Optional, Sequence, Union

from .engine import Options, Policy, compile_policy

__all__ = ["RedactingFilter", "RedactingFormatter", "install"]


class RedactingFilter(logging.Filter):
    """A ``logging.Filter`` that redacts the record before it is emitted.

    The record is modified in place and always passes, so the message still gets
    logged — with the secret gone. Attach it to a *logger* (not a handler) so
    every handler downstream is covered.

        logging.getLogger().addFilter(RedactingFilter(enable=["pii"]))
    """

    def __init__(
        self,
        options: Union[Options, Mapping[str, Any], Policy, None] = None,
        *,
        extra_attributes: Sequence[str] = (),
        **overrides: Any,
    ) -> None:
        super().__init__()
        self.policy = options if isinstance(options, Policy) else compile_policy(options, **overrides)
        #: Additional ``record`` attributes to redact, for structured-logging setups
        #: that stash context on the record (``record.context``, ``record.extra``…).
        self.extra_attributes = tuple(extra_attributes)

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.policy.redact_str(record.msg)
        elif record.msg is not None:
            record.msg = self.policy.redact(record.msg)

        if record.args:
            record.args = self.policy.redact(record.args)

        if getattr(record, "exc_text", None):
            record.exc_text = self.policy.redact_str(record.exc_text)

        for name in self.extra_attributes:
            value = getattr(record, name, None)
            if value is not None:
                setattr(record, name, self.policy.redact(value))

        return True


class RedactingFormatter(logging.Formatter):
    """Wraps another formatter and redacts everything it produces.

    This is the backstop: it sees the rendered message, the traceback and any
    custom formatting, so nothing reaches the handler unredacted. It costs a scan
    of the formatted string per record, which is why the filter handles the
    common path and this handles the handlers that render exceptions.
    """

    def __init__(
        self,
        inner: Optional[logging.Formatter] = None,
        options: Union[Options, Mapping[str, Any], Policy, None] = None,
        **overrides: Any,
    ) -> None:
        super().__init__()
        self._inner = inner or logging.Formatter()
        self.policy = options if isinstance(options, Policy) else compile_policy(options, **overrides)

    def format(self, record: logging.LogRecord) -> str:
        return self.policy.redact_str(self._inner.format(record))


def install(
    logger: Optional[logging.Logger] = None,
    options: Union[Options, Mapping[str, Any], Policy, None] = None,
    *,
    formatter: bool = True,
    **overrides: Any,
) -> RedactingFilter:
    """Protect a logger in one line.

        import flare_redact.log as flare_log
        flare_log.install(enable=["pii"])

    Adds a :class:`RedactingFilter` to ``logger`` (the root logger by default)
    and, unless ``formatter=False``, wraps each of its handlers' formatters so
    tracebacks are covered too. Returns the filter, so you can remove it again.
    """
    target = logger or logging.getLogger()
    policy = options if isinstance(options, Policy) else compile_policy(options, **overrides)
    redacting_filter = RedactingFilter(policy)
    target.addFilter(redacting_filter)
    if formatter:
        for handler in target.handlers:
            if isinstance(handler.formatter, RedactingFormatter):
                continue
            handler.setFormatter(RedactingFormatter(handler.formatter, policy))
    return redacting_filter
