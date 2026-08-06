"""flare-redact — hide secrets and PII before they reach a log, a model, or a vendor.

Zero-dependency secret and PII redaction for Python, implementing the same
FRS-1 detector spec as the JavaScript, Go and Rust engines. The same pack, the
same options and the same input produce the same output in every one of them, so
a policy written once holds across a polyglot system.

    from flare_redact import redact, scan, compile_policy

    redact("contact me at ada@example.com")
    # 'contact me at a***@***'

    policy = compile_policy(enable=["pii"], mode="label")
    policy.redact({"user": {"email": "ada@example.com"}})
    # {'user': {'email': '[REDACTED:email]'}}

For a chat or agent loop, use a session so the model never sees the data but
your user still gets the right answer:

    from flare_redact import create_session

    session = create_session(enable=["pii"])
    safe = session.redact(user_message)      # send this to the model
    reply = session.restore(model_reply)     # show this to the user
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Union

from .checksums import luhn, shannon_entropy
from .crypto import derive_bytes, hmac_fingerprint
from .engine import (
    DEFAULT_MAX_FINDINGS,
    DEFAULT_MAX_INPUT_LENGTH,
    MODES,
    Finding,
    FlareRedactError,
    Options,
    Policy,
    RedactionLimitError,
    compile_policy,
    is_clean,
    redact,
    scan,
    summarize,
    summary,
)
from .keywords import MULTILANG_KEY_SET, SECRET_KEYWORDS
from .ml import extract_features, secret_probability
from .pack import Detector, Pack, PackError, core_pack, load_pack
from .transforms import pseudonymize, surrogate
from .vault import Session, StreamRestorer, Vault, build_restore, restore

__version__ = "1.5.0"

#: The FRS-1 revision this engine implements.
SPEC_REVISION = "FRS-1"

__all__ = [
    "__version__",
    "SPEC_REVISION",
    # core
    "redact",
    "scan",
    "is_clean",
    "summary",
    "summarize",
    "compile_policy",
    "Policy",
    "Options",
    "Finding",
    "MODES",
    "DEFAULT_MAX_INPUT_LENGTH",
    "DEFAULT_MAX_FINDINGS",
    # reversible
    "create_vault",
    "create_session",
    "Vault",
    "Session",
    "StreamRestorer",
    "restore",
    "build_restore",
    # packs
    "Pack",
    "Detector",
    "PackError",
    "load_pack",
    "core_pack",
    # transforms and helpers
    "pseudonymize",
    "surrogate",
    "hmac_fingerprint",
    "derive_bytes",
    "luhn",
    "shannon_entropy",
    "extract_features",
    "secret_probability",
    "SECRET_KEYWORDS",
    "MULTILANG_KEY_SET",
    # errors
    "FlareRedactError",
    "RedactionLimitError",
]


def create_vault(
    options: Union[Options, Mapping[str, Any], None] = None,
    **kwargs: Any,
) -> Vault:
    """A reversible redactor. See :class:`~flare_redact.vault.Vault`."""
    return Vault(options, **kwargs)


def create_session(
    options: Union[Options, Mapping[str, Any], None] = None,
    **kwargs: Any,
) -> Session:
    """A conversation-scoped vault. See :class:`~flare_redact.vault.Session`."""
    return Session(options, **kwargs)
