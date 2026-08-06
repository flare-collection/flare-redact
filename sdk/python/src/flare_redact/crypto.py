"""Keyed primitives shared by the hash, pseudonym and surrogate modes.

Everything here is HMAC-SHA256 over the caller's ``transform_secret``. There is
no key stretching and no salt: the point is a *deterministic* mapping, so the
same value produces the same output on every host and in every language, which
is what makes a pseudonymised dataset joinable. That also means the secret is
the only thing standing between the output and a dictionary attack on a small
domain, so it has to be a real secret — see ``spec/SPEC.md`` §8.
"""

from __future__ import annotations

import hashlib
import hmac

__all__ = ["hmac_sha256", "hmac_fingerprint", "derive_bytes"]


class MissingSecretError(ValueError):
    """Raised when a keyed transform is requested without a secret."""


def _key_bytes(secret: str) -> bytes:
    if not secret:
        raise MissingSecretError(
            "A non-empty transform_secret is required for deterministic protected transforms."
        )
    return secret.encode("utf-8")


def hmac_sha256(secret: str, message: str) -> bytes:
    """Raw HMAC-SHA256 digest of ``message`` under ``secret``."""
    return hmac.new(_key_bytes(secret), message.encode("utf-8"), hashlib.sha256).digest()


def hmac_fingerprint(secret: str, value: str, length: int = 16) -> str:
    """Lowercase hex of the first ``length`` bytes of HMAC-SHA256(secret, value)."""
    return hmac_sha256(secret, value)[:length].hex()


def derive_bytes(secret: str, context: str, length: int) -> bytes:
    """Expand ``secret`` into ``length`` bytes bound to ``context``.

    Counter-mode HMAC, matching ``deriveBytes`` in the reference implementation
    byte for byte: block *i* is ``HMAC(secret, context + "\\x00" + str(i))``.
    """
    if length <= 0:
        return b""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hmac_sha256(secret, f"{context}\x00{counter}")
        counter += 1
    return bytes(out[:length])
