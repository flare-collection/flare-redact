"""Keyed, shape-preserving replacements: pseudonyms and typed surrogates.

Masking destroys a dataset for analytics: every card becomes ``**** 1234`` and
joins stop working. These transforms keep the *shape* and the *distinctness* of
a value while removing its meaning, so a staging database still exercises the
same code paths as production.

Neither transform is reversible. If you need the original back, use a vault.
"""

from __future__ import annotations

import re
from typing import Callable, Dict

from .crypto import derive_bytes, hmac_fingerprint

__all__ = ["pseudonymize", "surrogate"]

_LOWER = "abcdefghijklmnopqrstuvwxyz"
_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_DIGITS = "0123456789"
_GIVEN_NAMES = ("Alex", "Avery", "Casey", "Emery", "Jordan", "Morgan", "Riley", "Robin")
_FAMILY_NAMES = ("Arden", "Blake", "Hayes", "Lane", "Parker", "Reed", "Shaw", "Vale")
_STREETS = ("Cedar", "Harbor", "Juniper", "Maple", "Orchard", "River", "Willow", "Summit")


def _alphabet_for(ch: str) -> str:
    if "0" <= ch <= "9":
        return _DIGITS
    if "a" <= ch <= "z":
        return _LOWER
    if "A" <= ch <= "Z":
        return _UPPER
    return ""


def pseudonymize(value: str, secret: str) -> str:
    """Deterministic, keyed, shape-preserving substitution.

    Deliberately not called format-preserving encryption: it is not reversible
    and does not implement NIST FF1. It is a stable pseudonym — the same input
    and key always give the same output, so joins survive.
    """
    stream = derive_bytes(secret, f"pseudonym:{value}", len(value))
    out = []
    for index, ch in enumerate(value):
        alphabet = _alphabet_for(ch)
        out.append(alphabet[stream[index] % len(alphabet)] if alphabet else ch)
    return "".join(out)


def _digit_surrogate(value: str, secret: str) -> str:
    stream = derive_bytes(secret, f"digits:{value}", len(value))
    return "".join(
        _DIGITS[stream[index] % 10] if "0" <= ch <= "9" else ch
        for index, ch in enumerate(value)
    )


def _luhn_check_digit(prefix: str) -> str:
    digits = re.sub(r"[^0-9]", "", prefix)
    total = 0
    double = True
    for ch in reversed(digits):
        n = int(ch)
        if double:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        double = not double
    return str((10 - (total % 10)) % 10)


def _card_surrogate(value: str, secret: str) -> str:
    shaped = _digit_surrogate(value, secret)
    last = -1
    for index, ch in enumerate(shaped):
        if "0" <= ch <= "9":
            last = index
    if last < 0:
        return shaped
    prefix = shaped[:last]
    return prefix + _luhn_check_digit(prefix) + shaped[last + 1 :]


def _email_surrogate(value: str, secret: str) -> str:
    return f"user_{hmac_fingerprint(secret, f'email:{value}', 6)}@example.invalid"


def _person_surrogate(value: str, secret: str) -> str:
    stream = derive_bytes(secret, f"person:{value}", 2)
    return f"{_GIVEN_NAMES[stream[0] % len(_GIVEN_NAMES)]} {_FAMILY_NAMES[stream[1] % len(_FAMILY_NAMES)]}"


def _address_surrogate(value: str, secret: str) -> str:
    stream = derive_bytes(secret, f"address:{value}", 3)
    number = 100 + (((stream[0] << 8) | stream[1]) % 9800)
    return f"{number} {_STREETS[stream[2] % len(_STREETS)]} Street"


_SURROGATES: Dict[str, Callable[[str, str], str]] = {
    "email": _email_surrogate,
    "credit_card": _card_surrogate,
    "phone": _digit_surrogate,
    "person_name": _person_surrogate,
    "street_address": _address_surrogate,
}


def surrogate(value: str, detector_id: str, secret: str) -> str:
    """A deterministic, type-consistent synthetic value for local test data."""
    builder = _SURROGATES.get(detector_id)
    return builder(value, secret) if builder else pseudonymize(value, secret)
