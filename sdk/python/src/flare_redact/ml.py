"""The learned secret-confidence classifier.

Pattern-only detection over-fires on high-entropy text: a git SHA, a UUID, a
content digest and an API key all look alike to a character-class matcher. This
is a 14-feature logistic regression that scores how likely a match is a real
secret, so ``refine_confidence`` can push benign look-alikes below a threshold
instead of masking them.

The weights ship inside the detector pack, so scoring stays dependency-free,
synchronous and identical across languages. Inference is one feature pass and a
dot product — no matrix library, no model download.
"""

from __future__ import annotations

import math
import re
from typing import List, Sequence

from .checksums import shannon_entropy

__all__ = ["FEATURES", "extract_features", "secret_probability", "ConfidenceModel"]

#: Feature names, in the exact order ``extract_features`` returns them.
FEATURES = (
    "log2Len", "entropy", "fracLower", "fracUpper", "fracDigit", "fracSymbol",
    "fracHex", "vowelFrac", "classTransitionRate", "hasMixedClasses",
    "maxRunFrac", "structuredHexId", "ctxSecret", "ctxBenign",
)

_SECRET_CTX = re.compile(
    r"\b(secret|api[_-]?key|apikey|token|password|passwd|pwd|auth|authorization|bearer"
    r"|access[_-]?key|private[_-]?key|client[_-]?secret|credential|signing[_-]?key)\b",
    re.IGNORECASE,
)
_BENIGN_CTX = re.compile(
    r"\b(uuid|guid|sha1|sha256|sha512|md5|hash|digest|etag|checksum|commit|revision"
    r"|request[_-]?id|trace[_-]?id|correlation[_-]?id|span[_-]?id|object[_-]?id"
    r"|content[_-]?id|version|colou?r|slug|filename)\b",
    re.IGNORECASE,
)
_STRUCTURED_HEX = re.compile(
    r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|[0-9a-f]{24}|[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})",
    re.IGNORECASE,
)

_VOWELS = frozenset("aeiouAEIOU")


class ConfidenceModel:
    """Logistic-regression weights loaded from a detector pack."""

    __slots__ = ("version", "features", "weights", "bias")

    def __init__(self, version: int, features: Sequence[str], weights: Sequence[float], bias: float) -> None:
        if len(weights) != len(features):
            raise ValueError("Confidence model weights and features must have the same length.")
        if tuple(features) != FEATURES:
            raise ValueError(
                "Confidence model feature layout does not match this engine; "
                f"expected {FEATURES!r}, received {tuple(features)!r}."
            )
        self.version = version
        self.features = tuple(features)
        self.weights = tuple(float(w) for w in weights)
        self.bias = float(bias)


def extract_features(value: str, context: str = "") -> List[float]:
    """Cheap character-level features for ``value``, informed by nearby text."""
    length = len(value) or 1
    lower = upper = digit = symbol = hexish = vowel = letters = 0
    transitions = 0
    run = 1
    max_run = 1
    prev_class = -1

    for ch in value:
        code = ord(ch)
        if 97 <= code <= 122:
            lower += 1
            letters += 1
        elif 65 <= code <= 90:
            upper += 1
            letters += 1
        elif 48 <= code <= 57:
            digit += 1
        else:
            symbol += 1
        if (48 <= code <= 57) or (97 <= code <= 102) or (65 <= code <= 70):
            hexish += 1
        if ch in _VOWELS:
            vowel += 1
        cls = 1 if 48 <= code <= 57 else 0 if (97 <= code <= 122 or 65 <= code <= 90) else 2
        if prev_class == -1:
            prev_class = cls
        else:
            if cls != prev_class:
                transitions += 1
                run = 1
            else:
                run += 1
            if run > max_run:
                max_run = run
            prev_class = cls

    return [
        math.log2(length),
        shannon_entropy(value),
        lower / length,
        upper / length,
        digit / length,
        symbol / length,
        hexish / length,
        (vowel / letters) if letters else 0.0,
        (transitions / (length - 1)) if length > 1 else 0.0,
        1.0 if lower > 0 and upper > 0 and digit > 0 else 0.0,
        max_run / length,
        1.0 if _STRUCTURED_HEX.fullmatch(value) else 0.0,
        1.0 if _SECRET_CTX.search(context) else 0.0,
        1.0 if _BENIGN_CTX.search(context) else 0.0,
    ]


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def secret_probability(value: str, context: str, model: ConfidenceModel) -> float:
    """Probability in [0, 1] that ``value`` is a secret rather than a look-alike."""
    features = extract_features(value, context)
    z = model.bias
    for weight, feature in zip(model.weights, features):
        z += weight * feature
    return _sigmoid(z)
