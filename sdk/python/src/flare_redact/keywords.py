"""Field names that are sensitive by convention, in 24 major languages.

Structured secrets — API keys, JWTs, card numbers — carry their own shape and
are found by pattern. Word-based secrets are not: ``password``, ``密码``,
``şifrə`` and ``كلمةالمرور`` are only recognisable as *names*. This list is what
lets ``{"parola": "hunter2"}`` be redacted in an Italian codebase and
``parol: hunter2`` in an Azerbaijani log line.

Every entry is identifier-shaped, so the same list serves both roles: object key
names, and the left-hand side of an assignment.
"""

from __future__ import annotations

import re
from typing import FrozenSet, Tuple

__all__ = [
    "SECRET_KEYWORDS",
    "MULTILANG_KEY_SET",
    "SENSITIVE_KEY_PATTERN",
    "normalize_key_name",
    "is_sensitive_key_name",
]

_RAW: Tuple[str, ...] = (
    # 1. English
    "password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "api-key",
    "access_key", "access-key", "accesskey", "secret_key", "client_secret",
    "private_key", "privatekey", "credential", "credentials", "auth_token", "passphrase",
    # 2. Chinese
    "密码", "密碼", "秘密", "令牌", "密钥", "私钥", "口令",
    # 3. Hindi
    "पासवर्ड", "गुप्त", "कुंजी", "टोकन",
    # 4. Spanish
    "contraseña", "contrasena", "clave", "secreto", "credencial",
    # 5. Arabic
    "كلمةالمرور", "كلمةالسر", "سر", "رمز", "مفتاح", "سري",
    # 6. French
    "motdepasse", "mot_de_passe", "motdepass", "clé", "clef", "clésecrète",
    # 7. Portuguese
    "senha", "segredo", "chavesecreta", "chave",
    # 8. Russian
    "пароль", "секрет", "токен", "ключ", "секретныйключ",
    # 9. Japanese
    "パスワード", "トークン", "暗証番号", "合言葉",
    # 10. German
    "passwort", "kennwort", "geheimnis", "geheim", "schlüssel", "schluessel", "zugangsschlüssel",
    # 11. Korean
    "비밀번호", "암호", "비밀", "토큰", "비밀키",
    # 12. Turkish
    "şifre", "sifre", "parola", "gizli", "anahtar", "gizlianahtar",
    # 13. Italian
    "segreto", "chiave", "parolachiave", "parola_chiave", "credenziale",
    # 14. Persian
    "رمزعبور", "گذرواژه", "کلمهعبور", "کلید", "محرمانه",
    # 15. Polish
    "hasło", "haslo", "tajne", "klucz", "poufne",
    # 16. Ukrainian
    "таємний",
    # 17. Dutch
    "wachtwoord", "sleutel",
    # 18. Vietnamese
    "matkhau", "mat_khau", "bimat", "khoa",
    # 19. Indonesian
    "katasandi", "kata_sandi", "sandi", "rahasia", "kunci",
    # 20. Thai
    "รหัสผ่าน", "ความลับ",
    # 21. Greek
    "κωδικός", "μυστικό", "κλειδί",
    # 22. Hebrew
    "סיסמה", "סוד", "מפתח",
    # 23. Azerbaijani
    "şifrə", "parol", "açar", "məxfi",
    # 24. Romanian
    "parolă", "cheie",
)

#: Deduplicated, lowercased keyword list in declaration order.
SECRET_KEYWORDS: Tuple[str, ...] = tuple(dict.fromkeys(word.lower() for word in _RAW))

#: Fast membership test for object key names.
MULTILANG_KEY_SET: FrozenSet[str] = frozenset(SECRET_KEYWORDS)

#: English key names that are sensitive by convention, including punctuated forms.
SENSITIVE_KEY_PATTERN = (
    r"(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret"
    r"|private[_-]?key|auth(?:orization)?|cookie|session[_-]?id|refresh[_-]?token"
    r"|credit[_-]?card|card[_-]?number|cvv|ssn)"
)


def normalize_key_name(name: str) -> str:
    """The form a key name is compared in (FRS-1 §9).

    İ and ı become i, every character takes its simple lowercase mapping, then
    final sigma and long s fold to σ and s. ``str.lower`` differs from simple
    lowercasing only in İ and the final-sigma rule, both of which this erases, so
    ``ŞİFRE``, ``GİZLİ`` and ``ΚΩΔΙΚΌΣ`` compare equal to their keywords in every
    FRS-1 engine.
    """
    return (
        name.replace("\u0130", "i")
        .replace("\u0131", "i")
        .lower()
        .replace("\u03c2", "\u03c3")
        .replace("\u017f", "s")
    )


_NORMALIZED_KEYWORDS: FrozenSet[str] = frozenset(normalize_key_name(word) for word in SECRET_KEYWORDS)
_SENSITIVE_KEY_NAME = re.compile(SENSITIVE_KEY_PATTERN)


def is_sensitive_key_name(name: str) -> bool:
    """Whether a key is sensitive by name: its normalised form is one of the
    English names or one of the multilingual keywords."""
    normal = normalize_key_name(name)
    return _SENSITIVE_KEY_NAME.fullmatch(normal) is not None or normal in _NORMALIZED_KEYWORDS
