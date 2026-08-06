"""Named validators referenced by FRS-1 detector packs.

A checksum is the difference between "eleven digits" and "a Turkish national
identity number". Every national identifier below is validated, so a random run
of digits in a log line cannot be mistaken for real PII — which is what keeps
the opt-in country detectors usable at all.

Each function takes the raw matched text and returns ``True`` when it is a
plausible instance of the identifier.
"""

from __future__ import annotations

import math
import re
from typing import Callable, Dict

__all__ = ["VALIDATORS", "luhn", "shannon_entropy"]

_NON_DIGIT = re.compile(r"[^0-9]")


def _digits(value: str) -> str:
    return _NON_DIGIT.sub("", value)


def _all_same(digits: str) -> bool:
    return bool(digits) and digits == digits[0] * len(digits)


def luhn(value: str, min_digits: int = 2, max_digits: int = 0) -> bool:
    """Luhn (mod-10) check over the digits of ``value``."""
    d = _digits(value)
    if len(d) < min_digits:
        return False
    if max_digits and len(d) > max_digits:
        return False
    total = 0
    double = False
    for ch in reversed(d):
        n = ord(ch) - 48
        if double:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        double = not double
    return total % 10 == 0


def shannon_entropy(value: str) -> float:
    """Entropy in bits per symbol over Unicode code points."""
    if not value:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(value)
    out = 0.0
    for count in freq.values():
        p = count / total
        out -= p * math.log2(p)
    return out


def phone(value: str) -> bool:
    """E.164 digit bounds, plus a guard against dotted dates like ``07.24.2026``."""
    d = _digits(value)
    if len(d) < 8 or len(d) > 15:
        return False
    if not value.startswith("+"):
        if len(d) < 9:
            return False
        if re.search(r"(?:19|20)[0-9]{2}$", d) and re.search(r"[. \t\n\x0b\f\r-](?:19|20)[0-9]{2}$", value):
            return False
    return True


def iban(value: str) -> bool:
    """ISO 13616: rearrange, letters to numbers, mod 97 must be 1."""
    text = re.sub(r"[ \t\n\x0b\f\r-]", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}", text):
        return False
    rearranged = text[4:] + text[:4]
    remainder = 0
    for ch in rearranged:
        chunk = str(ord(ch) - 55) if "A" <= ch <= "Z" else ch
        for digit in chunk:
            remainder = (remainder * 10 + (ord(digit) - 48)) % 97
    return remainder == 1


def tckn(value: str) -> bool:
    """Türkiye T.C. Kimlik No — 11 digits with two check digits."""
    d = _digits(value)
    if len(d) != 11 or d[0] == "0":
        return False
    n = [ord(c) - 48 for c in d]
    odd = n[0] + n[2] + n[4] + n[6] + n[8]
    even = n[1] + n[3] + n[5] + n[7]
    if ((odd * 7 - even) % 10 + 10) % 10 != n[9]:
        return False
    return sum(n[:10]) % 10 == n[10]


def cpf(value: str) -> bool:
    """Brazil CPF — 11 digits with two mod-11 check digits."""
    c = _digits(value)
    if len(c) != 11 or _all_same(c):
        return False

    def check(length: int) -> int:
        total = sum(int(c[i]) * (length + 1 - i) for i in range(length))
        r = (total * 10) % 11
        return 0 if r == 10 else r

    return check(9) == int(c[9]) and check(10) == int(c[10])


_DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


def dni(value: str) -> bool:
    """Spain DNI / NIE — number mod 23 selects a control letter."""
    m = re.fullmatch(r"([XYZ]?)([0-9]{7,8})([A-Z])", re.sub(r"[ \t\n\x0b\f\r-]", "", value).upper())
    if not m:
        return False
    prefix = str("XYZ".index(m.group(1))) if m.group(1) else ""
    return _DNI_LETTERS[int(prefix + m.group(2)) % 23] == m.group(3)


def bsn(value: str) -> bool:
    """Netherlands BSN — 9 digits, 11-test with a final weight of −1."""
    d = _digits(value)
    if len(d) != 9 or d == "000000000":
        return False
    total = sum(int(d[i]) * (9 - i) for i in range(8)) - int(d[8])
    return total % 11 == 0


def pesel(value: str) -> bool:
    """Poland PESEL — 11 digits, weighted mod-10 check."""
    d = _digits(value)
    if len(d) != 11:
        return False
    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    total = sum(int(d[i]) * weights[i] for i in range(10))
    return (10 - (total % 10)) % 10 == int(d[10])


def de_tax_id(value: str) -> bool:
    """Germany Steuer-IdNr — 11 digits, ISO 7064 MOD 11,10."""
    d = _digits(value)
    if len(d) != 11:
        return False
    product = 10
    for i in range(10):
        total = (int(d[i]) + product) % 10
        if total == 0:
            total = 10
        product = (total * 2) % 11
    return (11 - product) % 10 == int(d[10])


_CF_ODD = {
    "0": 1, "1": 0, "2": 5, "3": 7, "4": 9, "5": 13, "6": 15, "7": 17, "8": 19, "9": 21,
    "A": 1, "B": 0, "C": 5, "D": 7, "E": 9, "F": 13, "G": 15, "H": 17, "I": 19, "J": 21,
    "K": 2, "L": 4, "M": 18, "N": 20, "O": 11, "P": 3, "Q": 6, "R": 8, "S": 12, "T": 14,
    "U": 16, "V": 10, "W": 22, "X": 25, "Y": 24, "Z": 23,
}


def codice_fiscale(value: str) -> bool:
    """Italy Codice Fiscale — 16 characters, odd/even table checksum."""
    cf = value.upper()
    if not re.fullmatch(r"[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]", cf):
        return False
    total = 0
    for i in range(15):
        ch = cf[i]
        if i % 2 == 0:
            total += _CF_ODD[ch]
        else:
            total += ord(ch) - 48 if "0" <= ch <= "9" else ord(ch) - 65
    return chr(65 + (total % 26)) == cf[15]


def fr_nir(value: str) -> bool:
    """France NIR — key = 97 − (number mod 97), with Corsican 2A/2B mapping."""
    nir = re.sub(r"[ \t\n\x0b\f\r.-]", "", value).upper()
    m = re.fullmatch(r"([12][0-9]{4})([0-9]{2}|2[AB])([0-9]{6})([0-9]{2})", nir)
    if not m:
        return False
    dept = {"2A": "19", "2B": "18"}.get(m.group(2), m.group(2))
    n = int(m.group(1) + dept + m.group(3))
    return 97 - (n % 97) == int(m.group(4))


_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6), (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4), (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2), (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def aadhaar(value: str) -> bool:
    """India Aadhaar — 12 digits, Verhoeff checksum, first digit 2–9."""
    d = _digits(value)
    if len(d) != 12 or d[0] in "01":
        return False
    c = 0
    for i in range(12):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(d[11 - i])]]
    return c == 0


def tfn(value: str) -> bool:
    """Australia TFN — 9 digits, weighted sum divisible by 11."""
    d = _digits(value)
    if len(d) != 9 or _all_same(d):
        return False
    weights = (1, 4, 3, 7, 5, 8, 6, 9, 10)
    return sum(int(d[i]) * weights[i] for i in range(9)) % 11 == 0


_CN_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_CN_CHECK = "10X98765432"


def cn_resident_id(value: str) -> bool:
    """China resident ID — 18 characters, ISO 7064 MOD 11-2."""
    ident = value.upper()
    if not re.fullmatch(
        r"[1-9][0-9]{5}(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9X]",
        ident,
    ):
        return False
    total = sum(int(ident[i]) * _CN_WEIGHTS[i] for i in range(17))
    return _CN_CHECK[total % 11] == ident[17]


def jp_my_number(value: str) -> bool:
    """Japan My Number — 12 digits, weighted mod-11 check digit."""
    d = _digits(value)
    if len(d) != 12:
        return False
    total = 0
    for n in range(1, 12):
        total += int(d[11 - n]) * (n + 1 if n <= 6 else n - 5)
    r = total % 11
    return (0 if r <= 1 else 11 - r) == int(d[11])


def us_ssn(value: str) -> bool:
    """US SSN — no checksum exists, but whole ranges were never issued."""
    m = re.fullmatch(r"([0-9]{3})-?([0-9]{2})-?([0-9]{4})", value)
    if not m:
        return False
    area, group, serial = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if area == 0 or area == 666 or area >= 900:
        return False
    return group != 0 and serial != 0


def aba(value: str) -> bool:
    """US ABA routing number — 9 digits, weighted 3-7-1 mod-10."""
    d = _digits(value)
    if len(d) != 9:
        return False
    total = 0
    for i in range(0, 9, 3):
        total += 3 * int(d[i]) + 7 * int(d[i + 1]) + int(d[i + 2])
    return total != 0 and total % 10 == 0


def nhs(value: str) -> bool:
    """UK NHS number — 10 digits, weighted mod-11 check digit."""
    d = _digits(value)
    if len(d) != 10 or _all_same(d):
        return False
    total = sum(int(d[i]) * (10 - i) for i in range(9))
    check = 11 - (total % 11)
    if check == 11:
        check = 0
    if check == 10:
        return False
    return check == int(d[9])


_VIN_TRANS = {
    "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8, "J": 1, "K": 2,
    "L": 3, "M": 4, "N": 5, "P": 7, "R": 9, "S": 2, "T": 3, "U": 4, "V": 5, "W": 6,
    "X": 7, "Y": 8, "Z": 9,
}
_VIN_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)


def vin(value: str) -> bool:
    """Vehicle VIN — 17 characters, transliterated weighted mod-11 at index 8."""
    v = value.upper()
    if not re.fullmatch(r"[A-HJ-NPR-Z0-9]{17}", v):
        return False
    total = 0
    for i, ch in enumerate(v):
        t = int(ch) if "0" <= ch <= "9" else _VIN_TRANS.get(ch)
        if t is None:
            return False
        total += t * _VIN_WEIGHTS[i]
    check = total % 11
    return v[8] == ("X" if check == 10 else str(check))


#: Validators addressable by name from a detector pack. An unknown name is a
#: load-time error, never a silently skipped check.
VALIDATORS: Dict[str, Callable[[str], bool]] = {
    "phone": phone,
    "iban": iban,
    "tckn": tckn,
    "cpf": cpf,
    "dni": dni,
    "bsn": bsn,
    "pesel": pesel,
    "de_tax_id": de_tax_id,
    "codice_fiscale": codice_fiscale,
    "fr_nir": fr_nir,
    "aadhaar": aadhaar,
    "tfn": tfn,
    "cn_resident_id": cn_resident_id,
    "jp_my_number": jp_my_number,
    "us_ssn": us_ssn,
    "aba": aba,
    "nhs": nhs,
    "vin": vin,
}
