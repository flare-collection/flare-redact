//! Named validators referenced by an FRS-1 detector pack.
//!
//! A checksum is the difference between "eleven digits" and "a Turkish national
//! identity number". Every national identifier here is validated, which is what
//! keeps the opt-in country detectors usable on real logs instead of drowning
//! them in false positives.

use std::collections::HashMap;

fn digits_of(value: &str) -> String {
    value.chars().filter(|c| c.is_ascii_digit()).collect()
}

fn digit_at(digits: &str, index: usize) -> u32 {
    digits.as_bytes()[index] as u32 - b'0' as u32
}

fn all_same(digits: &str) -> bool {
    let bytes = digits.as_bytes();
    !bytes.is_empty() && bytes.iter().all(|b| *b == bytes[0])
}

fn strip(value: &str, drop: &[char]) -> String {
    value.chars().filter(|c| !drop.contains(c)).collect()
}

const SPACES_AND_DASH: [char; 7] = [' ', '\t', '\n', '\r', '\u{0B}', '\u{0C}', '-'];
const SPACES_DOT_DASH: [char; 8] = [' ', '\t', '\n', '\r', '\u{0B}', '\u{0C}', '.', '-'];

/// Luhn (mod-10) over the digits of `value`, with an optional length window.
/// `max_digits` of zero means unbounded.
pub fn luhn(value: &str, min_digits: usize, max_digits: usize) -> bool {
    let d = digits_of(value);
    if d.len() < min_digits {
        return false;
    }
    if max_digits > 0 && d.len() > max_digits {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for index in (0..d.len()).rev() {
        let mut n = digit_at(&d, index);
        if double {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        double = !double;
    }
    sum % 10 == 0
}

/// Shannon entropy in bits per symbol, over Unicode code points.
pub fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut frequency: HashMap<char, usize> = HashMap::new();
    let mut total = 0usize;
    for ch in value.chars() {
        *frequency.entry(ch).or_insert(0) += 1;
        total += 1;
    }
    let mut entropy = 0.0;
    for count in frequency.values() {
        let p = *count as f64 / total as f64;
        entropy -= p * p.log2();
    }
    entropy
}

fn ends_with_year(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    chars.len() >= 4
        && chars[chars.len() - 4..].iter().all(|c| c.is_ascii_digit())
        && matches!(
            (chars[chars.len() - 4], chars[chars.len() - 3]),
            ('1', '9') | ('2', '0')
        )
}

/// E.164 digit bounds, plus a guard against dotted dates such as `07.24.2026`.
///
/// Only a *separated* trailing year looks like a date: `0532 1234 2026` is a
/// phone number, `07.24.2026` is not.
pub fn phone(value: &str) -> bool {
    let d = digits_of(value);
    if d.len() < 8 || d.len() > 15 {
        return false;
    }
    if value.starts_with('+') {
        return true;
    }
    if d.len() < 9 {
        return false;
    }
    if ends_with_year(&d) && ends_with_year(value) {
        let chars: Vec<char> = value.chars().collect();
        if chars.len() >= 5
            && matches!(
                chars[chars.len() - 5],
                '.' | ' ' | '\t' | '\n' | '\r' | '\u{0B}' | '\u{0C}' | '-'
            )
        {
            return false;
        }
    }
    true
}

/// ISO 13616 IBAN check: rearrange, letters to numbers, mod 97 must be 1.
pub fn iban(value: &str) -> bool {
    let text = strip(value, &SPACES_AND_DASH).to_uppercase();
    // Byte slicing below is only sound on ASCII, and every IBAN is ASCII.
    if !text.is_ascii() || text.len() < 14 || text.len() > 34 {
        return false;
    }
    let bytes = text.as_bytes();
    if !bytes[0].is_ascii_uppercase()
        || !bytes[1].is_ascii_uppercase()
        || !bytes[2].is_ascii_digit()
        || !bytes[3].is_ascii_digit()
        || !bytes[4..].iter().all(|b| b.is_ascii_alphanumeric() && !b.is_ascii_lowercase())
    {
        return false;
    }
    let rearranged: String = format!("{}{}", &text[4..], &text[..4]);
    let mut remainder = 0u32;
    for ch in rearranged.chars() {
        let chunk = if ch.is_ascii_uppercase() {
            (ch as u32 - 55).to_string()
        } else {
            ch.to_string()
        };
        for digit in chunk.bytes() {
            remainder = (remainder * 10 + (digit - b'0') as u32) % 97;
        }
    }
    remainder == 1
}

/// Türkiye T.C. Kimlik No — 11 digits with two check digits.
pub fn tckn(value: &str) -> bool {
    let d = digits_of(value);
    if d.len() != 11 || d.starts_with('0') {
        return false;
    }
    let n: Vec<u32> = (0..11).map(|i| digit_at(&d, i)).collect();
    let odd = n[0] + n[2] + n[4] + n[6] + n[8];
    let even = n[1] + n[3] + n[5] + n[7];
    if ((odd as i64 * 7 - even as i64) % 10 + 10) % 10 != n[9] as i64 {
        return false;
    }
    let sum: u32 = n[..10].iter().sum();
    sum % 10 == n[10]
}

/// Brazil CPF — 11 digits with two mod-11 check digits.
pub fn cpf(value: &str) -> bool {
    let c = digits_of(value);
    if c.len() != 11 || all_same(&c) {
        return false;
    }
    let check = |length: usize| -> u32 {
        let mut sum = 0u32;
        for i in 0..length {
            sum += digit_at(&c, i) * (length as u32 + 1 - i as u32);
        }
        let r = (sum * 10) % 11;
        if r == 10 {
            0
        } else {
            r
        }
    };
    check(9) == digit_at(&c, 9) && check(10) == digit_at(&c, 10)
}

const DNI_LETTERS: &[u8] = b"TRWAGMYFPDXBNJZSQVHLCKE";

/// Spain DNI / NIE — number mod 23 selects a control letter.
pub fn dni(value: &str) -> bool {
    let text = strip(value, &SPACES_AND_DASH).to_uppercase();
    let bytes = text.as_bytes();
    if !text.is_ascii() || bytes.len() < 8 || bytes.len() > 10 {
        return false;
    }
    let (prefix, rest) = match bytes[0] {
        b'X' => (Some(0u32), &text[1..]),
        b'Y' => (Some(1u32), &text[1..]),
        b'Z' => (Some(2u32), &text[1..]),
        _ => (None, &text[..]),
    };
    let rest_bytes = rest.as_bytes();
    if rest_bytes.len() < 8 || rest_bytes.len() > 9 {
        return false;
    }
    let (number, letter) = rest.split_at(rest.len() - 1);
    if !number.bytes().all(|b| b.is_ascii_digit()) || !letter.as_bytes()[0].is_ascii_uppercase() {
        return false;
    }
    let combined = match prefix {
        Some(p) => format!("{p}{number}"),
        None => number.to_string(),
    };
    let Ok(n) = combined.parse::<u64>() else {
        return false;
    };
    DNI_LETTERS[(n % 23) as usize] == letter.as_bytes()[0]
}

/// Netherlands BSN — 9 digits, 11-test with a final weight of −1.
pub fn bsn(value: &str) -> bool {
    let d = digits_of(value);
    if d.len() != 9 || d == "000000000" {
        return false;
    }
    let mut sum: i64 = 0;
    for i in 0..8 {
        sum += digit_at(&d, i) as i64 * (9 - i as i64);
    }
    sum -= digit_at(&d, 8) as i64;
    sum % 11 == 0
}

/// Poland PESEL — 11 digits, weighted mod-10 check.
pub fn pesel(value: &str) -> bool {
    let d = digits_of(value);
    if d.len() != 11 {
        return false;
    }
    const WEIGHTS: [u32; 10] = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
    let mut sum = 0u32;
    for (i, weight) in WEIGHTS.iter().enumerate() {
        sum += digit_at(&d, i) * weight;
    }
    (10 - (sum % 10)) % 10 == digit_at(&d, 10)
}

/// Germany Steuer-IdNr — 11 digits, ISO 7064 MOD 11,10.
pub fn de_tax_id(value: &str) -> bool {
    let d = digits_of(value);
    if d.len() != 11 {
        return false;
    }
    let mut product = 10u32;
    for i in 0..10 {
        let mut sum = (digit_at(&d, i) + product) % 10;
        if sum == 0 {
            sum = 10;
        }
        product = (sum * 2) % 11;
    }
    (11 - product) % 10 == digit_at(&d, 10)
}

fn cf_odd(ch: u8) -> Option<u32> {
    const TABLE: [(u8, u32); 36] = [
        (b'0', 1), (b'1', 0), (b'2', 5), (b'3', 7), (b'4', 9), (b'5', 13), (b'6', 15), (b'7', 17),
        (b'8', 19), (b'9', 21), (b'A', 1), (b'B', 0), (b'C', 5), (b'D', 7), (b'E', 9), (b'F', 13),
        (b'G', 15), (b'H', 17), (b'I', 19), (b'J', 21), (b'K', 2), (b'L', 4), (b'M', 18), (b'N', 20),
        (b'O', 11), (b'P', 3), (b'Q', 6), (b'R', 8), (b'S', 12), (b'T', 14), (b'U', 16), (b'V', 10),
        (b'W', 22), (b'X', 25), (b'Y', 24), (b'Z', 23),
    ];
    TABLE.iter().find(|(key, _)| *key == ch).map(|(_, value)| *value)
}

/// Italy Codice Fiscale — 16 characters, odd/even table checksum.
pub fn codice_fiscale(value: &str) -> bool {
    let cf = value.to_uppercase();
    let bytes = cf.as_bytes();
    if bytes.len() != 16 {
        return false;
    }
    let shape = [
        (0..6, "alpha"), (6..8, "digit"), (8..9, "alpha"), (9..11, "digit"),
        (11..12, "alpha"), (12..15, "digit"), (15..16, "alpha"),
    ];
    for (range, kind) in shape {
        for index in range {
            let ok = match kind {
                "alpha" => bytes[index].is_ascii_uppercase(),
                _ => bytes[index].is_ascii_digit(),
            };
            if !ok {
                return false;
            }
        }
    }
    let mut sum = 0u32;
    for (index, byte) in bytes[..15].iter().enumerate() {
        if index % 2 == 0 {
            match cf_odd(*byte) {
                Some(value) => sum += value,
                None => return false,
            }
        } else if byte.is_ascii_digit() {
            sum += (*byte - b'0') as u32;
        } else {
            sum += (*byte - b'A') as u32;
        }
    }
    (b'A' + (sum % 26) as u8) == bytes[15]
}

/// France NIR — key = 97 − (number mod 97), with Corsica's 2A/2B mapped first.
pub fn fr_nir(value: &str) -> bool {
    let nir = strip(value, &SPACES_DOT_DASH).to_uppercase();
    if !nir.is_ascii() || nir.len() != 15 {
        return false;
    }
    let bytes = nir.as_bytes();
    if bytes[0] != b'1' && bytes[0] != b'2' {
        return false;
    }
    let department = &nir[5..7];
    let mapped = match department {
        "2A" => "19".to_string(),
        "2B" => "18".to_string(),
        other if other.bytes().all(|b| b.is_ascii_digit()) => other.to_string(),
        _ => return false,
    };
    let head = &nir[..5];
    let body = &nir[7..13];
    let key = &nir[13..];
    if !head.bytes().all(|b| b.is_ascii_digit())
        || !body.bytes().all(|b| b.is_ascii_digit())
        || !key.bytes().all(|b| b.is_ascii_digit())
    {
        return false;
    }
    let Ok(number) = format!("{head}{mapped}{body}").parse::<u64>() else {
        return false;
    };
    let Ok(expected) = key.parse::<u64>() else {
        return false;
    };
    97 - (number % 97) == expected
}

const VERHOEFF_D: [[usize; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const VERHOEFF_P: [[usize; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/// India Aadhaar — 12 digits, Verhoeff checksum, first digit 2–9.
pub fn aadhaar(value: &str) -> bool {
    let d = digits_of(value);
    if d.len() != 12 || d.starts_with('0') || d.starts_with('1') {
        return false;
    }
    let mut c = 0usize;
    for i in 0..12 {
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit_at(&d, 11 - i) as usize]];
    }
    c == 0
}

/// Australia TFN — 9 digits, weighted sum divisible by 11.
pub fn tfn(value: &str) -> bool {
    let d = digits_of(value);
    if d.len() != 9 || all_same(&d) {
        return false;
    }
    const WEIGHTS: [u32; 9] = [1, 4, 3, 7, 5, 8, 6, 9, 10];
    let mut sum = 0u32;
    for (i, weight) in WEIGHTS.iter().enumerate() {
        sum += digit_at(&d, i) * weight;
    }
    sum % 11 == 0
}

const CN_WEIGHTS: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
const CN_CHECK: &[u8] = b"10X98765432";

/// China resident ID — 18 characters, ISO 7064 MOD 11-2.
pub fn cn_resident_id(value: &str) -> bool {
    let id = value.to_uppercase();
    let bytes = id.as_bytes();
    if bytes.len() != 18 || !bytes[..17].iter().all(|b| b.is_ascii_digit()) || bytes[0] == b'0' {
        return false;
    }
    if !(bytes[17].is_ascii_digit() || bytes[17] == b'X') {
        return false;
    }
    let mut sum = 0u32;
    for (index, weight) in CN_WEIGHTS.iter().enumerate() {
        sum += (bytes[index] - b'0') as u32 * weight;
    }
    CN_CHECK[(sum % 11) as usize] == bytes[17]
}

/// Japan My Number — 12 digits, weighted mod-11 check digit.
pub fn jp_my_number(value: &str) -> bool {
    let d = digits_of(value);
    if d.len() != 12 {
        return false;
    }
    let mut sum = 0u32;
    for n in 1..=11usize {
        let weight = if n <= 6 { n as u32 + 1 } else { n as u32 - 5 };
        sum += digit_at(&d, 11 - n) * weight;
    }
    let r = sum % 11;
    let check = if r <= 1 { 0 } else { 11 - r };
    check == digit_at(&d, 11)
}

/// US SSN — no checksum exists, but whole ranges were never issued.
pub fn us_ssn(value: &str) -> bool {
    let d = digits_of(value);
    if d.len() != 9 {
        return false;
    }
    let area: u32 = d[..3].parse().unwrap_or(0);
    let group: u32 = d[3..5].parse().unwrap_or(0);
    let serial: u32 = d[5..].parse().unwrap_or(0);
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }
    group != 0 && serial != 0
}

/// US ABA routing number — 9 digits, weighted 3-7-1 mod-10.
pub fn aba(value: &str) -> bool {
    let d = digits_of(value);
    if d.len() != 9 {
        return false;
    }
    let mut sum = 0u32;
    let mut index = 0;
    while index < 9 {
        sum += 3 * digit_at(&d, index) + 7 * digit_at(&d, index + 1) + digit_at(&d, index + 2);
        index += 3;
    }
    sum != 0 && sum % 10 == 0
}

/// UK NHS number — 10 digits, weighted mod-11 check digit.
pub fn nhs(value: &str) -> bool {
    let d = digits_of(value);
    if d.len() != 10 || all_same(&d) {
        return false;
    }
    let mut sum = 0u32;
    for i in 0..9 {
        sum += digit_at(&d, i) * (10 - i as u32);
    }
    let mut check = 11 - (sum % 11);
    if check == 11 {
        check = 0;
    }
    if check == 10 {
        return false;
    }
    check == digit_at(&d, 9)
}

fn vin_value(ch: u8) -> Option<u32> {
    if ch.is_ascii_digit() {
        return Some((ch - b'0') as u32);
    }
    const TABLE: [(u8, u32); 23] = [
        (b'A', 1), (b'B', 2), (b'C', 3), (b'D', 4), (b'E', 5), (b'F', 6), (b'G', 7), (b'H', 8),
        (b'J', 1), (b'K', 2), (b'L', 3), (b'M', 4), (b'N', 5), (b'P', 7), (b'R', 9), (b'S', 2),
        (b'T', 3), (b'U', 4), (b'V', 5), (b'W', 6), (b'X', 7), (b'Y', 8), (b'Z', 9),
    ];
    TABLE.iter().find(|(key, _)| *key == ch).map(|(_, value)| *value)
}

const VIN_WEIGHTS: [u32; 17] = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];

/// Vehicle VIN — 17 characters, transliterated weighted mod-11 at position 9.
pub fn vin(value: &str) -> bool {
    let v = value.to_uppercase();
    let bytes = v.as_bytes();
    if bytes.len() != 17 {
        return false;
    }
    let mut sum = 0u32;
    for (index, byte) in bytes.iter().enumerate() {
        match vin_value(*byte) {
            Some(mapped) => sum += mapped * VIN_WEIGHTS[index],
            None => return false,
        }
    }
    let check = sum % 11;
    let expected = if check == 10 { b'X' } else { b'0' + check as u8 };
    bytes[8] == expected
}

/// Look up a validator by the name a pack uses. `None` means this engine cannot
/// perform the check, which is a load error rather than a skipped validation.
pub fn named(name: &str) -> Option<fn(&str) -> bool> {
    Some(match name {
        "phone" => phone,
        "iban" => iban,
        "tckn" => tckn,
        "cpf" => cpf,
        "dni" => dni,
        "bsn" => bsn,
        "pesel" => pesel,
        "de_tax_id" => de_tax_id,
        "codice_fiscale" => codice_fiscale,
        "fr_nir" => fr_nir,
        "aadhaar" => aadhaar,
        "tfn" => tfn,
        "cn_resident_id" => cn_resident_id,
        "jp_my_number" => jp_my_number,
        "us_ssn" => us_ssn,
        "aba" => aba,
        "nhs" => nhs,
        "vin" => vin,
        _ => return None,
    })
}
