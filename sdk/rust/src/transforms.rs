//! Keyed, shape-preserving replacements: pseudonyms and typed surrogates.
//!
//! Masking destroys a dataset for analytics: every card becomes `**** 1234` and
//! joins stop working. These transforms keep the shape and the distinctness of a
//! value while removing its meaning, so a staging database still exercises the
//! same code paths as production. Neither is reversible — use a vault for that.

use crate::crypto::{derive_bytes, hmac_fingerprint};

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";

const GIVEN_NAMES: [&str; 8] = ["Alex", "Avery", "Casey", "Emery", "Jordan", "Morgan", "Riley", "Robin"];
const FAMILY_NAMES: [&str; 8] = ["Arden", "Blake", "Hayes", "Lane", "Parker", "Reed", "Shaw", "Vale"];
const STREETS: [&str; 8] = ["Cedar", "Harbor", "Juniper", "Maple", "Orchard", "River", "Willow", "Summit"];

fn alphabet_for(ch: char) -> Option<&'static [u8]> {
    match ch {
        '0'..='9' => Some(DIGITS),
        'a'..='z' => Some(LOWER),
        'A'..='Z' => Some(UPPER),
        _ => None,
    }
}

/// Deterministic, keyed, shape-preserving substitution.
///
/// Deliberately not called format-preserving encryption: it is not reversible
/// and does not implement NIST FF1. It is a stable pseudonym — the same input
/// and key always give the same output, so joins survive.
pub fn pseudonymize(value: &str, secret: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let stream = derive_bytes(secret, &format!("pseudonym:{value}"), chars.len());
    let mut out = String::with_capacity(value.len());
    for (index, ch) in chars.iter().enumerate() {
        match alphabet_for(*ch) {
            Some(alphabet) => out.push(alphabet[stream[index] as usize % alphabet.len()] as char),
            None => out.push(*ch),
        }
    }
    out
}

fn digit_surrogate(value: &str, secret: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let stream = derive_bytes(secret, &format!("digits:{value}"), chars.len());
    let mut out = String::with_capacity(value.len());
    for (index, ch) in chars.iter().enumerate() {
        if ch.is_ascii_digit() {
            out.push(DIGITS[stream[index] as usize % 10] as char);
        } else {
            out.push(*ch);
        }
    }
    out
}

fn luhn_check_digit(prefix: &str) -> char {
    let digits: Vec<u32> = prefix.chars().filter_map(|c| c.to_digit(10)).collect();
    let mut sum = 0u32;
    let mut double = true;
    for digit in digits.iter().rev() {
        let mut n = *digit;
        if double {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        double = !double;
    }
    char::from_digit((10 - (sum % 10)) % 10, 10).unwrap_or('0')
}

/// Keeps the card's shape and recomputes the Luhn digit, so the synthetic number
/// still passes the validation the surrounding code already performs.
fn card_surrogate(value: &str, secret: &str) -> String {
    let shaped: Vec<char> = digit_surrogate(value, secret).chars().collect();
    let Some(last) = shaped.iter().rposition(|c| c.is_ascii_digit()) else {
        return shaped.into_iter().collect();
    };
    let prefix: String = shaped[..last].iter().collect();
    let suffix: String = shaped[last + 1..].iter().collect();
    let check = luhn_check_digit(&prefix);
    format!("{prefix}{check}{suffix}")
}

fn email_surrogate(value: &str, secret: &str) -> String {
    format!("user_{}@example.invalid", hmac_fingerprint(secret, &format!("email:{value}"), 6))
}

fn person_surrogate(value: &str, secret: &str) -> String {
    let stream = derive_bytes(secret, &format!("person:{value}"), 2);
    format!(
        "{} {}",
        GIVEN_NAMES[stream[0] as usize % GIVEN_NAMES.len()],
        FAMILY_NAMES[stream[1] as usize % FAMILY_NAMES.len()]
    )
}

fn address_surrogate(value: &str, secret: &str) -> String {
    let stream = derive_bytes(secret, &format!("address:{value}"), 3);
    let number = 100 + (((stream[0] as usize) << 8 | stream[1] as usize) % 9800);
    format!("{number} {} Street", STREETS[stream[2] as usize % STREETS.len()])
}

/// A deterministic, type-consistent synthetic value for the given detector.
pub fn surrogate(value: &str, detector_id: &str, secret: &str) -> String {
    match detector_id {
        "email" => email_surrogate(value, secret),
        "credit_card" => card_surrogate(value, secret),
        "phone" => digit_surrogate(value, secret),
        "person_name" => person_surrogate(value, secret),
        "street_address" => address_surrogate(value, secret),
        _ => pseudonymize(value, secret),
    }
}
