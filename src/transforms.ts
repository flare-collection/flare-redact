import { deriveBytes, hmacFingerprint } from './crypto.js';
import type { Detector } from './detectors.js';

const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const GIVEN_NAMES = ['Alex', 'Avery', 'Casey', 'Emery', 'Jordan', 'Morgan', 'Riley', 'Robin'];
const FAMILY_NAMES = ['Arden', 'Blake', 'Hayes', 'Lane', 'Parker', 'Reed', 'Shaw', 'Vale'];
const STREETS = ['Cedar', 'Harbor', 'Juniper', 'Maple', 'Orchard', 'River', 'Willow', 'Summit'];

function alphabetFor(ch: string): string | undefined {
  if (ch >= '0' && ch <= '9') return DIGITS;
  if (ch >= 'a' && ch <= 'z') return LOWER;
  if (ch >= 'A' && ch <= 'Z') return UPPER;
  return undefined;
}

/**
 * Deterministic, keyed, shape-preserving pseudonymization. This is deliberately
 * not called format-preserving encryption: it is not reversible and does not
 * implement NIST FF1.
 */
export function pseudonymize(value: string, secret: string): string {
  const bytes = deriveBytes(secret, `pseudonym:${value}`, value.length);
  let out = '';
  for (let i = 0; i < value.length; i++) {
    const alphabet = alphabetFor(value[i]!);
    out += alphabet ? alphabet[bytes[i]! % alphabet.length] : value[i]!;
  }
  return out;
}

/** @deprecated Use pseudonymize(). This alias never represented encryption. */
export function fpe(value: string, secret: string): string {
  return pseudonymize(value, secret);
}

function digitSurrogate(value: string, secret: string): string {
  const bytes = deriveBytes(secret, `digits:${value}`, value.length);
  let out = '';
  for (let i = 0; i < value.length; i++) {
    out += /\d/.test(value[i]!) ? DIGITS[bytes[i]! % 10] : value[i]!;
  }
  return out;
}

function luhnCheckDigit(prefix: string): string {
  const digits = prefix.replace(/\D/g, '');
  let sum = 0;
  let double = true;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = Number(digits[i]);
    if (double) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    double = !double;
  }
  return String((10 - (sum % 10)) % 10);
}

function cardSurrogate(value: string, secret: string): string {
  const shaped = digitSurrogate(value, secret);
  const lastDigitIndex = shaped.search(/\d(?=\D*$)/);
  if (lastDigitIndex < 0) return shaped;
  const prefix = shaped.slice(0, lastDigitIndex);
  return prefix + luhnCheckDigit(prefix) + shaped.slice(lastDigitIndex + 1);
}

function emailSurrogate(value: string, secret: string): string {
  const tag = hmacFingerprint(secret, `email:${value}`, 6);
  return `user_${tag}@example.invalid`;
}

function personSurrogate(value: string, secret: string): string {
  const bytes = deriveBytes(secret, `person:${value}`, 2);
  return `${GIVEN_NAMES[bytes[0]! % GIVEN_NAMES.length]} ${FAMILY_NAMES[bytes[1]! % FAMILY_NAMES.length]}`;
}

function addressSurrogate(value: string, secret: string): string {
  const bytes = deriveBytes(secret, `address:${value}`, 3);
  const number = 100 + ((bytes[0]! << 8 | bytes[1]!) % 9800);
  return `${number} ${STREETS[bytes[2]! % STREETS.length]} Street`;
}

/** Produce a deterministic, type-consistent synthetic value for local test data. */
export function surrogate(value: string, detector: Detector, secret: string): string {
  switch (detector.id) {
    case 'email': return emailSurrogate(value, secret);
    case 'credit_card': return cardSurrogate(value, secret);
    case 'phone': return digitSurrogate(value, secret);
    case 'person_name':
    case 'private_person': return personSurrogate(value, secret);
    case 'street_address':
    case 'private_address': return addressSurrogate(value, secret);
    case 'private_phone': return digitSurrogate(value, secret);
    default: return pseudonymize(value, secret);
  }
}
