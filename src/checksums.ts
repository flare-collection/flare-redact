const onlyDigits = (s: string): string => s.replace(/\D/g, '');

/** Generic Luhn (any length ≥ 2). Used by several national numbers and cards. */
export function luhnCheck(value: string): boolean {
  const d = onlyDigits(value);
  if (d.length < 2) return false;
  let sum = 0;
  let alt = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = d.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

/** ISO 13616 IBAN check: rearrange, letters→numbers, mod 97 === 1. */
export function ibanValid(value: string): boolean {
  const iban = value.replace(/[\s-]/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(iban)) return false;
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const code = ch >= 'A' && ch <= 'Z' ? (ch.charCodeAt(0) - 55).toString() : ch;
    for (let i = 0; i < code.length; i++) {
      remainder = (remainder * 10 + (code.charCodeAt(i) - 48)) % 97;
    }
  }
  return remainder === 1;
}

/**
 * Total IBAN length per country: the SWIFT IBAN registry, then the countries
 * that use the format without being in it. The compact form needs no table, but
 * the printed form does: "BE68 5390 0754 7034 EUR" only stops before "EUR" if
 * the pattern knows a Belgian IBAN ends after three groups.
 */
export const IBAN_LENGTHS: Readonly<Record<string, number>> = {
  AD: 24, AE: 23, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22, BI: 27,
  BR: 29, BY: 28, CH: 21, CR: 22, CY: 28, CZ: 24, DE: 22, DJ: 27, DK: 18, DO: 28,
  EE: 20, EG: 29, ES: 24, FI: 18, FK: 18, FO: 18, FR: 27, GB: 22, GE: 22, GI: 23,
  GL: 18, GR: 27, GT: 28, HN: 28, HR: 21, HU: 28, IE: 22, IL: 23, IQ: 23, IS: 26,
  IT: 27, JO: 30, KW: 30, KZ: 20, LB: 28, LC: 32, LI: 21, LT: 20, LU: 20, LV: 21,
  LY: 25, MC: 27, MD: 24, ME: 22, MK: 19, MN: 20, MR: 27, MT: 31, MU: 30, NI: 28,
  NL: 18, NO: 15, OM: 23, PK: 24, PL: 28, PS: 29, PT: 25, QA: 29, RO: 24, RS: 22,
  RU: 33, SA: 24, SC: 31, SD: 18, SE: 24, SI: 19, SK: 24, SM: 27, SO: 23, ST: 25,
  SV: 28, TL: 23, TN: 24, TR: 26, UA: 29, VA: 22, VG: 24, XK: 20, YE: 30,
  AO: 25, BF: 28, BJ: 28, CF: 27, CG: 27, CI: 28, CM: 27, CV: 25, DZ: 26, GA: 27,
  GQ: 27, GW: 25, IR: 26, KM: 27, MA: 28, MG: 27, ML: 28, MZ: 25, NE: 28, SN: 28,
  TD: 27, TG: 28,
};

/**
 * Pattern source for an IBAN in ISO 13616 print format: groups of four after
 * the country and check digits, the last group shorter. `separator` is a
 * character class; `digit` lets the FRS-1 pack spell `\d` as `[0-9]`.
 */
export function ibanPrintedPattern(separator: string, digit = '[0-9]'): string {
  const byShape = new Map<string, string[]>();
  for (const [country, length] of Object.entries(IBAN_LENGTHS)) {
    const groups = Math.floor((length - 4) / 4);
    const tail = (length - 4) % 4;
    const shape = `(?:${separator}[A-Z0-9]{4}){${groups}}` + (tail ? `${separator}[A-Z0-9]{${tail}}` : '');
    const list = byShape.get(shape) ?? [];
    list.push(country);
    byShape.set(shape, list);
  }
  return [...byShape].map(([shape, countries]) => `(?:${countries.join('|')})${digit}{2}${shape}`).join('|');
}

/** Turkey T.C. Kimlik No — 11 digits, two check digits. */
export function tcknValid(value: string): boolean {
  const d = onlyDigits(value);
  if (d.length !== 11 || d[0] === '0') return false;
  const n = d.split('').map(Number);
  const odd = n[0]! + n[2]! + n[4]! + n[6]! + n[8]!;
  const even = n[1]! + n[3]! + n[5]! + n[7]!;
  if (((odd * 7 - even) % 10 + 10) % 10 !== n[9]) return false;
  const sum10 = n.slice(0, 10).reduce((a, b) => a + b, 0);
  return sum10 % 10 === n[10];
}

/** Brazil CPF — 11 digits, two mod-11 check digits. */
export function cpfValid(value: string): boolean {
  const c = onlyDigits(value);
  if (c.length !== 11 || /^(\d)\1{10}$/.test(c)) return false;
  const digit = (len: number): number => {
    let sum = 0;
    for (let i = 0; i < len; i++) sum += Number(c[i]) * (len + 1 - i);
    const r = (sum * 10) % 11;
    return r === 10 ? 0 : r;
  };
  return digit(9) === Number(c[9]) && digit(10) === Number(c[10]);
}

const DNI_LETTERS = 'TRWAGMYFPDXBNJZSQVHLCKE';
/** Spain DNI / NIE — number mod 23 maps to a control letter. */
export function dniValid(value: string): boolean {
  const m = value.toUpperCase().replace(/[\s-]/g, '').match(/^([XYZ]?)(\d{7,8})([A-Z])$/);
  if (!m) return false;
  const prefix = m[1] ? String('XYZ'.indexOf(m[1])) : '';
  const n = parseInt(prefix + m[2], 10);
  return DNI_LETTERS[n % 23] === m[3];
}

/** Netherlands BSN — 9 digits, 11-test (last weight is −1). */
export function bsnValid(value: string): boolean {
  const d = onlyDigits(value);
  if (d.length !== 9 || d === '000000000') return false;
  let sum = 0;
  for (let i = 0; i < 8; i++) sum += Number(d[i]) * (9 - i);
  sum += Number(d[8]) * -1;
  return sum % 11 === 0;
}

/** Poland PESEL — 11 digits, weighted mod-10 check. */
export function peselValid(value: string): boolean {
  const d = onlyDigits(value);
  if (d.length !== 11) return false;
  const w = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
  let sum = 0;
  for (let i = 0; i < 10; i++) sum += Number(d[i]) * w[i]!;
  return (10 - (sum % 10)) % 10 === Number(d[10]);
}

/** Germany Steuer-IdNr — 11 digits, ISO 7064 MOD 11,10 check digit. */
export function deTaxIdValid(value: string): boolean {
  const d = onlyDigits(value);
  if (d.length !== 11) return false;
  let product = 10;
  for (let i = 0; i < 10; i++) {
    let sum = (Number(d[i]) + product) % 10;
    if (sum === 0) sum = 10;
    product = (sum * 2) % 11;
  }
  const check = (11 - product) % 10;
  return check === Number(d[10]);
}

/** US ABA routing number — 9 digits, weighted 3-7-1 mod-10. */
export function abaValid(value: string): boolean {
  const d = onlyDigits(value);
  if (d.length !== 9) return false;
  let sum = 0;
  for (let i = 0; i < 9; i += 3) {
    sum += 3 * Number(d[i]) + 7 * Number(d[i + 1]) + Number(d[i + 2]);
  }
  return sum !== 0 && sum % 10 === 0;
}

/** UK NHS number — 10 digits, weighted mod-11 check digit. */
export function nhsValid(value: string): boolean {
  const d = onlyDigits(value);
  if (d.length !== 10 || /^(\d)\1{9}$/.test(d)) return false;
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += Number(d[i]) * (10 - i);
  let check = 11 - (sum % 11);
  if (check === 11) check = 0;
  if (check === 10) return false;
  return check === Number(d[9]);
}

const VIN_TRANS: Record<string, number> = {
  A: 1, B: 2, C: 3, D: 4, E: 5, F: 6, G: 7, H: 8, J: 1, K: 2, L: 3, M: 4, N: 5,
  P: 7, R: 9, S: 2, T: 3, U: 4, V: 5, W: 6, X: 7, Y: 8, Z: 9,
};
const VIN_WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];
/** Vehicle VIN — 17 chars, transliterated weighted mod-11 check at position 9. */
export function vinValid(value: string): boolean {
  const v = value.toUpperCase();
  if (!/^[A-HJ-NPR-Z0-9]{17}$/.test(v)) return false;
  let sum = 0;
  for (let i = 0; i < 17; i++) {
    const c = v[i]!;
    const t = c >= '0' && c <= '9' ? Number(c) : VIN_TRANS[c];
    if (t === undefined) return false;
    sum += t * VIN_WEIGHTS[i]!;
  }
  const check = sum % 11;
  return v[8] === (check === 10 ? 'X' : String(check));
}

/** US SSN — no checksum exists, but whole ranges are never issued. */
export function ssnValid(value: string): boolean {
  const m = value.match(/^(\d{3})[- ]?(\d{2})[- ]?(\d{4})$/);
  if (!m) return false;
  const area = Number(m[1]);
  const group = Number(m[2]);
  const serial = Number(m[3]);
  if (area === 0 || area === 666 || area >= 900) return false;
  return group !== 0 && serial !== 0;
}

/** France NIR (INSEE) — 13 digits + 2-digit key, key = 97 − (number mod 97). */
export function frNirValid(value: string): boolean {
  const nir = value.replace(/[\s.-]/g, '').toUpperCase();
  const m = nir.match(/^([12]\d{4})(\d{2}|2[AB])(\d{6})(\d{2})$/);
  if (!m) return false;
  // Corsican departments: 2A → 19, 2B → 18 before the modulo.
  const dept = m[2] === '2A' ? '19' : m[2] === '2B' ? '18' : m[2]!;
  const n = Number(m[1]! + dept + m[3]!);
  const key = 97 - (n % 97);
  return key === Number(m[4]);
}

const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];
/** India Aadhaar — 12 digits, Verhoeff checksum, first digit 2–9. */
export function aadhaarValid(value: string): boolean {
  const d = onlyDigits(value);
  if (d.length !== 12 || d[0] === '0' || d[0] === '1') return false;
  let c = 0;
  for (let i = 0; i < 12; i++) {
    c = VERHOEFF_D[c]![VERHOEFF_P[i % 8]![Number(d[11 - i])]!]!;
  }
  return c === 0;
}

const TFN_WEIGHTS = [1, 4, 3, 7, 5, 8, 6, 9, 10];
/** Australia TFN — 9 digits, weighted sum divisible by 11. */
export function tfnValid(value: string): boolean {
  const d = onlyDigits(value);
  if (d.length !== 9 || /^(\d)\1{8}$/.test(d)) return false;
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += Number(d[i]) * TFN_WEIGHTS[i]!;
  return sum % 11 === 0;
}

const CN_ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
const CN_ID_CHECK = '10X98765432';
/** China resident ID — 18 chars, ISO 7064 MOD 11-2 check character. */
export function cnResidentIdValid(value: string): boolean {
  const id = value.toUpperCase();
  if (!/^[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dX]$/.test(id)) return false;
  let sum = 0;
  for (let i = 0; i < 17; i++) sum += Number(id[i]) * CN_ID_WEIGHTS[i]!;
  return CN_ID_CHECK[sum % 11] === id[17];
}

/** Japan My Number — 12 digits, weighted mod-11 check digit. */
export function jpMyNumberValid(value: string): boolean {
  const d = onlyDigits(value);
  if (d.length !== 12) return false;
  let sum = 0;
  for (let n = 1; n <= 11; n++) {
    const digit = Number(d[11 - n]);
    sum += digit * (n <= 6 ? n + 1 : n - 5);
  }
  const r = sum % 11;
  const check = r <= 1 ? 0 : 11 - r;
  return check === Number(d[11]);
}

const CF_ODD: Record<string, number> = {
  '0': 1, '1': 0, '2': 5, '3': 7, '4': 9, '5': 13, '6': 15, '7': 17, '8': 19, '9': 21,
  A: 1, B: 0, C: 5, D: 7, E: 9, F: 13, G: 15, H: 17, I: 19, J: 21, K: 2, L: 4, M: 18,
  N: 20, O: 11, P: 3, Q: 6, R: 8, S: 12, T: 14, U: 16, V: 10, W: 22, X: 25, Y: 24, Z: 23,
};
/** Italy Codice Fiscale — 16 chars, odd/even table checksum. */
export function codiceFiscaleValid(value: string): boolean {
  const cf = value.toUpperCase();
  if (!/^[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]$/.test(cf)) return false;
  let sum = 0;
  for (let i = 0; i < 15; i++) {
    const ch = cf[i]!;
    if (i % 2 === 0) {
      sum += CF_ODD[ch]!;
    } else {
      const even = ch >= '0' && ch <= '9' ? ch.charCodeAt(0) - 48 : ch.charCodeAt(0) - 65;
      sum += even;
    }
  }
  return String.fromCharCode(65 + (sum % 26)) === cf[15];
}

/** Day 01-31 and month 01-12, the plausibility check shared by date-based IDs. */
function plausibleDate(day: number, month: number): boolean {
  return day >= 1 && day <= 31 && month >= 1 && month <= 12;
}

const CNP_WEIGHTS = [2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9];
/** Romania CNP: 13 digits, birth date, weighted mod-11 check digit (10 is written as 1). */
export function cnpValid(value: string): boolean {
  const d = onlyDigits(value);
  if (d.length !== 13 || d[0] === '0') return false;
  if (!plausibleDate(Number(d.slice(5, 7)), Number(d.slice(3, 5)))) return false;
  let sum = 0;
  for (let i = 0; i < 12; i++) sum += Number(d[i]) * CNP_WEIGHTS[i]!;
  const r = sum % 11;
  return (r === 10 ? 1 : r) === Number(d[12]);
}

/**
 * Sweden personnummer: YYMMDD-NNNC (or `+` from age 100), or YYYYMMDDNNNC.
 * Luhn over the ten-digit form; a samordningsnummer adds 60 to the day.
 */
export function personnummerValid(value: string): boolean {
  let d = value.replace(/[-+]/g, '');
  if (!/^\d+$/.test(d)) return false;
  if (d.length === 12) {
    if (!/^(?:18|19|20)/.test(d)) return false;
    d = d.slice(2);
  }
  if (d.length !== 10) return false;
  const day = Number(d.slice(4, 6));
  if (!plausibleDate(day > 60 ? day - 60 : day, Number(d.slice(2, 4)))) return false;
  return luhnCheck(d);
}

const HETU_CHECK = '0123456789ABCDEFHJKLMNPRSTUVWXY';
/** Finland henkilötunnus: DDMMYY, century sign, individual number, mod-31 check character. */
export function hetuValid(value: string): boolean {
  const m = value.match(/^(\d{2})(\d{2})(\d{2})[-+A-FU-Y](\d{3})([0-9A-FHJ-NPR-Y])$/);
  if (!m) return false;
  if (!plausibleDate(Number(m[1]), Number(m[2])) || Number(m[4]) < 2) return false;
  return HETU_CHECK[Number(m[1]! + m[2]! + m[3]! + m[4]!) % 31] === m[5];
}

const FNR_W1 = [3, 7, 6, 1, 8, 9, 4, 5, 2];
const FNR_W2 = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
/** Norway fødselsnummer (and D- and H-numbers): 11 digits, two mod-11 check digits. */
export function fodselsnummerValid(value: string): boolean {
  const d = onlyDigits(value);
  if (d.length !== 11) return false;
  const day = Number(d.slice(0, 2));
  const month = Number(d.slice(2, 4));
  if (!plausibleDate(day > 40 ? day - 40 : day, month > 40 ? month - 40 : month)) return false;
  const check = (weights: number[]): number => {
    let sum = 0;
    for (let i = 0; i < weights.length; i++) sum += Number(d[i]) * weights[i]!;
    return (11 - (sum % 11)) % 11;
  };
  return check(FNR_W1) === Number(d[9]) && check(FNR_W2) === Number(d[10]);
}

/**
 * Belgium national register number: YYMMDD, counter, check = 97 − (n mod 97),
 * with a 2 prefixed for people born from 2000. BIS numbers add 20 or 40 to the
 * month. The day is not checked: it is 00 when unknown and runs past 31 once a
 * date's counter is used up.
 */
export function beNationalNumberValid(value: string): boolean {
  const d = onlyDigits(value);
  if (d.length !== 11) return false;
  const month = Number(d.slice(2, 4));
  if (month > 52 || month % 20 > 12) return false;
  const base = Number(d.slice(0, 9));
  const check = Number(d.slice(9));
  return 97 - (base % 97) === check || 97 - ((2_000_000_000 + base) % 97) === check;
}

/** Portugal NIF of a person (first digit 1-3, or 45 for non-residents): weighted mod-11. */
export function ptNifValid(value: string): boolean {
  const d = onlyDigits(value);
  if (d.length !== 9 || !(/^[123]/.test(d) || d.startsWith('45'))) return false;
  let sum = 0;
  for (let i = 0; i < 8; i++) sum += Number(d[i]) * (9 - i);
  return ((11 - (sum % 11)) % 11) % 10 === Number(d[8]);
}

/** South Africa ID number: YYMMDD, citizenship digit 0-2, Luhn over all 13 digits. */
export function zaIdValid(value: string): boolean {
  const d = onlyDigits(value);
  if (d.length !== 13 || d[10]! > '2') return false;
  if (!plausibleDate(Number(d.slice(4, 6)), Number(d.slice(2, 4)))) return false;
  return luhnCheck(d);
}

const CURP_STATES = new Set([
  'AS', 'BC', 'BS', 'CC', 'CH', 'CL', 'CM', 'CS', 'DF', 'DG', 'GR', 'GT', 'HG', 'JC', 'MC', 'MN', 'MS',
  'NE', 'NL', 'NT', 'OC', 'PL', 'QR', 'QT', 'SL', 'SP', 'SR', 'TC', 'TL', 'TS', 'VZ', 'YN', 'ZS',
]);
/**
 * Mexico CURP: 18 characters, birth date, sex, state, check digit. The check
 * alphabet is 0-9, A-N, Ñ, O-Z, so O-Z count one higher than their place in A-Z.
 */
export function curpValid(value: string): boolean {
  const m = value.match(/^[A-Z]{4}(\d{2})(\d{2})(\d{2})[HM]([A-Z]{2})[B-DF-HJ-NP-TV-Z]{3}[0-9A-Z]\d$/);
  if (!m || !plausibleDate(Number(m[3]), Number(m[2])) || !CURP_STATES.has(m[4]!)) return false;
  let sum = 0;
  for (let i = 0; i < 17; i++) {
    const c = value.charCodeAt(i);
    const v = c <= 57 ? c - 48 : c <= 78 ? c - 55 : c - 54;
    sum += v * (18 - i);
  }
  return (10 - (sum % 10)) % 10 === Number(value[17]);
}

/** Chile RUT / RUN: 7-8 digits and a mod-11 check character (10 is K, 11 is 0). */
export function rutValid(value: string): boolean {
  const m = value.replace(/[ \t\n\x0B\f\r.-]/g, '').toUpperCase().match(/^(\d{7,8})([0-9K])$/);
  if (!m) return false;
  let sum = 0;
  let weight = 2;
  for (let i = m[1]!.length - 1; i >= 0; i--) {
    sum += Number(m[1]![i]) * weight;
    weight = weight === 7 ? 2 : weight + 1;
  }
  const r = 11 - (sum % 11);
  return (r === 11 ? '0' : r === 10 ? 'K' : String(r)) === m[2];
}

const CUIT_WEIGHTS = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
/**
 * Argentina CUIL / CUIT of a person (prefix 20, 23, 24 or 27): weighted mod-11.
 * A check value of 10 is accepted as 9, the digit used for it in practice.
 */
export function cuitValid(value: string): boolean {
  const d = onlyDigits(value);
  if (d.length !== 11 || !/^2[0347]/.test(d)) return false;
  let sum = 0;
  for (let i = 0; i < 10; i++) sum += Number(d[i]) * CUIT_WEIGHTS[i]!;
  const r = sum % 11;
  return (r === 0 ? 0 : r === 1 ? 9 : 11 - r) === Number(d[10]);
}

const NRIC_WEIGHTS = [2, 7, 6, 5, 4, 3, 2];
/** Singapore NRIC / FIN (S, T, F, G series): weighted mod-11 check letter. */
export function nricValid(value: string): boolean {
  const m = value.match(/^([STFG])(\d{7})([A-Z])$/);
  if (!m) return false;
  let sum = m[1] === 'T' || m[1] === 'G' ? 4 : 0;
  for (let i = 0; i < 7; i++) sum += Number(m[2]![i]) * NRIC_WEIGHTS[i]!;
  const letters = m[1] === 'S' || m[1] === 'T' ? 'JZIHGFEDCBA' : 'XWUTRQPNMLK';
  return letters[sum % 11] === m[3];
}

/** Greece AMKA: DDMMYY birth date, serial, Luhn over all 11 digits. */
export function amkaValid(value: string): boolean {
  const d = onlyDigits(value);
  if (d.length !== 11) return false;
  if (!plausibleDate(Number(d.slice(0, 2)), Number(d.slice(2, 4)))) return false;
  return luhnCheck(d);
}

const NINO_UNUSED_PREFIXES = new Set(['BG', 'GB', 'KN', 'NK', 'NT', 'TN', 'ZZ']);
/**
 * UK National Insurance number. No checksum exists; HMRC's allocation rules
 * (letters never used in the prefix, prefixes never issued, suffix A-D) are checked.
 */
export function ninoValid(value: string): boolean {
  const n = value.replace(/ /g, '');
  if (!/^[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]$/.test(n)) return false;
  return !NINO_UNUSED_PREFIXES.has(n.slice(0, 2));
}
