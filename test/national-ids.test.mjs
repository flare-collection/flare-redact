import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact, scan, isClean } from '../dist/index.js';
import {
  frNirValid,
  aadhaarValid,
  tfnValid,
  cnResidentIdValid,
  jpMyNumberValid,
} from '../dist/checksums.js';
import * as checksums from '../dist/checksums.js';

// Every sample is either the well-known documentation example for the format
// or was generated with an independent implementation of the checksum.

test('fr_nir validates the INSEE key, including Corsican departments', () => {
  assert.ok(frNirValid('2690549588157 80'.replace(' ', '')));
  assert.ok(frNirValid('1 55 08 2A 168 025 50'));
  assert.ok(!frNirValid('269054958815781'));
  const text = 'assuré 2 69 05 49 588 157 80 dossier';
  assert.equal(scan(text, { enable: ['fr'] })[0]?.detector, 'fr_nir');
  assert.equal(redact(text, { enable: ['fr'] }).includes('588'), false);
  assert.ok(isClean(text));
});

test('in_aadhaar validates the Verhoeff checksum', () => {
  assert.ok(aadhaarValid('234123412346'));
  assert.ok(aadhaarValid('987654321096'));
  assert.ok(!aadhaarValid('234123412347'));
  assert.ok(!aadhaarValid('123412341234'));
  assert.equal(scan('uid 2341 2341 2346 ok', { enable: ['in'] })[0]?.detector, 'in_aadhaar');
  assert.ok(isClean('uid 2341 2341 2346 ok'));
});

test('au_tfn validates the weighted mod-11 checksum', () => {
  assert.ok(tfnValid('123456782'));
  assert.ok(!tfnValid('123456783'));
  assert.ok(!tfnValid('999999999'));
  assert.equal(scan('tfn 123 456 782', { enable: ['au'] })[0]?.detector, 'au_tfn');
});

test('cn_resident_id validates the ISO 7064 check character and birth date', () => {
  assert.ok(cnResidentIdValid('11010519491231002X'));
  assert.ok(cnResidentIdValid('11010519491231002x'));
  assert.ok(!cnResidentIdValid('110105194912310021'));
  assert.ok(!cnResidentIdValid('11010519491331002X'));
  assert.equal(scan('id 11010519491231002X', { enable: ['cn'] })[0]?.detector, 'cn_resident_id');
});

test('jp_my_number validates the weighted mod-11 check digit', () => {
  assert.ok(jpMyNumberValid('123456789018'));
  assert.ok(jpMyNumberValid('867530901231'));
  assert.ok(!jpMyNumberValid('123456789019'));
  assert.equal(scan('番号 1234 5678 9018', { enable: ['jp'] })[0]?.detector, 'jp_my_number');
});

test('new national IDs stay opt-in and are groupable by the pii tag', () => {
  const text = 'nir 2690549588157 80 aadhaar 234123412346 tfn 123456782';
  assert.ok(isClean(text));
  const detectors = scan(text.replace(' 80', '80'), { enable: ['pii'] }).map((f) => f.detector);
  assert.ok(detectors.includes('in_aadhaar'));
});

// Checksum-validated IDs for 14 more countries. Every valid sample was generated
// for these tests and cross-checked with an independent implementation of each
// algorithm; none belongs to a person. Each near-miss passes the checksum (or the
// shape) but breaks one other rule: a date, a prefix, a reserved letter.
const MORE_IDS = [
  {
    id: 'ro_cnp', tag: 'ro', validate: checksums.cnpValid,
    valid: ['1850101401238', '5050505123453'],
    invalid: ['1850101401239', '1851301401236', '0850101401238'],
    text: 'CNP 1850101401238',
  },
  {
    id: 'se_personnummer', tag: 'se', validate: checksums.personnummerValid,
    valid: ['850709-1232', '200505054569', '850769-1239'],
    invalid: ['850709-1233', '851309-1234', '170505054569'],
    text: 'personnummer 850709-1232',
  },
  {
    id: 'fi_hetu', tag: 'fi', validate: checksums.hetuValid,
    valid: ['010185-123B', '150605A456H'],
    invalid: ['010185-123C', '320185-123B', '010185-001K', '010185-123b'],
    text: 'henkilötunnus 010185-123B',
  },
  {
    id: 'no_fodselsnummer', tag: 'no', validate: checksums.fodselsnummerValid,
    valid: ['01018512366', '010185 12447', '41018510187', '01458512309'],
    invalid: ['01018512367', '32018512318'],
    text: 'fødselsnummer 010185 12366',
  },
  {
    id: 'be_national_number', tag: 'be', validate: checksums.beNationalNumberValid,
    valid: ['85.01.01-123.87', '05050500186', '85210112333'],
    invalid: ['85010112388', '85130112374'],
    text: 'rijksregisternummer 85.01.01-123.87',
  },
  {
    id: 'pt_nif', tag: 'pt', validate: checksums.ptNifValid,
    valid: ['123456789', '234 567 899', '451234561'],
    invalid: ['123456788', '512345678'],
    text: 'NIF 123 456 789',
  },
  {
    id: 'za_id', tag: 'za', validate: checksums.zaIdValid,
    valid: ['8501015123085', '0505056000183'],
    invalid: ['8501015123086', '8513015123080', '8501015123383'],
    text: 'ID number 850101 5123 08 5',
  },
  {
    id: 'mx_curp', tag: 'mx', validate: checksums.curpValid,
    valid: ['ABCD850101HDFBCD00', 'WXYZ050505MNLRSTA4'],
    invalid: ['ABCD850101HDFBCD01', 'ABCD851301HDFBCD06', 'ABCD850101HXXBCD00'],
    text: 'CURP ABCD850101HDFBCD00',
  },
  {
    id: 'cl_rut', tag: 'cl', validate: checksums.rutValid,
    valid: ['12.345.678-5', '7.654.321-6', '10000013-K', '10000013-k'],
    invalid: ['12.345.678-6', '10000013-0'],
    text: 'RUT 12.345.678-5',
  },
  {
    id: 'ar_cuit', tag: 'ar', validate: checksums.cuitValid,
    valid: ['20-12345678-6', '27876543219'],
    invalid: ['20-12345678-7', '30123456781'],
    text: 'CUIL 20-12345678-6',
  },
  {
    id: 'sg_nric', tag: 'sg', validate: checksums.nricValid,
    valid: ['S1234567D', 'T1234567J', 'F1234567N', 'G1234567X'],
    invalid: ['S1234567A', 'G1234567N', 's1234567d'],
    text: 'NRIC S1234567D',
  },
  {
    id: 'il_teudat_zehut', tag: 'il', validate: checksums.luhnCheck,
    valid: ['123456782', '023456783'],
    invalid: ['123456783'],
    text: 'teudat zehut 12345678-2',
  },
  {
    id: 'gr_amka', tag: 'gr', validate: checksums.amkaValid,
    valid: ['01018512341', '31120543215'],
    invalid: ['01018512342', '32018512346'],
    text: 'AMKA 01018512341',
  },
  {
    id: 'uk_nino', tag: 'gb', validate: checksums.ninoValid,
    // QQ 12 34 56 C is HMRC's documentation placeholder: Q is never a prefix letter.
    valid: ['AB 12 34 56 C', 'AB123456C'],
    invalid: ['QQ 12 34 56 C', 'GB 12 34 56 A', 'AO 12 34 56 A', 'AB 12 34 56 E'],
    text: 'National Insurance number AB 12 34 56 C',
  },
];

for (const c of MORE_IDS) {
  test(`${c.id}: known-valid samples pass, near-misses fail`, () => {
    for (const v of c.valid) assert.equal(c.validate(v), true, `expected valid: ${v}`);
    for (const v of c.invalid) assert.equal(c.validate(v), false, `expected invalid: ${v}`);
  });

  test(`${c.id}: opt-in by its country tag, masked whole`, () => {
    assert.ok(!scan(c.text).some((f) => f.detector === c.id), 'off by default');
    assert.deepEqual(scan(c.text, { enable: [c.tag] }).map((f) => f.detector), [c.id]);
    const out = redact(c.text, { enable: [c.tag] });
    assert.ok(out.endsWith('[REDACTED ID]'), out);
    assert.equal(scan(c.text, { preset: 'llm' })[0]?.detector, c.id, 'reached by the llm preset');
  });
}

test('a South African ID is masked as an ID, not as a card, once za is on', () => {
  const text = 'ID 8501015123085';
  assert.equal(redact(text), 'ID **** **** **** 3085', 'without za it is still caught by the card detector');
  assert.equal(redact(text, { enable: ['za'] }), 'ID [REDACTED ID]');
});

test('the new IDs leave nearby ordinary values alone', () => {
  const text = 'build 2025.11.18 ticket AB-123456 total 1234.56 port 8080';
  assert.deepEqual(scan(text, { enable: MORE_IDS.map((c) => c.tag) }), []);
});
