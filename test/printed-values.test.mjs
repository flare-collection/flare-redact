// GHSA-2jx3-6xv8-798v: grouped values printed with spaces, and PEM keys whose
// END footer is missing or carries the wrong label, must not pass through.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact, scan } from '../dist/index.js';
import { redactStream } from '../dist/stream.js';
import { IBAN_LENGTHS, ibanPrintedPattern, ibanValid, ssnValid } from '../dist/checksums.js';
import { readFileSync } from 'node:fs';

const BODY = 'MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAq7BFUpkGp3+LQmlQ';

test('printed IBANs are masked by the default policy', () => {
  assert.equal(redact('iban GB82 WEST 1234 5698 7654 32'), 'iban [REDACTED IBAN]');
  assert.equal(redact('DE89 3704 0044 0532 0130 00'), '[REDACTED IBAN]');
  assert.equal(redact('FR76 3000 6000 0112 3456 7890 189'), '[REDACTED IBAN]');
  assert.equal(redact('MT84 MALT 0110 0001 2345 MTLC AST0 01S'), '[REDACTED IBAN]');
  assert.equal(redact('NO93 8601 1117 947'), '[REDACTED IBAN]');
});

test('a printed IBAN stops at its registry length, so a following word cannot break it', () => {
  assert.equal(redact('IBAN: BE68 5390 0754 7034 EUR'), 'IBAN: [REDACTED IBAN] EUR');
  assert.equal(redact('IBAN BE68 5390 0754 7034 BIC: GKCCBEBB'), 'IBAN [REDACTED IBAN] BIC: GKCCBEBB');
  assert.equal(redact('DE89 3704 0044 0532 0130 00 USD'), '[REDACTED IBAN] USD');
});

test('no-break, thin and narrow no-break spaces count as IBAN group separators', () => {
  for (const sep of ['\u00a0', '\u2009', '\u202f']) {
    const iban = ['GB82', 'WEST', '1234', '5698', '7654', '32'].join(sep);
    assert.equal(redact(`pay ${iban} now`), 'pay [REDACTED IBAN] now', JSON.stringify(sep));
  }
});

test('a printed IBAN with a wrong check digit is left alone', () => {
  assert.equal(redact('GB82 WEST 1234 5698 7654 33'), 'GB82 WEST 1234 5698 7654 33');
  assert.equal(ibanValid('GB82 WEST 1234 5698 7654 32'), true);
  assert.equal(ibanValid('GB82\u00a0WEST\u00a01234\u00a05698\u00a07654\u00a032'), true);
});

test('the IBAN registry produces one printed shape per country length', () => {
  assert.equal(IBAN_LENGTHS.GB, 22);
  assert.equal(IBAN_LENGTHS.NO, 15);
  assert.equal(IBAN_LENGTHS.RU, 33);
  for (const [country, length] of Object.entries(IBAN_LENGTHS)) {
    assert.match(country, /^[A-Z]{2}$/);
    assert.ok(length >= 15 && length <= 34, `${country}: ${length}`);
  }
  const re = new RegExp(`^(?:${ibanPrintedPattern(' ')})$`);
  assert.ok(re.test('GB82 WEST 1234 5698 7654 32'));
  assert.ok(!re.test('GB82 WEST 1234 5698 7654 3'));
  assert.ok(!re.test('GB82 WEST 1234 5698 7654 32 EUR'));
});

test('the FRS-1 pack carries the same printed IBAN shapes as the Node detector', () => {
  const pack = JSON.parse(readFileSync(new URL('../spec/detectors.json', import.meta.url), 'utf8'));
  const iban = pack.detectors.find((d) => d.id === 'iban');
  const printed = ibanPrintedPattern('[ \\xA0\u2009\u202F]');
  assert.equal(iban.pattern, `(?:[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}|${printed})`);
});

test('spaced SSN, CPF and German tax IDs are masked like their compact forms', () => {
  assert.equal(redact('123 45 6789', { enable: ['pii'] }), '[REDACTED ID]');
  assert.equal(redact('123-45-6789', { enable: ['pii'] }), '[REDACTED ID]');
  assert.equal(redact('111 444 777 35', { enable: ['pii'] }), '[REDACTED ID]');
  assert.equal(redact('IdNr 26 954 371 827', { enable: ['de'] }), 'IdNr [REDACTED ID]');
  assert.equal(ssnValid('123 45 6789'), true);
  assert.equal(ssnValid('000 45 6789'), false);
  assert.equal(redact('4242 4242 4242 4242', { enable: ['pii'] }), '**** **** **** 4242');
});

test('a private key with a mismatched END footer is masked through that footer', () => {
  const text = `-----BEGIN RSA PRIVATE KEY-----\n${BODY}\n-----END CERTIFICATE-----\nnext line`;
  assert.equal(redact(text), '[REDACTED PRIVATE KEY]\nnext line');
  assert.equal(
    redact(`-----BEGIN OPENSSH PRIVATE KEY-----\n${BODY}\n-----END SSH-----`),
    '[REDACTED PRIVATE KEY]',
  );
});

test('a truncated private key fails closed to the end of the input', () => {
  assert.equal(redact(`log: -----BEGIN RSA PRIVATE KEY-----\n${BODY}`), 'log: [REDACTED PRIVATE KEY]');
  const findings = scan(`-----BEGIN PRIVATE KEY-----\n${BODY}\n${BODY}`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].detector, 'private_key');
});

test('PGP private key blocks and two keys in one string are both caught', () => {
  assert.equal(
    redact(`-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n${BODY}\n-----END PGP PRIVATE KEY BLOCK-----\ndone`),
    '[REDACTED PRIVATE KEY]\ndone',
  );
  const two = `a -----BEGIN RSA PRIVATE KEY-----\n${BODY}\n-----END RSA PRIVATE KEY----- b `
    + `-----BEGIN EC PRIVATE KEY-----\n${BODY}\n-----END EC PRIVATE KEY----- c`;
  assert.equal(redact(two), 'a [REDACTED PRIVATE KEY] b [REDACTED PRIVATE KEY] c');
});

test('the private key pattern stays linear on many unterminated footers', () => {
  // Each "-----END AAAAAAAAAAx" starts a footer that never closes.
  const hostile = '-----BEGIN RSA PRIVATE KEY-----\n' + '-----END AAAAAAAAAAx'.repeat(50_000);
  const started = performance.now();
  assert.equal(redact(hostile), '[REDACTED PRIVATE KEY]');
  assert.ok(performance.now() - started < 2000);
});

function run(input) {
  return new Promise((resolve, reject) => {
    const s = redactStream();
    const chunks = [];
    s.on('data', (c) => chunks.push(c.toString()));
    s.on('end', () => resolve(chunks.join('')));
    s.on('error', reject);
    for (const part of input) s.write(part);
    s.end();
  });
}

test('the stream closes a key record on a mismatched footer and keeps later lines', async () => {
  const out = await run([
    'before\n-----BEGIN RSA PRIVATE KEY-----\n',
    `${BODY}\n-----END CERTIFICATE-----\n`,
    'after\n',
  ]);
  assert.equal(out, 'before\n[REDACTED PRIVATE KEY]\nafter\n');
});

test('the stream buffers a key that begins after an earlier footer on the same line', async () => {
  const out = await run([
    '-----END CERTIFICATE----- -----BEGIN RSA PRIVATE KEY-----\n',
    `${BODY}\n`,
    '-----END RSA PRIVATE KEY-----\nafter\n',
  ]);
  assert.ok(!out.includes(BODY), out);
  assert.match(out, /\[REDACTED PRIVATE KEY\]\nafter\n$/);
});
