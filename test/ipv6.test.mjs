import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { redact } from '../dist/index.js';
import { loadPack } from '../dist/pack.js';

const pack = loadPack(JSON.parse(readFileSync(new URL('../spec/detectors.json', import.meta.url), 'utf8')));
const MASK = '[REDACTED IPv6]';

const engines = [
  ['built-in', (text) => redact(text, { enable: ['ipv6'] })],
  ['portable pack', (text) => redact(text, { enable: ['ipv6'], detectors: pack.detectors })],
];

const addresses = [
  '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
  '2001:db8::8a2e:370:7334',
  '2001:db8:0:0:1:0:0:1',
  'fe80::1',
  '::1',
  '2001:db8::',
  '1:2:3:4:5:6:7::',
  'fe80::1:2:3:4:5:6',
  '::ffff:192.168.1.10',
  '64:ff9b::192.0.2.33',
];

const notAddresses = [
  'started at 12:30:45 and ended 13:05:10',
  '35=D|52=20261118-12:30:45.123|10=092',
  'nic 00:1b:44:11:3a:b7',
  'std::vector and dead::beef and Foo::abc',
  'x2001:db8::1y',
];

for (const [name, run] of engines) {
  test(`${name}: an IPv6 address is masked whole, never in part`, () => {
    for (const address of addresses) {
      assert.equal(run(`peer ${address} up`), `peer ${MASK} up`, address);
    }
  });

  test(`${name}: an address in brackets or with a prefix length keeps its punctuation`, () => {
    assert.equal(run('[2001:db8::1]:8080'), `[${MASK}]:8080`);
    assert.equal(run('route 2001:db8::/32 via fe80::1'), `route ${MASK}/32 via ${MASK}`);
  });

  test(`${name}: clock times, MAC addresses and code scopes are left alone`, () => {
    for (const text of notAddresses) assert.equal(run(text), text);
  });
}
