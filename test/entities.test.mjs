// The model-free entity recogniser: labels, options, transforms and the cost of hostile input.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ENTITY_LABELS,
  createEntityRecognizer,
  createVault,
  recognizeEntities,
  redact,
  scan,
} from '../dist/index.js';
import { recognizeEntities as fromSubpath } from '../dist/entities.js';

const spans = (text, options) =>
  recognizeEntities(text, options).map((f) => [f.detector, text.slice(f.start, f.end)]);

test('the label set matches the privacy-filter categories', () => {
  assert.deepEqual([...ENTITY_LABELS], [
    'private_person', 'private_address', 'private_phone', 'private_date',
    'account_number', 'private_handle', 'private_url', 'secret',
  ]);
  assert.equal(fromSubpath, recognizeEntities);
});

test('a support message yields typed spans for every kind of value', () => {
  const text = 'Hi, my name is Alice Johnson and I live at 221B Baker Street, London NW1 6XE. '
    + 'Call me at 415-555-0132. DOB: 03/04/1985, customer number CX-55821-7, '
    + 'my password is hunter2, find me at @alice_codes or https://www.linkedin.com/in/alice-johnson-1234';
  assert.deepEqual(spans(text), [
    ['private_person', 'Alice Johnson'],
    ['private_address', '221B Baker Street, London NW1 6XE'],
    ['private_phone', '415-555-0132'],
    ['private_date', '03/04/1985'],
    ['account_number', 'CX-55821-7'],
    ['secret', 'hunter2'],
    ['private_handle', '@alice_codes'],
    ['private_url', 'https://www.linkedin.com/in/alice-johnson-1234'],
  ]);
});

test('names, addresses and phones are found in the library languages', () => {
  const cases = [
    ['Ich heiße Jürgen Müller und wohne in der Hauptstraße 5, 10115 Berlin.', [['private_person', 'Jürgen Müller'], ['private_address', 'Hauptstraße 5, 10115 Berlin']]],
    ["Je m'appelle Camille Lefèvre, j'habite au 12 rue de la Paix, 75002 Paris.", [['private_person', 'Camille Lefèvre'], ['private_address', '12 rue de la Paix, 75002 Paris']]],
    ['Soy Carlos Ruiz, vivo en Calle Mayor 15, 28013 Madrid.', [['private_person', 'Carlos Ruiz'], ['private_address', 'Calle Mayor 15, 28013 Madrid']]],
    ['Meu telefone é (11) 91234-5678.', [['private_phone', '(11) 91234-5678']]],
    ['Mój numer telefonu to 601 234 567.', [['private_phone', '601 234 567']]],
    ['Salam, mənim adım Nigar Əliyeva. Ünvan: Nizami küçəsi 25, Bakı.', [['private_person', 'Nigar Əliyeva'], ['private_address', 'Nizami küçəsi 25, Bakı']]],
    ['Меня зовут Ольга Петрова, дата рождения 12.05.1990.', [['private_person', 'Ольга Петрова'], ['private_date', '12.05.1990']]],
    ['我的名字是李华，住在北京市朝阳区建国路88号。', [['private_person', '李华'], ['private_address', '北京市朝阳区建国路88号']]],
    ['私の名前は田中太郎です。住所は東京都千代田区丸の内1丁目2番3号です。', [['private_person', '田中太郎'], ['private_address', '東京都千代田区丸の内1丁目2番3号']]],
    ['저는 김민준입니다. 주소는 서울특별시 강남구 테헤란로 123 입니다.', [['private_person', '김민준'], ['private_address', '서울특별시 강남구 테헤란로 123']]],
    ['مرحبا، اسمي أحمد علي.', [['private_person', 'أحمد علي']]],
    ['मेरा नाम राहुल शर्मा है।', [['private_person', 'राहुल शर्मा']]],
  ];
  for (const [text, expected] of cases) assert.deepEqual(spans(text), expected, text);
});

test('ordinary prose, code and config produce no findings', () => {
  const clean = [
    'We deployed version 2.3.1 to Production Cluster on Monday.',
    'Order #48213 shipped via UPS 3 days later.',
    'Google released Gemini and Microsoft updated Copilot.',
    'Mercedes and BMW reported strong sales in March 2024.',
    'IP address 10.0.0.1 resolved to the staging host.',
    'The password is incorrect, please try again.',
    'Route 66 is a famous highway.',
    '@Override\npublic String toString() { return name; }',
    'name: api-gateway\nreplicas: 3',
    'Jordan is a country in the Middle East.',
    'The Lincoln Memorial attracts millions of visitors.',
    'SELECT name, email FROM users WHERE id = 42;',
    'Ich bin Arzt und arbeite in Berlin.',
    '저는 선생님입니다.',
    'Download the report from https://github.com/features or https://example.com/reports/2024.pdf.',
  ];
  for (const text of clean) assert.deepEqual(spans(text), [], text);
});

test('a confident name is followed to its later mentions', () => {
  const text = 'Please contact Mrs. Anna Kowalski about the lease. Kowalski signed it in May.';
  assert.deepEqual(spans(text), [
    ['private_person', 'Anna Kowalski'],
    ['private_person', 'Kowalski'],
  ]);
  assert.deepEqual(spans(text, { propagate: false }), [['private_person', 'Anna Kowalski']]);
});

test('labels and minConfidence narrow the output', () => {
  const text = 'My name is Alice Johnson, phone 415-555-0132.';
  assert.deepEqual(spans(text, { labels: ['private_phone'] }), [['private_phone', '415-555-0132']]);
  for (const f of recognizeEntities(text)) assert.ok(f.confidence >= 0.5 && f.confidence <= 1);
  assert.deepEqual(spans(text, { minConfidence: 1.01 }), []);
});

test('entities are opt-in and plug into redact, scan, disable and only', () => {
  const text = 'Spoke with Emily Clarke, card ending in 4242.';
  assert.equal(redact(text), text);
  assert.equal(redact(text, { enable: ['entities'] }), 'Spoke with [REDACTED PERSON], card ending in [REDACTED ACCOUNT].');
  assert.equal(redact(text, { entities: true }), redact(text, { enable: ['entities'] }));
  assert.equal(
    redact(text, { enable: ['entities'], disable: ['account_number'] }),
    'Spoke with [REDACTED PERSON], card ending in 4242.',
  );
  assert.equal(redact(text, { entities: { labels: ['account_number'] } }), 'Spoke with Emily Clarke, card ending in [REDACTED ACCOUNT].');
  assert.equal(redact(text, { only: ['private_person'] }), 'Spoke with [REDACTED PERSON], card ending in 4242.');
  const findings = scan(text, { enable: ['entities'] });
  assert.deepEqual(findings.map((f) => f.detector), ['private_person', 'account_number']);
});

test('a recognised person beats the label-only person detector on the same text', () => {
  const text = 'my name is Alice Johnson and I live in Leeds';
  const findings = scan(text, { enable: ['contextual', 'entities'] });
  const person = findings.find((f) => f.detector === 'private_person');
  assert.ok(person);
  assert.equal(text.slice(person.start, person.end), 'Alice Johnson');
  assert.ok(!findings.some((f) => f.detector === 'person_name'));
});

test('a reset link carrying a token is masked whole as a critical URL', () => {
  const text = 'Reset link: https://example.com/reset?email=anna%40example.com&token=9f8e7d';
  assert.equal(redact(text, { enable: ['entities'] }), 'Reset link: [REDACTED URL]');
  const url = scan(text, { enable: ['entities'] }).find((f) => f.detector === 'private_url');
  assert.equal(url.risk, 'critical');
});

test('surrogate mode swaps people, addresses and phones for stand-ins', () => {
  const text = 'My name is Alice Johnson, call me at 415-555-0132.';
  const out = redact(text, { enable: ['entities'], mode: 'surrogate', transformSecret: 'test-secret' });
  assert.doesNotMatch(out, /Alice|Johnson|415-555-0132/);
  assert.equal(out, redact(text, { enable: ['entities'], mode: 'surrogate', transformSecret: 'test-secret' }));
});

test('a vault restores recognised entities', () => {
  const vault = createVault({ enable: ['entities'] });
  const text = 'Patient: Maria García, DOB: 03/04/1985, MRN 00482913.';
  const masked = vault.redact(text);
  assert.doesNotMatch(masked, /Maria|García|1985|00482913/);
  assert.equal(vault.restore(masked), text);
});

test('the recogniser works as a SemanticProvider', () => {
  const provider = createEntityRecognizer({ labels: ['private_person'] });
  const out = redact('Thanks,\nGrace Hopper', { semanticProvider: provider });
  assert.doesNotMatch(out, /Grace Hopper/);
});

test('hostile input stays linear', () => {
  const N = 200_000;
  const inputs = [
    'A'.repeat(N),
    'Alice '.repeat(N / 6),
    'Mr. Alice Johnson-Smith '.repeat(N / 24),
    'Van de Van de '.repeat(N / 14),
    '北京市朝阳区'.repeat(N / 6),
    '서울특별시 강남구 '.repeat(N / 10),
    '東京都千代田区丸の内'.repeat(N / 10),
    '1 '.repeat(N / 2),
    'address: 12 '.repeat(N / 12),
    ('appointment ' + 'on '.repeat(20)).repeat(N / 72),
    '12 Main Main Main Main '.repeat(N / 23),
    'https://x.com/?email='.repeat(N / 21),
    'password is '.repeat(N / 12),
    'Name: Alice\nAddress: 1 '.repeat(N / 24),
  ];
  for (const text of inputs) {
    const started = performance.now();
    recognizeEntities(text);
    const ms = performance.now() - started;
    assert.ok(ms < 3000, `${JSON.stringify(text.slice(0, 24))}: ${ms.toFixed(0)} ms`);
  }
});
