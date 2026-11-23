// Snapshot files are committed; a token that reached a rendered component or
// an error message must be masked before the snapshot is written.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import serializer, { createSnapshotSerializer } from '../dist/snapshot.js';

const TOKEN = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';

// A stand-in for the snapshot printer: it asks each serializer again, as the
// real one does, and falls back to JSON.
const print = (value, plugin) => {
  const printer = (v) => (plugin.test(v) ? plugin.serialize(v, {}, '', 0, [], printer) : JSON.stringify(v));
  return printer(value);
};

test('only values that need masking are taken over', () => {
  assert.equal(serializer.test({ a: 1, b: 'plain' }), false);
  assert.equal(serializer.test('plain'), false);
  assert.equal(serializer.test(42), false);
  assert.equal(serializer.test({ auth: `Bearer ${TOKEN}` }), true);
  assert.equal(serializer.test(`key ${TOKEN}`), true);
});

test('masked values go back to the printer once, without looping', () => {
  assert.equal(print({ user: 'ada@example.com', n: 1 }, serializer), '{"user":"a***@***","n":1}');
  assert.equal(print(`token ${TOKEN}`, serializer), '"token ghp_***"');
});

test('options are honoured', () => {
  assert.equal(print('mail ada@example.com', createSnapshotSerializer({ mode: 'label' })), '"mail [REDACTED:email]"');
});
