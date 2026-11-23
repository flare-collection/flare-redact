// Session replays record what users see and type. Mask what is sensitive,
// keep the rest readable, and keep text length so the replay layout holds.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { replayMaskFn, rrwebMasking } from '../dist/replay.js';

const TOKEN = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';

// The parts of a DOM element the masker reads.
const el = (tagName, attrs = {}) => ({
  tagName,
  type: attrs.type,
  id: attrs.id ?? '',
  getAttribute: (name) => attrs[name] ?? null,
});

test('text keeps its length and clean text is untouched', () => {
  const mask = replayMaskFn();
  assert.equal(mask('Support ticket'), 'Support ticket');
  assert.equal(mask('mail ada@example.com now'), 'mail *************** now');
  assert.equal(mask('call +44 20 7946 0958'), 'call *** ** **** ****', 'phone numbers count by default');
  assert.equal(mask(`key ${TOKEN}`), `key ${'*'.repeat(TOKEN.length)}`);
  assert.equal(mask(''), '');
});

test('form fields are masked whole when they hold a credential', () => {
  const mask = replayMaskFn();
  assert.equal(mask('hunter2', el('INPUT', { type: 'password' })), '*******');
  assert.equal(mask('4242424242424242', el('INPUT', { autocomplete: 'cc-number' })), '*'.repeat(16));
  assert.equal(mask('123456', el('input', { autocomplete: 'one-time-code' })), '******');
  assert.equal(mask('k-7c1e0f2a9b', el('INPUT', { name: 'api_key' })), '************');
  assert.equal(mask('Baku', el('INPUT', { name: 'city' })), 'Baku');
  assert.equal(mask('find ada@example.com', el('INPUT', { id: 'q' })), 'find ***************');
  assert.equal(mask('card 4242 4242 4242 4242', el('TEXTAREA')), 'card **** **** **** ****');
  assert.equal(mask('hunter2', el('SPAN', { type: 'password' })), 'hunter2', 'only form fields');
});

test('options: usual masks, labels and an explicit detector choice', () => {
  assert.equal(replayMaskFn({ preserveLength: false })('mail ada@example.com'), 'mail a***@***');
  assert.equal(replayMaskFn({ preserveLength: false })('x', el('INPUT', { type: 'password' })), '***');
  assert.equal(replayMaskFn({ mode: 'label' })('mail ada@example.com'), 'mail [REDACTED:email]');
  assert.equal(replayMaskFn({ only: ['email'] })('call +44 20 7946 0958'), 'call +44 20 7946 0958');
});

test('the cache stays bounded and answers stay the same', () => {
  const mask = replayMaskFn({ cacheSize: 2 });
  for (let i = 0; i < 10; i += 1) assert.equal(mask(`user${i}@example.com`), '*'.repeat(`user${i}@example.com`.length));
  assert.equal(mask('user0@example.com'), '*****************');
});

test('rrwebMasking sends every text node and input through the mask', () => {
  const options = rrwebMasking();
  assert.equal(options.maskAllInputs, true);
  assert.equal(options.maskTextSelector, '*');
  assert.equal(options.maskTextFn('mail ada@example.com', el('P')), 'mail ***************');
  assert.equal(options.maskInputFn('hunter2', el('INPUT', { type: 'password' })), '*******');
});
