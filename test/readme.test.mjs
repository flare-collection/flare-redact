// The README is the first page people read: its numbers must match the code.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DETECTORS } from '../dist/index.js';

const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');

test('the detector badge counts the detectors that ship', () => {
  const badge = readme.match(/badge\/detectors-(\d+)-/);
  assert.ok(badge, 'detectors badge');
  assert.equal(Number(badge[1]), DETECTORS.length);
  assert.match(readme, new RegExp(`alt="${DETECTORS.length} detectors"`));
});

test('the language badge matches the flag row', () => {
  const badge = Number(readme.match(/badge\/languages-(\d+)-/)?.[1]);
  const flagRow = readme.split('\n').find((line) => /^\s*🇬🇧/.test(line)) ?? '';
  const flags = flagRow.match(/(?:\p{Regional_Indicator}{2})/gu) ?? [];
  assert.equal(flags.length, badge);
  assert.match(readme, new RegExp(`International by default: ${badge} languages`));
});

test('version and CI badges are live, never typed by hand', () => {
  assert.match(readme, /img\.shields\.io\/npm\/v\/flare-redact/);
  assert.match(readme, /actions\/workflows\/ci\.yml\/badge\.svg\?branch=main/);
  assert.doesNotMatch(readme, /badge\/npm-v?\d/);
});

test('the README uses no long dashes', () => {
  assert.doesNotMatch(readme, /[\u2013\u2014]/);
});
