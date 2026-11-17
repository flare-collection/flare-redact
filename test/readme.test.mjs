// The README is the first page people read: its numbers must match the code.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
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

const guide = readFileSync(new URL('../docs/guide.md', import.meta.url), 'utf8');
/** GitHub's anchor for a heading. */
const slug = (heading) => heading.trim().toLowerCase().replace(/[^\p{L}\p{N}\s_-]/gu, '').replace(/\s/g, '-');
const anchors = new Set(guide.split('\n').filter((l) => /^#{1,4} /.test(l)).map((l) => slug(l.replace(/^#+ /, ''))));

test('every detector count in the README is the real one', () => {
  for (const [, n] of readme.matchAll(/(\d+) detectors/g)) assert.equal(Number(n), DETECTORS.length);
});

test('README links into the guide land on a heading, and its files exist', () => {
  const links = [...readme.matchAll(/docs\/guide\.md#([a-z0-9-]+)/g)].map((m) => m[1]);
  assert.ok(links.length > 5);
  for (const anchor of links) assert.ok(anchors.has(anchor), anchor);
  for (const [, file] of readme.matchAll(/(?:\]\(|href="|src=")([^)"#:]+?)(?:#[^)"]*)?[)"]/g)) {
    assert.ok(existsSync(new URL(`../${file}`, import.meta.url)), file);
  }
});

test('the guide links resolve and it uses no long dashes', () => {
  assert.doesNotMatch(guide, /[–—]/);
  for (const [, file] of guide.matchAll(/(?:\]\(|href="|src=")(\.\.\/[^)"#]+)/g)) {
    assert.ok(existsSync(new URL(`../docs/${file}`, import.meta.url)), file);
  }
  for (const [, anchor] of guide.matchAll(/\]\(#([a-z0-9-]+)\)/g)) assert.ok(anchors.has(anchor), anchor);
});
