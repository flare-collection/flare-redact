// The publish job turns the CHANGELOG section of the released version into the
// GitHub Release body, so every version in package.json needs one.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { releaseNotes } from '../scripts/release-notes.mjs';

const read = (file) => readFileSync(new URL(`../${file}`, import.meta.url), 'utf8');

test('the package version has a CHANGELOG section for its GitHub Release', () => {
  const { version } = JSON.parse(read('package.json'));
  const notes = releaseNotes(read('CHANGELOG.md'), version);
  assert.ok(notes, `CHANGELOG.md needs a "## ${version}" section`);
  assert.doesNotMatch(notes, /^## /m);
});

test('a section ends at the next version and never matches a longer version', () => {
  const changelog = '# Changelog\n\n## 1.10.0 (x)\n\nten\n\n## 1.1.0 (y)\n\none\n';
  assert.equal(releaseNotes(changelog, '1.1.0'), 'one');
  assert.equal(releaseNotes(changelog, '1.10.0'), 'ten');
  assert.equal(releaseNotes(changelog, '1.1'), undefined);
  assert.equal(releaseNotes(changelog, '2.0.0'), undefined);
});
