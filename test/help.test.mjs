// The help system is a documentation surface that ships as code, so it is
// tested like one: every topic must render, every topic must be reachable, and
// a wrong name must point somewhere useful instead of just failing.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { HELP, TOPICS, renderHelp, topicIndex } from '../dist/help.js';
import { DETECTORS } from '../dist/index.js';

const cli = fileURLToPath(new URL('../bin/flare-redact.mjs', import.meta.url));
const gatewayCli = fileURLToPath(new URL('../bin/flare-gateway.mjs', import.meta.url));

function run(bin, args) {
  return spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8' });
}

test('bare help prints the summary', () => {
  const result = run(cli, ['help']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout, HELP);
});

test('every topic renders and is listed in the index', () => {
  const index = topicIndex();
  for (const topic of TOPICS) {
    const { text, code } = renderHelp(topic.name);
    assert.equal(code, 0, `${topic.name} must resolve`);
    assert.ok(text.trim().length > 200, `${topic.name} must actually explain something`);
    assert.ok(index.includes(topic.name), `${topic.name} must appear in the index`);
    assert.ok(index.includes(topic.summary), `${topic.name} summary must appear in the index`);
  }
});

test('topic names are unique and never collide with a detector id', () => {
  const names = TOPICS.map((topic) => topic.name);
  assert.equal(new Set(names).size, names.length, 'topic names must be unique');
  const ids = new Set(DETECTORS.map((detector) => detector.id));
  // A collision would silently shadow the detector page, so it is an error
  // rather than a preference.
  for (const name of names) assert.ok(!ids.has(name), `topic "${name}" shadows a detector`);
});

test('a detector id is a help topic', () => {
  const { text, code } = renderHelp('email');
  assert.equal(code, 0);
  assert.match(text, /DETECTOR email/);
  assert.match(text, /on by default/);
  assert.match(text, /--only email/);
});

test('an off-by-default detector says how to turn it on', () => {
  const off = DETECTORS.find((detector) => !detector.default);
  const { text } = renderHelp(off.id);
  assert.match(text, new RegExp(`--enable ${off.id}`));
});

test('an unknown topic suggests the nearest name and exits 2', () => {
  const { text, code } = renderHelp('vaults');
  assert.equal(code, 2);
  assert.match(text, /No help for "vaults"/);
  assert.match(text, /Did you mean: vault\?/);
  assert.match(text, /HELP TOPICS/);
});

test('an unknown topic with no near match still lists the topics', () => {
  const { text, code } = renderHelp('zzzzzzzz');
  assert.equal(code, 2);
  assert.doesNotMatch(text, /Did you mean/);
  assert.match(text, /HELP TOPICS/);
});

test('help topics is reachable from the command line and names every topic', () => {
  const result = run(cli, ['help', 'topics']);
  assert.equal(result.status, 0);
  for (const topic of TOPICS) assert.ok(result.stdout.includes(topic.name));
});

test('an unresolved topic goes to stderr, not stdout', () => {
  const result = run(cli, ['help', 'nonsense-topic']);
  assert.equal(result.status, 2);
  assert.equal(result.stdout, '', 'a failure must not pollute a piped stdout');
  assert.match(result.stderr, /HELP TOPICS/);
});

test('the gateway answers to bare help as well as --help', () => {
  for (const args of [['help'], ['--help'], ['-h']]) {
    const result = run(gatewayCli, args);
    assert.equal(result.status, 0, `flare-gateway ${args.join(' ')}`);
    assert.match(result.stdout, /flare-redact gateway —/);
  }
  const throughParent = run(cli, ['gateway', 'help']);
  assert.equal(throughParent.status, 0);
  assert.match(throughParent.stdout, /flare-redact gateway —/);
});

test('an unknown flag points at the help instead of only complaining', () => {
  const main = run(cli, ['--nope']);
  assert.equal(main.status, 2);
  assert.match(main.stderr, /unknown option: --nope/);
  assert.match(main.stderr, /flare-redact help topics/);

  const gateway = run(gatewayCli, ['--nope']);
  assert.equal(gateway.status, 2);
  assert.match(gateway.stderr, /flare-redact gateway help/);
});

test('the summary tells you the help exists', () => {
  assert.match(HELP, /flare-redact help \[topic\]/);
  assert.match(HELP, /help topics/);
});

test('the sdks topic does not promise an install that does not work', () => {
  const { text } = renderHelp('sdks');
  // The Python and Rust engines are not on PyPI or crates.io; documenting the
  // registry commands would send people to a 404.
  assert.doesNotMatch(text, /pip install flare-redact\s*$/m);
  assert.doesNotMatch(text, /cargo add flare-redact/);
  assert.match(text, /git\+https:\/\/github\.com\/flare-collection\/flare-redact/);
  assert.match(text, /go get github\.com\/flare-collection\/flare-redact\/sdk\/go/);
});
