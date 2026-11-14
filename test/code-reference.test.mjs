// Scans leave out assignments whose value is code; redaction never does.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { isCodeReference, codeAwareDetectors } from '../dist/code-reference.js';
import { DETECTORS, redact, scan } from '../dist/index.js';

const cli = fileURLToPath(new URL('../bin/flare-redact.mjs', import.meta.url));
const run = (input, ...args) => spawnSync(process.execPath, [cli, ...args], { input, encoding: 'utf8' });

const code = [
  'token = process.env.TOKEN',
  'apiKey = config.apiKey',
  'password: string',
  'api_key = os.environ[',
  'password = os.getenv(',
  'token: ${GITHUB_TOKEN}',
  'token: "${GITHUB_TOKEN}"',
  'PASSWORD=$DB_PASSWORD',
  'password: "$DB_PASSWORD"',
  'secret: "{{ vault_secret }}"',
  'secret: %(secret)s',
  'password: %DB_PASS%',
  'token = token',
  'password = password',
  'password = req.body.password',
  'password = user.password',
  'token = session.authToken',
  'token = getToken()',
  'password: null',
  'secret = None',
  'password: <your-password>',
  'api_key = YOUR_API_KEY',
  'password=********',
  'password = "********"',
  'token: [REDACTED]',
];

const secrets = [
  'password = "hunter2xyz"',
  'password=Sup3rS3cret!',
  'api_key = sk_' + 'test_abcdefghijklmnop',
  'token: "abcd1234efgh"',
  'password=$argon2id$v=19$m=65536',
  'password=$ecret123',
  'password=$2b$10$N9qo8uLOickgx2ZMRZoMye',
  'pwd=<3kittens',
  'password=Pass.word1',
  'password=My.Passw0rd',
  'password=monkey123',
  'secret=supersecret99',
  'PASSWORD=secret',
  '"password": "password"',
  'token = "process.env.TOKEN"',
  'password = "string"',
  `password=${'a.'.repeat(200)}password`,
];

test('code is recognised, and anything that could be a literal is not', () => {
  for (const line of code) assert.equal(isCodeReference(line), true, line);
  for (const line of secrets) assert.equal(isCodeReference(line), false, line);
});

test('redaction is untouched: it masks every assignment, code or not', () => {
  for (const line of [...code, ...secrets]) {
    const [finding] = scan(line).filter((f) => f.detector === 'generic_assignment');
    if (!finding) continue;
    assert.notEqual(redact(line), line, line);
  }
  assert.equal(redact('token = process.env.TOKEN'), 'token = ***');
  assert.equal(redact('password=$argon2id$v=19$m=65536'), 'password=***');
});

test('the code-aware detectors differ only in generic_assignment', () => {
  const aware = codeAwareDetectors(DETECTORS);
  assert.equal(aware.length, DETECTORS.length);
  assert.deepEqual(aware.filter((d, i) => d !== DETECTORS[i]).map((d) => d.id), ['generic_assignment']);
  const [kept] = scan('password=hunter2000', { detectors: aware });
  const [plain] = scan('password=hunter2000');
  assert.deepEqual(kept, plain, 'a real finding keeps its confidence and risk');
  assert.deepEqual(scan('token = process.env.TOKEN', { detectors: aware }), []);
});

test('the CLI scan leaves code out, and --no-code-filter brings it back', () => {
  const source = 'export const token = process.env.TOKEN;\npassword: string;\nconst secret = "hunter2000";\n';
  const filtered = run(source, '--scan');
  assert.equal(filtered.status, 1);
  assert.match(filtered.stdout, /^1 finding:/);
  assert.match(filtered.stdout, /at 3:7/);
  const all = run(source, '--scan', '--no-code-filter');
  assert.match(all.stdout, /^3 findings:/);
  assert.equal(run('export const token = process.env.TOKEN;\n', '--scan').status, 0);
  assert.equal(run('token = process.env.TOKEN\n').stdout, 'token = ***\n', 'plain redaction is not filtered');
});

test('a hostile value costs nothing', () => {
  for (const value of ['a.'.repeat(100_000) + 'b', 'a'.repeat(200_000), '$' + 'A'.repeat(200_000), '?.a'.repeat(60_000)]) {
    const started = performance.now();
    isCodeReference(`password=${value}`);
    assert.ok(performance.now() - started < 50);
  }
});
