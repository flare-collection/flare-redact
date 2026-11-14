// Scans leave out assignments whose value is code; redaction never does.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { withoutCodeAssignments, isCodeAssignment } from '../dist/code-reference.js';
import { redact, scan } from '../dist/index.js';

const cli = fileURLToPath(new URL('../bin/flare-redact.mjs', import.meta.url));
const run = (input, ...args) => spawnSync(process.execPath, [cli, ...args], { input, encoding: 'utf8' });

/** What a filtered scan of `text` reports. */
const report = (text) => withoutCodeAssignments(text, scan(text), () => scan(text, { disable: ['generic_assignment'] }));

const code = [
  'export const token = process.env.TOKEN;',
  'const apiKey = config.apiKey;',
  'password: string;',
  'interface Login { password: string; token: Optional[str] }',
  'function login(password: string, remember: boolean): Promise<void> {',
  'const check = (token: string | null) => token !== null;',
  'secret: ${{ secrets.NPM_TOKEN }}',
  'password: {{ .Values.password | b64enc }}',
  'token = secrets.token_hex(32)',
  'password = os.getenv("DB_PASSWORD")  # set by the deploy',
  'const password = process.env.DB_PASSWORD ?? "";',
  'declare const env: { API_KEY: string }',
  'api_key = os.environ["API_KEY"]',
  'SECRET_KEY = os.environ.get("SECRET_KEY")',
  'password = os.getenv("DB_PASSWORD")',
  "password = os.getenv('DB_PASSWORD', '')",
  'token: ${GITHUB_TOKEN}',
  'token: "${GITHUB_TOKEN}"',
  'PASSWORD=$DB_PASSWORD',
  'export PGPASSWORD="$DB_PASSWORD"',
  'password: "$DB_PASSWORD"',
  'POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}',
  'secret: {{secret}}',
  'secret: %(secret)s',
  'password: %DB_PASS%',
  'this.token = token;',
  'self.password = password',
  'const password = req.body.password;',
  'password = user.password',
  'token = session.authToken',
  'token = getToken()',
  'password: null,',
  'secret = None',
  'password: <your-password>',
  'api_key = YOUR_API_KEY',
  'password=********',
  'password = "********"',
  'token: [REDACTED]',
];

const secrets = [
  // plain literals
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
  // code-looking starts with a literal later on the line
  'const password: string = "hunter2abcd";',
  'password: process.env.PASSWORD || "hunter2default",',
  'SECRET_KEY = os.environ.get("SECRET_KEY", "django-insecure-9x8c7v6b5n4m")',
  'token = decode("ZXlKaGJHY2lPaUpJVXpJMU5pSjk")',
  'password = lookup("hunter2default")',
  "token = fs.readFileSync(path, 'utf8') + \"hunter2abcd\"",
  'db_password = "${DB_USER}:hunter2abcd"',
  'password = "$DB_PASSWORD hunter2abcd"',
  'password: string = hunter2abcd',
  // templates with a default, and .env, shell and YAML literals
  'POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-postgres123}',
  'POSTGRES_PASSWORD: password',
  'MYSQL_ROOT_PASSWORD=password',
  'DB_PASSWORD=Welcome(2024)!',
  'SMTP_PASSWORD=mail.secret',
  'DB_PASSWORD=jack.daniels.whiskey',
  'PASSWORD=$TR0NGPASS',
  'password: password',
  'password = jack.daniels.whiskey',
  // found by the second review: anything left over on the line keeps the finding
  'secret = pyotp.TOTP("JBSWY3DPEHPK3PXP")',
  'api_key = bytes.fromhex("DEADBEEF0123456789ABCDEF01234567")',
  'password = Secret("changeme")',
  'const password = make_secret("letmein")',
  'password: Summer(2024)',
  'spring.datasource.password=Admin(2024)',
  'password: self.Hunter2',
  'db.password=password',
  'password=password',
  'PASSWORD=$(echo)S3cretValue99',
  'password = "$(whoami)hunter2"',
  'PASSWORD=$PREFIX"hunter2secret"',
  'token = process.env.TOKEN || 1234567890',
  'password = str(12345678)',
  'password = os.environ.get("DB_PASSWORD",\n    "hunter2abcd")',
  'password = config.get("db.password")',
  'password=$(cat /run/secrets/db_password)',
  'function f(password: string, salt = "hunter2abcd") {',
  'password: string, pin = 12345678',
  // placeholders that are not placeholders
  'password = "[Tr0ub4dor&3]"',
  'password = <Tr0ub4dor3>',
  `password=${'a.'.repeat(200)}password`,
];

test('code is left out of a scan', () => {
  for (const line of code) assert.deepEqual(report(line).map((f) => f.detector), [], line);
});

test('anything that holds, or could be, a literal is still reported', () => {
  for (const line of secrets) assert.ok(report(line).length > 0, line);
});

test('the judgement reads its own line, not the ones around it', () => {
  const text = 'token = getToken()\nconst other = "hunter2abcd";\npassword: string\n  = oops';
  assert.deepEqual(report(text), []);
  const two = 'x\npassword = os.getenv("DB_PASSWORD")';
  const [finding] = scan(two);
  assert.equal(isCodeAssignment(two, finding.start, finding.end), true);
});

test('a more specific finding under a dropped assignment is still reported', () => {
  const line = 'token = ${ghp_' + 'a'.repeat(36) + '}';
  assert.deepEqual(scan(line).map((f) => f.detector), ['generic_assignment'], 'the assignment stands in for it');
  assert.deepEqual(report(line).map((f) => f.detector), ['github_token']);
});

test('redaction is untouched: it masks every assignment, code or not', () => {
  for (const line of [...code, ...secrets]) {
    if (!scan(line).some((f) => f.detector === 'generic_assignment')) continue;
    assert.notEqual(redact(line), line, line);
  }
  assert.equal(redact('token = process.env.TOKEN'), 'token = ***');
  assert.equal(redact('password=$argon2id$v=19$m=65536'), 'password=***');
  assert.deepEqual(scan('token = process.env.TOKEN').map((f) => f.detector), ['generic_assignment'], 'scan() from code is not filtered');
});

test('the CLI scan leaves code out, and --no-code-filter brings it back', () => {
  const source = 'export const token = process.env.TOKEN;\npassword: string;\nconst secret = "hunter2000";\n';
  const filtered = run(source, '--scan');
  assert.equal(filtered.status, 1);
  assert.match(filtered.stdout, /^1 finding:/);
  assert.match(filtered.stdout, /at 3:7/);
  assert.match(run(source, '--scan', '--no-code-filter').stdout, /^3 findings:/);
  assert.equal(run('export const token = process.env.TOKEN;\n', '--scan').status, 0);
  assert.equal(run('password: process.env.PASSWORD || "hunter2default",\n', '--scan').status, 1);
  assert.equal(run('token = process.env.TOKEN\n').stdout, 'token = ***\n', 'plain redaction is not filtered');
});

test('a hostile line costs nothing', () => {
  const lines = [
    `password=${'a.'.repeat(100_000)}b`,
    `password=${'a'.repeat(200_000)}`,
    `password=$${'A'.repeat(200_000)}`,
    `token = f(${'"a" '.repeat(50_000)})`,
    `token = f(${'"'.repeat(100_000)}`,
    `token = f(${'\\"'.repeat(100_000)}`,
    `${'x.'.repeat(50_000)}token = token`,
    `password: string, ${'!=='.repeat(90)}="`,
    `password: string, ${'<>!'.repeat(95)}'`,
  ];
  for (const line of lines) {
    const start = line.search(/password=|token = /);
    const started = performance.now();
    isCodeAssignment(line, start, start + 16);
    assert.ok(performance.now() - started < 50, line.slice(0, 30));
  }
  // Many findings in one text: the filter must not be slower than the scan by much.
  const oneLine = 'password=abc123x '.repeat(20_000);
  const manyLines = 'token = config.token\nmail alice@corp.com\n'.repeat(10_000);
  for (const text of [oneLine, manyLines]) {
    const found = scan(text);
    const started = performance.now();
    withoutCodeAssignments(text, found, () => scan(text, { disable: ['generic_assignment'] }));
    assert.ok(performance.now() - started < 1500, `${text.slice(0, 20)}: ${(performance.now() - started).toFixed(0)} ms`);
  }
});
