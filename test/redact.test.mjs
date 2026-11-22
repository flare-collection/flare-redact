import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact, scan, isClean, summary, compilePolicy, createRedactor, wrapConsole } from '../dist/index.js';

const gh = 'ghp_' + 'a'.repeat(36);

test('redacts an AWS access key but keeps a hint', () => {
  assert.equal(redact('key=AKIAIOSFODNN7EXAMPLE done'), 'key=AKIA*** done');
});

test('redacts GitHub, GitLab and npm tokens', () => {
  assert.equal(redact(`t ${gh}`), 't ghp_***');
  assert.equal(redact('glpat-' + 'x'.repeat(20)), 'glpat-***');
  assert.equal(redact('npm_' + 'y'.repeat(36)), 'npm_***');
});

test('redacts a JWT and a bearer header', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123456';
  assert.equal(redact(jwt), '[REDACTED JWT]');
  assert.equal(redact('Authorization: Bearer ' + jwt), 'Authorization: Bearer ***');
});

test('labels Anthropic keys as anthropic_key, not openai_key', () => {
  const anthropic = 'sk-ant-api03-' + 'a1B2'.repeat(23) + 'A';
  const [finding] = scan(`key=${anthropic}`);
  assert.equal(finding.detector, 'anthropic_key');
  assert.equal(redact(`key=${anthropic}`), 'key=sk-ant-***');
});

test('still labels OpenAI keys as openai_key', () => {
  for (const key of ['sk-' + 'x'.repeat(48), 'sk-proj-' + 'y'.repeat(48)]) {
    const [finding] = scan(`key=${key}`);
    assert.equal(finding.detector, 'openai_key');
    assert.equal(redact(`key=${key}`), 'key=sk-***');
  }
});

test('redacts a private key block whole', () => {
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj\n-----END RSA PRIVATE KEY-----';
  assert.equal(redact(pem), '[REDACTED PRIVATE KEY]');
});

test('redacts the password inside a connection string', () => {
  assert.equal(redact('postgres://user:s3cr3t@db.host:5432/app'), 'postgres://user:***@db.host:5432/app');
});

test('redacts a password-only connection string with an empty username', () => {
  // The canonical Redis/Valkey form, also used by RabbitMQ and others. Hosts such
  // as localhost, IPs and service names have no domain for the email detector.
  assert.equal(redact('redis://:SuperSecret123@localhost:6379/0'), 'redis://:***@localhost:6379/0');
  assert.equal(redact('postgres://:SuperSecret123@10.0.0.5:5432/app'), 'postgres://:***@10.0.0.5:5432/app');
  assert.equal(redact('REDIS_URL=rediss://:SuperSecret123@redis:6380'), 'REDIS_URL=rediss://:***@redis:6380');
  assert.equal(
    redact('{"url":"amqp://:SuperSecret123@rabbit:5672"}'),
    '{"url":"amqp://:***@rabbit:5672"}',
  );
});

test('masks a whole password that contains a colon', () => {
  assert.equal(redact('postgres://user:pa:ss@db/x'), 'postgres://user:***@db/x');
  assert.equal(redact('redis://:pa:ss@cache:6379'), 'redis://:***@cache:6379');
});

test('leaves URLs with no password alone', () => {
  for (const s of ['http://host:8080/path', 'redis://:@host:6379', 'https://user@host/x', 'ftp://anonymous@mirror/pub']) {
    assert.equal(redact(s), s);
  }
});

test('redacts connection strings whose scheme has an underscore', () => {
  // SQLAlchemy driver names such as cx_oracle and redshift_connector.
  assert.equal(redact('oracle+cx_oracle://scott:tiger99@db:1521/orcl'), 'oracle+cx_oracle://scott:***@db:1521/orcl');
  assert.equal(redact('redshift+redshift_connector://u:hunter22@h/db'), 'redshift+redshift_connector://u:***@h/db');
  assert.equal(redact('my_app://u:hunter22@h/db'), 'my_app://u:***@h/db');
  // A URL with a user but no password stays as it is.
  assert.equal(redact('oracle+cx_oracle://scott@db:1521/orcl'), 'oracle+cx_oracle://scott@db:1521/orcl');
});

test('a long run of scheme characters is scanned in linear time', () => {
  // Every position in "a-b.a-b.…" can start a scheme. With an unbounded scheme
  // each start read to the end of the run, so time grew with the square of the
  // length: 160 kB took about 25 s. The scheme is now at most 64 characters.
  const run = 'a-b.'.repeat(50_000) + '://';
  const start = performance.now();
  assert.equal(redact(run), run);
  assert.ok(performance.now() - start < 2000, `took ${Math.round(performance.now() - start)} ms`);
  assert.equal(redact('a-b.'.repeat(20) + 'x://u:hunter22@h'), 'a-b.'.repeat(20) + 'x://u:***@h');
});

test('masks a Luhn-valid card, ignores an invalid digit run', () => {
  assert.equal(redact('card 4242 4242 4242 4242 end'), 'card **** **** **** 4242 end');
  assert.equal(redact('id 1234 5678 9012 3456'), 'id 1234 5678 9012 3456');
});

test('masks emails as PII', () => {
  assert.equal(redact('reach me at alice@example.com now'), 'reach me at a***@*** now');
});

test('generic assignment catches password=…', () => {
  assert.equal(redact('password=hunter2'), 'password=***');
  assert.equal(redact('api_key: "abcd1234efgh"'), 'api_key: "***"');
});

test('deep-redacts objects and arrays', () => {
  const out = redact({
    user: 'bob@corp.com',
    password: 'hunter2',
    tokens: [gh],
    nested: { note: 'my key is AKIAIOSFODNN7EXAMPLE' },
  });
  assert.equal(out.password, '***');
  assert.equal(out.user, 'b***@***');
  assert.equal(out.tokens[0], 'ghp_***');
  assert.equal(out.nested.note, 'my key is AKIA***');
});

test('scan reports findings with a why, input unchanged', () => {
  const findings = scan('email bob@x.io and password=hunter2');
  const ids = findings.map((f) => f.detector);
  assert.ok(ids.includes('email'));
  assert.ok(ids.includes('generic_assignment'));
  for (const f of findings) assert.ok(f.why.length > 0);
  for (const f of findings) assert.equal(f.value, undefined);
});

test('scan includes raw values only when explicitly requested', () => {
  const [safe] = scan('email bob@x.io', { only: ['email'] });
  const [unsafe] = scan('email bob@x.io', { only: ['email'], includeValues: true });
  assert.equal(safe.value, undefined);
  assert.equal(unsafe.value, 'bob@x.io');
});

test('scan reports one-based line and column locations', () => {
  const [finding] = scan('safe line\ncontact bob@x.io now', { only: ['email'] });
  assert.equal(finding.line, 2);
  assert.equal(finding.column, 9);
  assert.equal(finding.start, 18);
});

test('scan on objects returns json paths', () => {
  const findings = scan({ a: { b: gh }, password: 'x' });
  const paths = findings.map((f) => f.path);
  assert.ok(paths.includes('a.b'));
  assert.ok(paths.includes('password'));
});

test('only/disable/enable toggles', () => {
  assert.equal(redact('bob@x.io', { disable: ['email'] }), 'bob@x.io');
  assert.equal(redact('AKIAIOSFODNN7EXAMPLE bob@x.io', { only: ['email'] }), 'AKIAIOSFODNN7EXAMPLE b***@***');
  assert.equal(redact('10.0.0.1', {}), '10.0.0.1');
  assert.equal(redact('10.0.0.1', { enable: ['ipv4'] }), '***.***.***.***');
});

test('label mode', () => {
  assert.equal(redact('AKIAIOSFODNN7EXAMPLE', { mode: 'label' }), '[REDACTED:aws_access_key]');
  assert.equal(redact({ password: 'x' }, { mode: 'label' }).password, '[REDACTED:sensitive_key]');
});

test('hash mode is deterministic and correlates equal values', () => {
  const a = redact('bob@x.io', { mode: 'hash', transformSecret: 'service-a-secret' });
  const b = redact('bob@x.io', { mode: 'hash', transformSecret: 'service-a-secret' });
  assert.equal(a, b);
  assert.match(a, /^email_[0-9a-f]{32}$/);
  assert.notEqual(a, redact('alice@x.io', { mode: 'hash', transformSecret: 'service-a-secret' }));
  assert.notEqual(a, redact('bob@x.io', { mode: 'hash', transformSecret: 'service-b-secret' }));
  assert.throws(() => redact('bob@x.io', { mode: 'hash' }), /transformSecret/);
});

test('allow list keeps known-safe values', () => {
  assert.equal(redact('support@example.com', { allow: ['support@example.com'] }), 'support@example.com');
  assert.equal(redact('a@b.io c@d.io', { allow: /a@b\.io/ }), 'a@b.io c***@***');
});

test('custom detector', () => {
  const out = redact('ticket ACME-1234 here', {
    custom: [{ id: 'ticket', label: 'Ticket', why: 'internal id', pattern: /\bACME-\d{4,6}\b/g, mask: () => '[TICKET]', default: true }],
  });
  assert.equal(out, 'ticket [TICKET] here');
});

test('high_entropy catches unknown tokens when enabled', () => {
  const token = 'Zx9Qw3Rt7Yp2Lm5Kv8Nb1Hs6Df4Gj0';
  assert.equal(redact(token, {}), token);
  assert.equal(redact(token, { enable: ['high_entropy'] }), 'Zx9Q***');
});

test('isClean and summary', () => {
  assert.equal(isClean('nothing to see here'), true);
  assert.equal(isClean('password=hunter2'), false);
  const s = summary({ password: 'x', note: 'bob@x.io', key: gh });
  assert.equal(s.total, 3);
  assert.equal(s.byDetector.email, 1);
});

test('createRedactor binds options', () => {
  const r = createRedactor({ disable: ['email'] });
  assert.equal(r.redact(`bob@x.io ${gh}`), 'bob@x.io ghp_***');
  assert.equal(r.isClean('bob@x.io'), true);
});

test('compilePolicy reuses a resolved policy and exposes async operations', async () => {
  const policy = compilePolicy({ disable: ['email'] });
  assert.equal(policy.redact(`bob@x.io ${gh}`), 'bob@x.io ghp_***');
  assert.equal(await policy.isCleanAsync('bob@x.io'), true);
  assert.equal((await policy.scanAsync(gh))[0].detector, 'github_token');
});

test('redact preserves cycles, shared references, Map, Set, and symbol metadata', () => {
  const symbol = Symbol('meta');
  const shared = { email: 'bob@corp.com' };
  const input = {
    shared,
    again: shared,
    map: new Map([['owner', 'alice@corp.com']]),
    set: new Set(['carol@corp.com']),
    [symbol]: 'dave@corp.com',
  };
  input.self = input;
  const out = redact(input);
  assert.equal(out.self, out);
  assert.equal(out.shared, out.again);
  assert.equal(out.shared.email, 'b***@***');
  assert.equal(out.map.get('owner'), 'a***@***');
  assert.deepEqual([...out.set], ['c***@***']);
  assert.equal(out[symbol], 'd***@***');
});

test('scan terminates on circular graphs and scans Map and Set values', () => {
  const input = { map: new Map([['email', 'alice@corp.com']]), set: new Set(['bob@corp.com']) };
  input.self = input;
  const findings = scan(input);
  assert.equal(findings.filter((finding) => finding.detector === 'email').length, 2);
});

test('redact and scan handle Error and URL objects without losing their type', () => {
  const error = new Error('request failed for alice@corp.com');
  const url = new URL('https://example.com/callback?email=bob@corp.com');
  const out = redact({ error, url });
  assert.equal(out.error instanceof Error, true);
  assert.doesNotMatch(out.error.message, /alice@corp/);
  assert.equal(out.url instanceof URL, true);
  assert.doesNotMatch(out.url.toString(), /bob@corp/);
  assert.equal(scan({ error, url }, { only: ['email'] }).length, 2);
});

test('global allow and sensitive-key regexes behave consistently across values', () => {
  const out = redact(
    { token: 'keep', token2: 'mask-me', token3: 'keep' },
    { redactKeys: /^token\d?$/g, allow: /^keep$/g },
  );
  assert.equal(out.token, 'keep');
  assert.equal(out.token2, '***');
  assert.equal(out.token3, 'keep');
});

test('adjacent secrets do not corrupt surrounding text', () => {
  assert.equal(redact('a AKIAIOSFODNN7EXAMPLE b bob@x.io c'), 'a AKIA*** b b***@*** c');
});

test('clean text is returned unchanged', () => {
  const s = 'the quick brown fox jumps over the lazy dog';
  assert.equal(redact(s), s);
  assert.deepEqual(scan(s), []);
});

test('wrapConsole redacts every argument then restores', () => {
  const seen = [];
  const fake = { log: (...a) => seen.push(a), info() {}, warn() {}, error() {}, debug() {} };
  const restore = wrapConsole({}, fake);
  fake.log('token', gh, { password: 'hunter2' });
  restore();
  assert.deepEqual(seen[0], ['token', 'ghp_***', { password: '***' }]);
  fake.log('again', gh);
  assert.deepEqual(seen[1], ['again', gh]);
});
