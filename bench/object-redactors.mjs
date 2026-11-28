// Speed and coverage of flare-redact next to the object redactors people use
// with loggers: fast-redact and @pinojs/redact (what pino's `redact` option runs
// on), deep-redact and veilit.
//
// The other libraries are not dependencies. Install them anywhere and point the
// benchmark at that folder:
//
//   mkdir /tmp/redactors && cd /tmp/redactors && npm init -y
//   npm install fast-redact @pinojs/redact deep-redact veilit
//   npm run build && FLARE_BENCH_DEPS=/tmp/redactors node bench/object-redactors.mjs
//
// Every library gets the configuration its README recommends for this record,
// with every sensitive field name listed where it takes a list. Coverage counts
// the planted values that still appear in the JSON line each library produces.

import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { compilePolicy } from '../dist/index.js';

const deps = process.env.FLARE_BENCH_DEPS;
if (!deps) {
  process.stderr.write('Set FLARE_BENCH_DEPS to a folder with fast-redact, @pinojs/redact, deep-redact and veilit installed.\n');
  process.exit(2);
}
const load = createRequire(join(deps, 'package.json'));
const versionOf = (name) => JSON.parse(readFileSync(join(deps, 'node_modules', name, 'package.json'), 'utf8')).version;

// Assembled at run time so no complete credential sits in this file.
const STRIPE = ['sk', 'live', '51H8x2eZvKYlo2C0aZt7fQ3mVb9Rk'].join('_');
const JWT = ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiJhZGEifQ', 'c2lnbmF0dXJlLXZhbHVlLTEyMzQ1'].join('.');
const GITHUB = 'ghp' + '_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8';

// The values that must not reach the log line, and where they sit.
const PLANTED = {
  'header authorization': `Bearer ${JWT}`,
  'header cookie': 'sid=7f3a9c1e5b2d4f6a8c0e',
  'user.password': 'hunter2-Correct-Horse',
  'db.db_password': 'pg-Secret-91x',
  'key inside the message': STRIPE,
  'email inside the message': 'ada@example.com',
  'token in a URL query': GITHUB,
  'password inside an error URL': 's3cr3tPassw0rd',
  'card number in an array item': '4111 1111 1111 1111',
};

const record = () => ({
  level: 30,
  time: 1764316800000,
  msg: `charge failed for ada@example.com using ${STRIPE}`,
  req: {
    method: 'POST',
    url: `/v1/repos/sync?access=${GITHUB}&page=2`,
    headers: {
      host: 'api.example.com',
      authorization: `Bearer ${JWT}`,
      cookie: 'sid=7f3a9c1e5b2d4f6a8c0e',
      'user-agent': 'curl/8.7.1',
    },
  },
  user: { id: 42, plan: 'pro', password: 'hunter2-Correct-Horse' },
  db: { host: 'db.internal', port: 5432, db_password: 'pg-Secret-91x' },
  err: { code: 'ECONNREFUSED', message: 'connect failed: postgres://admin:s3cr3tPassw0rd@db.internal:5432/app' },
  items: [
    { sku: 'A-100', qty: 1, card: '4111 1111 1111 1111' },
    { sku: 'B-200', qty: 3 },
  ],
});

// The field paths a careful user lists for this record.
const PATHS = ['req.headers.authorization', 'req.headers.cookie', 'user.password', 'db.db_password', 'items[*].card'];
const KEYS = ['authorization', 'cookie', 'password', 'db_password', 'card'];

const fastRedact = load('fast-redact');
const pinoRedact = load('@pinojs/redact');
const { redact: deepRedact } = load('deep-redact');
const { createRedactor: veilit } = load('veilit');

const flare = compilePolicy();
const flarePaths = compilePolicy({ paths: PATHS, detectors: [], redactKeys: false });

const contenders = [
  {
    name: 'flare-redact',
    version: load(join(process.cwd(), 'package.json')).version,
    config: 'defaults: value detectors + sensitive key names',
    run: (o) => JSON.stringify(flare.redact(o)),
  },
  {
    name: 'flare-redact (paths only)',
    version: load(join(process.cwd(), 'package.json')).version,
    config: '`paths` only, detectors off: the same job as fast-redact',
    run: (o) => JSON.stringify(flarePaths.redact(o)),
  },
  {
    name: 'fast-redact',
    version: versionOf('fast-redact'),
    config: `paths: ${PATHS.length} listed`,
    run: fastRedact({ paths: PATHS }),
  },
  {
    name: '@pinojs/redact',
    version: versionOf('@pinojs/redact'),
    config: `paths: ${PATHS.length} listed`,
    run: pinoRedact({ paths: PATHS }),
  },
  {
    name: 'deep-redact',
    version: versionOf('deep-redact'),
    config: `list: ${KEYS.length} key names`,
    run: (o) => JSON.stringify(deepRedact(o, { list: KEYS })),
  },
  {
    name: 'veilit',
    version: versionOf('veilit'),
    config: 'createRedactor() defaults: key list + value detectors',
    run: (() => {
      const r = veilit();
      return (o) => JSON.stringify(r(o));
    })(),
  },
];

const runs = Number(process.env.FLARE_BENCH_RUNS ?? 7);
const iterations = Number(process.env.FLARE_BENCH_ITERATIONS ?? 20_000);

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

const results = [];
for (const c of contenders) {
  const line = c.run(record());
  const leaked = Object.entries(PLANTED).filter(([, value]) => line.includes(value)).map(([where]) => where);
  for (let i = 0; i < 2_000; i++) c.run(record());
  const samples = [];
  for (let r = 0; r < runs; r++) {
    const start = performance.now();
    for (let i = 0; i < iterations; i++) c.run(record());
    samples.push(((performance.now() - start) * 1000) / iterations);
  }
  results.push({
    library: c.name,
    version: c.version,
    config: c.config,
    microsecondsPerRecord: Number(median(samples).toFixed(2)),
    caught: Object.keys(PLANTED).length - leaked.length,
    planted: Object.keys(PLANTED).length,
    leaked,
  });
}

process.stdout.write(JSON.stringify({ schemaVersion: 1, node: process.version, platform: process.platform, arch: process.arch, results }, null, 2) + '\n');
