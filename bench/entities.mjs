// Entity recognition quality on hand-labelled text.
//
//   npm run benchmark:entities            # table
//   npm run benchmark:entities -- --json  # machine-readable
//
// Compares the regex detectors alone (every PII detector switched on, the best
// the library could do before the recogniser) against the same detectors plus
// `entities`. Reports typed exact-span and overlap F1 per label, the share of
// gold PII characters left unmasked (leak), and the share of clean characters
// masked (over-redaction). The corpus is small and synthetic; read the numbers
// as a regression signal, not as a comparison with published model scores.

import { readFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { scan } from '../dist/index.js';

const corpus = JSON.parse(readFileSync(new URL('./entities-cases.json', import.meta.url), 'utf8'));
const asJson = process.argv.includes('--json');

/** Map the regex detectors onto the recogniser's label set. */
const LABEL_OF = {
  person_name: 'private_person',
  street_address: 'private_address',
  date_of_birth: 'private_date',
  phone: 'private_phone',
  generic_assignment: 'secret',
  credit_card: 'account_number',
  iban: 'account_number',
  us_ssn: 'account_number',
};

const LABELS = [
  'private_person', 'private_address', 'private_phone', 'private_date',
  'account_number', 'private_handle', 'private_url', 'secret',
];

/** generic_assignment reports `password: x` but masks only `x`; score the part it masks. */
function valueSpan(text, f) {
  if (f.detector !== 'generic_assignment') return { start: f.start, end: f.end };
  const m = /[:=]\s*["']?/.exec(text.slice(f.start, f.end));
  return m ? { start: f.start + m.index + m[0].length, end: f.end - (/["']$/.test(text.slice(f.start, f.end)) ? 1 : 0) } : { start: f.start, end: f.end };
}

function parse(line) {
  let text = '';
  const gold = [];
  const re = /\[\[([a-z_]+)\|([\s\S]*?)\]\]/g;
  let last = 0;
  let m;
  while ((m = re.exec(line)) !== null) {
    text += line.slice(last, m.index);
    gold.push({ label: m[1], start: text.length, end: text.length + m[2].length });
    text += m[2];
    last = m.index + m[0].length;
  }
  return { text: text + line.slice(last), gold };
}

const SYSTEMS = {
  'regex detectors': { enable: ['pii', 'contextual', 'phone'] },
  'regex + entities': { enable: ['pii', 'contextual', 'phone', 'entities'] },
};

function evaluate(lines, options) {
  const perLabel = Object.fromEntries(LABELS.map((l) => [l, { tp: 0, fp: 0, fn: 0, overlapTp: 0, overlapFn: 0 }]));
  let goldChars = 0;
  let leakedChars = 0;
  let cleanChars = 0;
  let overMasked = 0;
  let ms = 0;
  for (const line of lines) {
    const { text, gold } = parse(line);
    const started = performance.now();
    const found = scan(text, options)
      .filter((f) => f.detector !== 'email')
      .map((f) => ({ label: LABEL_OF[f.detector] ?? f.detector, ...valueSpan(text, f) }));
    ms += performance.now() - started;

    const masked = new Uint8Array(text.length);
    for (const f of found) masked.fill(1, f.start, f.end);
    const inGold = new Uint8Array(text.length);
    for (const g of gold) {
      inGold.fill(1, g.start, g.end);
      goldChars += g.end - g.start;
      for (let i = g.start; i < g.end; i++) if (!masked[i] && /\S/.test(text[i])) leakedChars++;
    }
    for (let i = 0; i < text.length; i++) {
      if (inGold[i] || !/\S/.test(text[i])) continue;
      cleanChars++;
      if (masked[i]) overMasked++;
    }

    for (const g of gold) {
      const stats = perLabel[g.label];
      if (found.some((f) => f.label === g.label && f.start === g.start && f.end === g.end)) stats.tp++;
      else stats.fn++;
      if (found.some((f) => f.label === g.label && f.start < g.end && g.start < f.end)) stats.overlapTp++;
      else stats.overlapFn++;
    }
    for (const f of found) {
      const stats = perLabel[f.label];
      if (!stats) continue;
      if (!gold.some((g) => g.label === f.label && g.start === f.start && g.end === f.end)) stats.fp++;
    }
  }
  const f1 = (tp, fp, fn) => (tp ? (2 * tp) / (2 * tp + fp + fn) : 0);
  const labels = {};
  let tp = 0, fp = 0, fn = 0;
  for (const [label, s] of Object.entries(perLabel)) {
    tp += s.tp; fp += s.fp; fn += s.fn;
    const support = s.tp + s.fn;
    if (!support && !s.fp) continue;
    labels[label] = {
      support,
      precision: s.tp + s.fp ? s.tp / (s.tp + s.fp) : 0,
      recall: support ? s.tp / support : 0,
      f1: f1(s.tp, s.fp, s.fn),
      overlapRecall: support ? s.overlapTp / support : 0,
    };
  }
  return {
    labels,
    micro: { precision: tp + fp ? tp / (tp + fp) : 0, recall: tp + fn ? tp / (tp + fn) : 0, f1: f1(tp, fp, fn) },
    leak: goldChars ? leakedChars / goldChars : 0,
    overRedaction: cleanChars ? overMasked / cleanChars : 0,
    msPerLine: ms / lines.length,
  };
}

const results = {};
for (const split of ['dev', 'holdout']) {
  results[split] = {};
  for (const [name, options] of Object.entries(SYSTEMS)) results[split][name] = evaluate(corpus[split], options);
}

if (asJson) {
  process.stdout.write(JSON.stringify({ schemaVersion: 1, results }, null, 2) + '\n');
} else {
  const pct = (n) => `${(n * 100).toFixed(1)}%`.padStart(7);
  for (const split of ['dev', 'holdout']) {
    process.stdout.write(`\n${split} (${corpus[split].length} lines)\n`);
    process.stdout.write(`${'system'.padEnd(18)} ${'P'.padStart(7)} ${'R'.padStart(7)} ${'F1'.padStart(7)} ${'leak'.padStart(7)} ${'over'.padStart(7)}\n`);
    for (const [name, r] of Object.entries(results[split])) {
      process.stdout.write(`${name.padEnd(18)} ${pct(r.micro.precision)} ${pct(r.micro.recall)} ${pct(r.micro.f1)} ${pct(r.leak)} ${pct(r.overRedaction)}\n`);
    }
    const best = results[split]['regex + entities'];
    for (const [label, s] of Object.entries(best.labels)) {
      process.stdout.write(`  ${label.padEnd(16)} n=${String(s.support).padStart(2)}  P ${pct(s.precision)}  R ${pct(s.recall)}  F1 ${pct(s.f1)}  overlap R ${pct(s.overlapRecall)}\n`);
    }
  }
}
