#!/usr/bin/env node
// Report a flare-redact SARIF file inside a GitHub Actions job: one error
// annotation per finding, a table in the job summary, and step outputs.
// Used by action.yml; not part of the npm package.
//
//   node scripts/github-action-report.mjs <sarif-file> [--no-annotations]
//
// SARIF from flare-redact carries the detector, its explanation and the
// location, never the matched value, and this report prints nothing else.

import { appendFileSync, readFileSync, realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

/** A finding as the report needs it: what fired and where. */
export function findingsFromSarif(sarif) {
  const findings = [];
  for (const run of sarif?.runs ?? []) {
    const names = new Map((run.tool?.driver?.rules ?? []).map((rule) => [rule.id, rule.name ?? rule.id]));
    for (const result of run.results ?? []) {
      const location = result.locations?.[0]?.physicalLocation;
      findings.push({
        detector: String(result.ruleId ?? 'unknown'),
        label: String(names.get(result.ruleId) ?? result.ruleId ?? 'Finding'),
        message: String(result.message?.text ?? ''),
        risk: String(result.properties?.risk ?? result.level ?? ''),
        file: location?.artifactLocation?.uri === undefined ? undefined : uriToPath(location.artifactLocation.uri),
        line: location?.region?.startLine,
        column: location?.region?.startColumn,
      });
    }
  }
  return findings;
}

function uriToPath(uri) {
  try {
    return decodeURI(String(uri));
  } catch {
    return String(uri);
  }
}

// Workflow commands: https://docs.github.com/actions/reference/workflow-commands-for-github-actions
const escapeData = (s) => String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const escapeProperty = (s) => escapeData(s).replace(/:/g, '%3A').replace(/,/g, '%2C');

/** One `::error` workflow command per finding. */
export function annotations(findings) {
  return findings.map((f) => {
    const props = [];
    if (f.file !== undefined) props.push(`file=${escapeProperty(f.file)}`);
    if (Number.isInteger(f.line)) props.push(`line=${f.line}`);
    if (Number.isInteger(f.column)) props.push(`col=${f.column}`);
    props.push(`title=${escapeProperty(`flare-redact: ${f.label}`)}`);
    return `::error ${props.join(',')}::${escapeData(f.message || f.label)}`;
  });
}

const cell = (s) => String(s).replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ');
const where = (f) => (f.file === undefined ? 'input' : [f.file, f.line, f.column].filter((v) => v !== undefined).join(':'));

/** Markdown for the job summary. Long reports are cut, with the count kept. */
export function summary(findings, limit = 200) {
  if (!findings.length) return '### flare-redact: no findings\n\nNo secrets or personal data were found.\n';
  const lines = [
    `### flare-redact: ${findings.length} finding${findings.length === 1 ? '' : 's'}`,
    '',
    'Values are never shown. Remove them from the code or the history, and rotate any real secret.',
    '',
    '| Detector | Risk | Where |',
    '| --- | --- | --- |',
  ];
  for (const f of findings.slice(0, limit)) {
    lines.push(`| ${cell(f.label)} (\`${cell(f.detector)}\`) | ${cell(f.risk)} | \`${cell(where(f))}\` |`);
  }
  if (findings.length > limit) lines.push('', `${findings.length - limit} more not shown; see the SARIF file.`);
  return lines.join('\n') + '\n';
}

function main(argv) {
  const file = argv.find((a) => !a.startsWith('--'));
  if (!file) throw new Error('usage: github-action-report.mjs <sarif-file> [--no-annotations]');
  const findings = findingsFromSarif(JSON.parse(readFileSync(file, 'utf8')));
  if (!argv.includes('--no-annotations')) {
    for (const line of annotations(findings)) process.stdout.write(line + '\n');
  }
  process.stdout.write(`flare-redact: ${findings.length} finding${findings.length === 1 ? '' : 's'}\n`);
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary(findings));
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `findings=${findings.length}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  main(process.argv.slice(2));
}
