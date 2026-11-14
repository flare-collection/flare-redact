/**
 * `flare-redact init`: read the project's package.json, pick the integrations
 * that fit, and print the lines to paste. `--ci` also writes a GitHub workflow
 * that scans every pull request. It never edits source files: the output is a
 * plan the developer applies, so nothing changes behind their back.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import type { Preset } from './engine.js';

export interface InitStep {
  /** The dependency that triggered the step, or `undefined` for the general ones. */
  readonly found?: string;
  readonly title: string;
  readonly code: string;
}

export interface InitPlan {
  /** Dependencies the plan reacted to, in the order the steps use them. */
  readonly found: readonly string[];
  /** True when flare-redact is not yet a dependency. */
  readonly install: boolean;
  readonly steps: readonly InitStep[];
}

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

const LLM: Preset = 'llm';
const LOGS: Preset = 'logs';

/** One recipe per supported library, in the order they are printed. */
const RECIPES: ReadonlyArray<{ dep: string; title: string; code: string }> = [
  {
    dep: 'openai',
    title: 'OpenAI: prompts are redacted before they leave, replies are restored',
    code: `import OpenAI from 'openai';
import { wrapOpenAI } from 'flare-redact/llm';

const openai = wrapOpenAI(new OpenAI(), { preset: '${LLM}' });`,
  },
  {
    dep: '@anthropic-ai/sdk',
    title: 'Anthropic: prompts are redacted before they leave, replies are restored',
    code: `import Anthropic from '@anthropic-ai/sdk';
import { wrapAnthropic } from 'flare-redact/llm';

const anthropic = wrapAnthropic(new Anthropic(), { preset: '${LLM}' });`,
  },
  {
    dep: 'pino',
    title: 'pino: every log line is redacted',
    code: `import pino from 'pino';
import { pinoRedact } from 'flare-redact/pino';

const log = pino(pinoRedact({ preset: '${LOGS}' }));`,
  },
  {
    dep: 'winston',
    title: 'winston: every log field is redacted',
    code: `import winston from 'winston';
import { winstonRedact } from 'flare-redact/winston';

const log = winston.createLogger({
  format: winston.format.combine(winston.format(winstonRedact({ preset: '${LOGS}' }))(), winston.format.json()),
  transports: [new winston.transports.Console()],
});`,
  },
  {
    dep: 'express',
    title: 'Express: log a safe copy of each request',
    code: `import { httpRedactor } from 'flare-redact/http';

app.use(httpRedactor({ preset: '${LOGS}' }));
app.use((req, _res, next) => { console.log(req.redacted()); next(); });`,
  },
];

const CONSOLE_STEP: InitStep = {
  title: 'console: redact everything printed with console.*',
  code: `import { wrapConsole } from 'flare-redact';

wrapConsole({ preset: '${LOGS}' });`,
};

/** Decide what to suggest for a package.json (or for no package.json at all). */
export function planInit(pkg: PackageJson | undefined): InitPlan {
  const deps = { ...pkg?.devDependencies, ...pkg?.dependencies };
  const has = (name: string): boolean => Object.prototype.hasOwnProperty.call(deps, name);
  const steps: InitStep[] = RECIPES.filter((recipe) => has(recipe.dep)).map((recipe) => ({
    found: recipe.dep,
    title: recipe.title,
    code: recipe.code,
  }));
  // No logger found: console is the logger.
  if (!steps.some((step) => step.found === 'pino' || step.found === 'winston')) steps.push(CONSOLE_STEP);
  return {
    found: steps.flatMap((step) => (step.found ? [step.found] : [])),
    install: !has('flare-redact'),
    steps,
  };
}

const indent = (text: string): string => text.split('\n').map((line) => (line ? `   ${line}` : '')).join('\n');

/** The plan as the text `flare-redact init` prints. */
export function renderInit(plan: InitPlan, source: string | undefined): string {
  const out: string[] = [];
  out.push(
    source === undefined
      ? 'flare-redact init: no package.json here, so these are the general steps.'
      : plan.found.length
        ? `flare-redact init: found ${plan.found.join(', ')} in ${source}.`
        : `flare-redact init: no supported library in ${source}, so these are the general steps.`,
  );
  let n = 0;
  if (plan.install) out.push('', `${++n}. Install`, indent('npm install flare-redact'));
  for (const step of plan.steps) out.push('', `${++n}. ${step.title}`, indent(step.code));
  out.push(
    '',
    'Presets: logs (defaults + phone numbers), llm (all personal data, names and',
    'addresses in prose), gdpr (llm + network and device IDs), strict (everything).',
    '',
    'Check the project now:     npx flare-redact --scan .',
    'Scan every pull request:   npx flare-redact init --ci',
    '',
  );
  return out.join('\n');
}

/** A GitHub workflow that fails a pull request when a secret is committed. */
export function ciWorkflow(version: string): string {
  return `name: Flare Redact

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-node@v5
        with:
          node-version: 24
      - name: Scan project text files
        run: npx --yes --package flare-redact@${version} flare-redact --scan . --exclude package-lock.json
`;
}

export const WORKFLOW_PATH = join('.github', 'workflows', 'flare-redact.yml');

export const INIT_HELP = `flare-redact init: suggest the integrations that fit this project

USAGE
  flare-redact init [dir] [--ci] [--force]

Reads package.json in dir (default: the current directory) and prints the lines
to paste for each library it recognises: openai, @anthropic-ai/sdk, pino,
winston and express, with console as the fallback. It never edits source files.

  --ci      also write ${WORKFLOW_PATH.split('\\').join('/')}, which runs
            'flare-redact --scan' on every pull request
  --force   overwrite that workflow if it already exists
`;

/** Run `flare-redact init`. Returns the exit code. */
export function runInit(argv: readonly string[], version: string, cwd: string = process.cwd()): number {
  let dir = cwd;
  let ci = false;
  let force = false;
  for (const arg of argv) {
    if (arg === '--ci') ci = true;
    else if (arg === '--force') force = true;
    else if (arg === '-h' || arg === '--help' || arg === 'help') {
      process.stdout.write(INIT_HELP);
      return 0;
    } else if (arg.startsWith('-')) {
      process.stderr.write(`unknown option: ${arg}\n\n${INIT_HELP}`);
      return 2;
    } else dir = join(cwd, arg);
  }

  const manifest = join(dir, 'package.json');
  let pkg: PackageJson | undefined;
  if (existsSync(manifest)) {
    try {
      pkg = JSON.parse(readFileSync(manifest, 'utf8')) as PackageJson;
    } catch (e) {
      process.stderr.write(`could not read ${manifest}: ${(e as Error).message}\n`);
      return 2;
    }
  }
  const source = pkg ? relative(cwd, manifest) || 'package.json' : undefined;
  process.stdout.write(renderInit(planInit(pkg), source));

  if (ci) {
    const target = join(dir, WORKFLOW_PATH);
    const shown = relative(cwd, target);
    if (existsSync(target) && !force) {
      process.stdout.write(`${shown} already exists; left unchanged (use --force to overwrite).\n`);
      return 0;
    }
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, ciWorkflow(version));
    process.stdout.write(`Wrote ${shown}.\n`);
  }
  return 0;
}
