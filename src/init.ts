/**
 * `flare-redact init`: read the project's package.json, pick the integrations
 * that fit, and print the lines to paste. `--ci` also writes a GitHub workflow
 * that scans every pull request, and `--hook` a git pre-commit hook that scans
 * the lines each commit adds. It never edits source files: the output is a
 * plan the developer applies, so nothing changes behind their back.
 */

import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
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
const GDPR: Preset = 'gdpr';

/** The Sentry SDKs whose `init` takes the hooks, in the order they are checked. */
const SENTRY_SDKS = [
  '@sentry/nextjs', '@sentry/node', '@sentry/nestjs', '@sentry/bun', '@sentry/deno',
  '@sentry/aws-serverless', '@sentry/google-cloud-serverless', '@sentry/cloudflare',
  '@sentry/sveltekit', '@sentry/nuxt', '@sentry/remix', '@sentry/astro',
  '@sentry/react', '@sentry/vue', '@sentry/angular', '@sentry/svelte', '@sentry/solid',
  '@sentry/browser', '@sentry/react-native', '@sentry/electron',
] as const;

interface Recipe {
  /** Any of these dependencies triggers the recipe; the first one found is named. */
  deps: readonly string[];
  title: string;
  /** `range` is the version range package.json asks for. */
  code: (dep: string, range: string) => string;
}

/** The major version a range like `^11.2.0` or `>=10 <12` starts at, if it names one. */
const major = (range: string): number | undefined => {
  const found = /^[^\d]*(\d+)/.exec(range);
  return found ? Number(found[1]) : undefined;
};

/** One recipe per supported library, in the order they are printed. */
const RECIPES: readonly Recipe[] = [
  {
    deps: ['openai'],
    title: 'OpenAI: prompts are redacted before they leave, replies are restored',
    code: () => `import OpenAI from 'openai';
import { wrapOpenAI } from 'flare-redact/llm';

const openai = wrapOpenAI(new OpenAI(), { preset: '${LLM}' });`,
  },
  {
    deps: ['@anthropic-ai/sdk'],
    title: 'Anthropic: prompts are redacted before they leave, replies are restored',
    code: () => `import Anthropic from '@anthropic-ai/sdk';
import { wrapAnthropic } from 'flare-redact/llm';

const anthropic = wrapAnthropic(new Anthropic(), { preset: '${LLM}' });`,
  },
  {
    deps: SENTRY_SDKS,
    title: 'Sentry: events, breadcrumbs, spans and logs are redacted before they are sent',
    // Sentry 11 streams spans and warns about a beforeSendTransaction hook.
    code: (dep, range) => `import * as Sentry from '${dep}';
import { sentryRedact } from 'flare-redact/sentry';

Sentry.init({ dsn: process.env.SENTRY_DSN, ...sentryRedact({ preset: '${GDPR}' }${(major(range) ?? 0) >= 11 ? ", { traceLifecycle: 'stream' }" : ''}) });`,
  },
  {
    deps: ['pino'],
    title: 'pino: every log line is redacted',
    code: () => `import pino from 'pino';
import { pinoRedact } from 'flare-redact/pino';

const log = pino(pinoRedact({ preset: '${LOGS}' }));`,
  },
  {
    deps: ['winston'],
    title: 'winston: every log field is redacted',
    code: () => `import winston from 'winston';
import { winstonRedact } from 'flare-redact/winston';

const log = winston.createLogger({
  format: winston.format.combine(winston.format(winstonRedact({ preset: '${LOGS}' }))(), winston.format.json()),
  transports: [new winston.transports.Console()],
});`,
  },
  {
    deps: ['express'],
    title: 'Express: log a safe copy of each request',
    code: () => `import { httpRedactor } from 'flare-redact/http';

app.use(httpRedactor({ preset: '${LOGS}' }));
app.use((req, _res, next) => { console.log(req.redacted()); next(); });`,
  },
];

const CONSOLE_STEP: InitStep = {
  title: 'console: redact everything printed with console.*',
  code: `// With no code change, start the app with:
//   FLARE_REDACT_PRESET=${LOGS} node --import flare-redact/register app.js
// or call this once, before anything logs:
import { wrapConsole } from 'flare-redact';

wrapConsole({ preset: '${LOGS}' });`,
};

/** Decide what to suggest for a package.json (or for no package.json at all). */
export function planInit(pkg: PackageJson | undefined): InitPlan {
  const deps = { ...pkg?.devDependencies, ...pkg?.dependencies };
  const has = (name: string): boolean => Object.prototype.hasOwnProperty.call(deps, name);
  const steps: InitStep[] = RECIPES.flatMap((recipe) => {
    const dep = recipe.deps.find(has);
    return dep ? [{ found: dep, title: recipe.title, code: recipe.code(dep, String(deps[dep] ?? '')) }] : [];
  });
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
    'Check every commit:        npx flare-redact init --hook',
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

/** The line to add to a pre-commit hook that another tool manages. */
export const HOOK_COMMAND = 'npx flare-redact --scan --staged';

/**
 * The git pre-commit hook `--hook` writes. It prefers the project's own copy
 * and falls back to the pinned release, so it works before `npm install` too.
 */
export function preCommitHook(version: string): string {
  return `#!/bin/sh
# Added by 'flare-redact init --hook': stop commits that add secrets or
# personal data. Only the lines a commit adds are scanned.
# Skip the check once with: git commit --no-verify
if ! command -v node >/dev/null 2>&1 || ! command -v npx >/dev/null 2>&1; then
  # A git client started without Node on its PATH: let the commit through
  # and say so, rather than block every commit from that client.
  echo "flare-redact: Node not found on PATH, commit not scanned" >&2
  exit 0
fi
if [ -x node_modules/.bin/flare-redact ]; then
  exec node_modules/.bin/flare-redact --scan --staged
fi
exec npx --yes --package flare-redact@${version} flare-redact --scan --staged
`;
}

export const INIT_HELP = `flare-redact init: suggest the integrations that fit this project

USAGE
  flare-redact init [dir] [--ci] [--hook] [--force]

Reads package.json in dir (default: the current directory) and prints the lines
to paste for each library it recognises: openai, @anthropic-ai/sdk, Sentry,
pino, winston and express, with console as the fallback. It never edits source
files.

  --ci      also write ${WORKFLOW_PATH.split('\\').join('/')}, which runs
            'flare-redact --scan' on every pull request
  --hook    also write a git pre-commit hook that runs
            'flare-redact --scan --staged', so a commit that adds a secret
            stops before it is made (with husky, it prints the line to add)
  --force   overwrite that workflow or hook if it already exists
`;

function installHook(dir: string, cwd: string, version: string, force: boolean): number {
  const git = (...args: string[]): string =>
    execFileSync('git', args, { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  let hooks: string;
  let roots: string[];
  try {
    hooks = git('rev-parse', '--git-path', 'hooks');
    // resolve() also turns git's forward slashes into the platform's separator.
    roots = [resolve(git('rev-parse', '--show-toplevel')), resolve(realpathSync(dir), git('rev-parse', '--git-common-dir'))]
      .map((root) => (existsSync(root) ? realpathSync(root) : root));
  } catch {
    process.stderr.write("--hook needs a git repository; run 'git init' first.\n");
    return 2;
  }
  // husky owns core.hooksPath and regenerates that folder; a file written
  // there would vanish, so say where the line belongs instead.
  if (/(?:^|[\\/])\.husky(?:[\\/]|$)/.test(hooks)) {
    process.stdout.write(`This repository runs its hooks through husky. Add this line to .husky/pre-commit:\n   ${HOOK_COMMAND}\n`);
    return 0;
  }
  // git prints real paths; resolve ours the same way (macOS /var is /private/var).
  // A hooks folder that is a symlink counts as where it points.
  const lexical = isAbsolute(hooks) ? resolve(hooks) : resolve(realpathSync(dir), hooks);
  const hooksDir = existsSync(lexical) ? realpathSync(lexical) : lexical;
  // A core.hooksPath outside the repository is shared with other projects;
  // writing there would change them too.
  if (!roots.some((root) => hooksDir === root || hooksDir.startsWith(root + sep))) {
    process.stdout.write(`Hooks for this repository live in ${hooksDir}, outside it. Add this line to the pre-commit hook there:\n   ${HOOK_COMMAND}\n`);
    return 0;
  }
  const target = join(hooksDir, 'pre-commit');
  const shown = relative(cwd, target) || target;
  // lstat, not exists: a symlink counts as a hook even when it dangles, and
  // is replaced by --force rather than written through.
  const present = lstatSync(target, { throwIfNoEntry: false }) !== undefined;
  if (present && !force) {
    process.stdout.write(`${shown} already exists; left unchanged. Add this line to it, or use --force to replace it:\n   ${HOOK_COMMAND}\n`);
    return 0;
  }
  mkdirSync(hooksDir, { recursive: true });
  if (present) rmSync(target, { force: true });
  writeFileSync(target, preCommitHook(version), { flag: 'wx' });
  chmodSync(target, 0o755);
  process.stdout.write(`Wrote ${shown}. Every commit is now scanned; skip once with git commit --no-verify.\n`);
  return 0;
}

/** Run `flare-redact init`. Returns the exit code. */
export function runInit(argv: readonly string[], version: string, cwd: string = process.cwd()): number {
  let dir = cwd;
  let ci = false;
  let hook = false;
  let force = false;
  for (const arg of argv) {
    if (arg === '--ci') ci = true;
    else if (arg === '--hook') hook = true;
    else if (arg === '--force') force = true;
    else if (arg === '-h' || arg === '--help' || arg === 'help') {
      process.stdout.write(INIT_HELP);
      return 0;
    } else if (arg.startsWith('-')) {
      process.stderr.write(`unknown option: ${arg}\n\n${INIT_HELP}`);
      return 2;
    } else dir = resolve(cwd, arg);
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
    } else {
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, ciWorkflow(version));
      process.stdout.write(`Wrote ${shown}.\n`);
    }
  }
  return hook ? installHook(dir, cwd, version, force) : 0;
}
