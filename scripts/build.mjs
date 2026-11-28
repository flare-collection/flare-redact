#!/usr/bin/env node
// Builds the package twice from the same source: ES modules in dist/ and
// CommonJS in dist/cjs/ (for require(), Jest and older bundlers). The gateway
// and the CLI read their own version through import.meta and stay ESM only.
import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const tsc = createRequire(import.meta.url).resolve('typescript/bin/tsc');

rmSync(join(root, 'dist'), { recursive: true, force: true });
execFileSync(process.execPath, [tsc, '-p', join(root, 'tsconfig.json')], { stdio: 'inherit' });
execFileSync(process.execPath, [tsc, '-p', join(root, 'tsconfig.cjs.json')], { stdio: 'inherit' });
mkdirSync(join(root, 'dist', 'cjs'), { recursive: true });
writeFileSync(join(root, 'dist', 'cjs', 'package.json'), '{\n  "type": "commonjs"\n}\n');
