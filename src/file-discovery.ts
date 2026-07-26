import {
  closeSync,
  lstatSync,
  openSync,
  readSync,
  readdirSync,
} from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';

const DEFAULT_EXCLUDED_DIRECTORIES = new Set([
  '.git',
  '.hg',
  '.svn',
  'node_modules',
  'vendor',
]);

const BINARY_SAMPLE_BYTES = 8 * 1024;

export interface FileDiscoveryOptions {
  excludes?: string[];
  maxFileSize: number;
  defaultExcludes: boolean;
}

export interface SkipSummary {
  excluded: number;
  binary: number;
  oversized: number;
  symlink: number;
}

export interface FileDiscoveryResult {
  files: string[];
  skipped: SkipSummary;
}

interface ExcludeMatcher {
  matches(path: string, name: string, directory: boolean): boolean;
}

/**
 * Expands explicit directory arguments into regular text files. Explicit file
 * arguments remain backward compatible: size and binary guards only apply to
 * files discovered while walking a directory.
 */
export function discoverScanFiles(inputs: string[], options: FileDiscoveryOptions): FileDiscoveryResult {
  const files: string[] = [];
  const seen = new Set<string>();
  const visitedDirectories = new Set<string>();
  const skipped: SkipSummary = { excluded: 0, binary: 0, oversized: 0, symlink: 0 };
  const matchers = (options.excludes ?? []).map(compileExclude);

  const add = (path: string): void => {
    const identity = resolve(path);
    if (seen.has(identity)) return;
    seen.add(identity);
    files.push(path);
  };

  const walk = (root: string, directory: string): void => {
    const directoryIdentity = resolve(directory);
    if (visitedDirectories.has(directoryIdentity)) return;
    visitedDirectories.add(directoryIdentity);

    const entries = readdirSync(directory, { withFileTypes: true })
      .sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);

    for (const entry of entries) {
      const path = join(directory, entry.name);
      const relativePath = normalizePath(relative(root, path));

      if (entry.isSymbolicLink()) {
        skipped.symlink++;
        continue;
      }

      const directoryExcluded = entry.isDirectory()
        && options.defaultExcludes
        && DEFAULT_EXCLUDED_DIRECTORIES.has(entry.name);
      const customExcluded = matchers.some((matcher) =>
        matcher.matches(relativePath, entry.name, entry.isDirectory()));
      if (directoryExcluded || customExcluded) {
        skipped.excluded++;
        continue;
      }

      if (entry.isDirectory()) {
        walk(root, path);
        continue;
      }
      if (!entry.isFile()) continue;

      const stat = lstatSync(path);
      if (stat.size > options.maxFileSize) {
        skipped.oversized++;
        continue;
      }
      if (isBinaryFile(path, stat.size)) {
        skipped.binary++;
        continue;
      }
      add(path);
    }
  };

  for (const input of inputs) {
    const stat = lstatSync(input);
    if (stat.isSymbolicLink()) {
      skipped.symlink++;
    } else if (stat.isDirectory()) {
      walk(input, input);
    } else if (stat.isFile()) {
      add(input);
    }
  }

  return { files, skipped };
}

function compileExclude(rawPattern: string): ExcludeMatcher {
  const normalized = normalizePath(rawPattern.trim())
    .replace(/^\.\/+/, '')
    .replace(/^\/+/, '');
  if (!normalized) throw new Error('--exclude requires a non-empty glob');

  const directoryOnly = normalized.endsWith('/');
  const pattern = directoryOnly ? normalized.slice(0, -1) : normalized;
  const basenameOnly = !pattern.includes('/');
  const expression = globToRegExp(pattern);

  return {
    matches(path, name, directory) {
      if (directoryOnly && !directory) return false;
      return expression.test(basenameOnly ? name : path);
    },
  };
}

function globToRegExp(pattern: string): RegExp {
  let source = '^';
  for (let i = 0; i < pattern.length; i++) {
    const char = pattern[i]!;
    if (char === '*') {
      if (pattern[i + 1] === '*') {
        if (pattern[i + 2] === '/') {
          source += '(?:.*/)?';
          i += 2;
        } else {
          source += '.*';
          i++;
        }
      } else {
        source += '[^/]*';
      }
    } else if (char === '?') {
      source += '[^/]';
    } else {
      source += char.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&');
    }
  }
  return new RegExp(`${source}$`);
}

function normalizePath(path: string): string {
  return sep === '/' ? path : path.split(sep).join('/');
}

function isBinaryFile(path: string, size: number): boolean {
  if (size === 0) return false;
  const descriptor = openSync(path, 'r');
  try {
    const sample = Buffer.allocUnsafe(Math.min(size, BINARY_SAMPLE_BYTES));
    const bytesRead = readSync(descriptor, sample, 0, sample.length, 0);
    return sample.subarray(0, bytesRead).includes(0);
  } finally {
    closeSync(descriptor);
  }
}
