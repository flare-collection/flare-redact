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

/**
 * A predicate for repository-relative paths that never touch the disk (staged
 * files, for example): true when the path, or any directory on the way to it,
 * is excluded by the defaults or by an `--exclude` glob.
 */
export function createPathFilter(options: Pick<FileDiscoveryOptions, 'excludes' | 'defaultExcludes'>): (path: string) => boolean {
  const matchers = (options.excludes ?? []).map(compileExclude);
  return (path) => {
    const parts = normalizePath(path).split('/').filter(Boolean);
    for (let i = 0; i < parts.length; i++) {
      const name = parts[i]!;
      const directory = i < parts.length - 1;
      if (directory && options.defaultExcludes && DEFAULT_EXCLUDED_DIRECTORIES.has(name)) return true;
      const prefix = parts.slice(0, i + 1).join('/');
      if (matchers.some((matcher) => matcher.matches(prefix, name, directory))) return true;
    }
    return false;
  };
}

function compileExclude(rawPattern: string): ExcludeMatcher {
  const normalized = normalizePath(rawPattern.trim())
    .replace(/^\.\/+/, '')
    .replace(/^\/+/, '');
  if (!normalized) throw new Error('--exclude requires a non-empty glob');

  const directoryOnly = normalized.endsWith('/');
  const pattern = directoryOnly ? normalized.slice(0, -1) : normalized;
  const basenameOnly = !pattern.includes('/');
  // Consecutive `**` parts mean the same as one.
  const parts = pattern.split('/').filter((part, i, all) => !(part === '**' && all[i - 1] === '**'));

  return {
    matches(path, name, directory) {
      if (directoryOnly && !directory) return false;
      return basenameOnly ? segmentMatches(pattern, name) : pathMatches(parts, path.split('/'));
    },
  };
}

/**
 * Match one path segment against a glob with `*` (any run of characters) and
 * `?` (one character). Two pointers and one remembered star, so the cost is
 * at most pattern length times segment length, never worse.
 */
function segmentMatches(glob: string, segment: string): boolean {
  let g = 0;
  let s = 0;
  let star = -1;
  let resume = 0;
  while (s < segment.length) {
    if (g < glob.length && (glob[g] === '?' || (glob[g] !== '*' && glob[g] === segment[s]))) {
      g++;
      s++;
    } else if (g < glob.length && glob[g] === '*') {
      star = g++;
      resume = s;
    } else if (star >= 0) {
      g = star + 1;
      s = ++resume;
    } else return false;
  }
  while (g < glob.length && glob[g] === '*') g++;
  return g === glob.length;
}

/**
 * Match a path against glob parts, where a part that is exactly `**` stands
 * for any number of whole segments (at least one when it ends the pattern, so
 * `dir/**` means what is inside `dir`). A table over parts and segments
 * keeps it proportional to their product: a regular expression built from
 * several `**` backtracks without bound on a deep path.
 */
function pathMatches(parts: readonly string[], segments: readonly string[]): boolean {
  const columns = segments.length + 1;
  // reach[p * columns + s]: parts from p on match segments from s on.
  const reach = new Uint8Array((parts.length + 1) * columns);
  reach[parts.length * columns + segments.length] = 1;
  for (let p = parts.length - 1; p >= 0; p--) {
    const part = parts[p]!;
    const last = p === parts.length - 1;
    for (let s = segments.length; s >= 0; s--) {
      let ok: boolean;
      if (part === '**') {
        ok = last
          ? s < segments.length
          : reach[(p + 1) * columns + s] === 1 || (s < segments.length && reach[p * columns + s + 1] === 1);
      } else {
        ok = s < segments.length && reach[(p + 1) * columns + s + 1] === 1 && segmentMatches(part, segments[s]!);
      }
      reach[p * columns + s] = ok ? 1 : 0;
    }
  }
  return reach[0] === 1;
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
