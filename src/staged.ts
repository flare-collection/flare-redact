/**
 * `flare-redact --scan --staged`: scan only the lines a commit adds.
 *
 * A pre-commit hook that scanned whole files would block every commit that
 * touches a file with an old finding, and people would learn to skip it.
 * Reading the staged diff instead means a commit is stopped only for what it
 * introduces, and each finding points at the line number in the staged file.
 */

import { execFileSync } from 'node:child_process';
import { createPathFilter } from './file-discovery.js';

export interface AddedBlock {
  /** Repository-relative path, exactly as git reports it. */
  readonly file: string;
  /** One-based line number, in the staged file, of the block's first line. */
  readonly line: number;
  /** The added lines, joined with `\n`. */
  readonly text: string;
}

export interface StagedSkips {
  excluded: number;
  oversized: number;
}

export interface StagedChanges {
  readonly files: string[];
  readonly blocks: AddedBlock[];
  readonly skipped: StagedSkips;
}

/**
 * Turn one file's `git diff --unified=0` output into runs of added lines.
 * Removed lines contribute nothing.
 */
export function addedBlocks(file: string, diff: string): AddedBlock[] {
  const blocks: AddedBlock[] = [];
  let inHunk = false;
  let next = 0;
  let start = 0;
  let lines: string[] = [];
  const flush = (): void => {
    if (lines.length) blocks.push({ file, line: start, text: lines.join('\n') });
    lines = [];
  };
  for (const raw of diff.split('\n')) {
    // A type change is two sections (the old file removed, the new one added);
    // the second header must not be read as content of the first hunk.
    if (raw.startsWith('diff --git ')) {
      flush();
      inHunk = false;
      continue;
    }
    if (raw.startsWith('@@')) {
      flush();
      const header = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
      inHunk = header !== null;
      next = header ? Number(header[1]) : 0;
      continue;
    }
    if (!inHunk) continue;
    if (raw.startsWith('+')) {
      if (!lines.length) start = next;
      lines.push(raw.slice(1).replace(/\r$/, ''));
      next++;
    } else if (raw.startsWith('\\')) {
      // "\ No newline at end of file" belongs to the line before it.
    } else {
      flush();
      // A context line: a leading space, or nothing at all when git is set to
      // drop the space of an empty one (diff.suppressBlankEmpty).
      if (raw.startsWith(' ') || raw === '') next++;
    }
  }
  flush();
  return blocks;
}

/**
 * Parse `git diff --name-status -z`: `A\0path\0`, `M\0path\0`, and for a
 * rename `R<score>\0old\0new\0`.
 */
export function stagedEntries(nameStatus: string): Array<{ file: string; from?: string }> {
  const parts = nameStatus.split('\0');
  const entries: Array<{ file: string; from?: string }> = [];
  for (let i = 0; i < parts.length; i++) {
    const status = parts[i]!;
    if (!status) continue;
    if (status.startsWith('R') || status.startsWith('C')) {
      const from = parts[++i];
      const file = parts[++i];
      if (file) entries.push(status.startsWith('R') && from ? { file, from } : { file });
    } else {
      const file = parts[++i];
      if (file) entries.push({ file });
    }
  }
  return entries;
}

const git = (cwd: string, args: string[], maxBuffer: number): string =>
  execFileSync('git', args, { cwd, encoding: 'utf8', maxBuffer, stdio: ['ignore', 'pipe', 'pipe'] });

/** Read what the next commit would add. Throws when `cwd` is not a git work tree. */
export function readStagedChanges(
  cwd: string,
  options: { excludes?: string[]; defaultExcludes: boolean; maxFileSize: number },
): StagedChanges {
  let names: string;
  let top: string;
  try {
    // Paths come back relative to the top of the work tree, so every later
    // command runs there too, whichever subdirectory the scan started in.
    top = git(cwd, ['rev-parse', '--show-toplevel'], 1024 * 1024).trim();
    names = git(top, ['diff', '--cached', '--name-status', '-z', '-M', '--diff-filter=ACMRT'], 64 * 1024 * 1024);
  } catch (e) {
    const detail = String((e as { stderr?: unknown }).stderr ?? (e as Error).message).trim();
    throw new Error(`--staged needs a git repository: ${detail}`);
  }
  const excluded = createPathFilter(options);
  const skipped: StagedSkips = { excluded: 0, oversized: 0 };
  const files: string[] = [];
  const blocks: AddedBlock[] = [];
  // A diff is roughly the file plus one character per line, so twice the
  // size limit (and a floor for small limits) is enough headroom.
  const maxBuffer = Math.max(options.maxFileSize * 2, 1024 * 1024);
  for (const { file, from } of stagedEntries(names)) {
    if (excluded(file)) {
      skipped.excluded++;
      continue;
    }
    let diff: string;
    try {
      // --literal-pathspecs: a file called "*.js" or ":x" is that file, not a pattern.
      // A renamed file is diffed against its old path, so moving a file does
      // not make its whole content look new.
      // --text: every file is diffed as text, including ones a .gitattributes
      // rule marks `-diff` or `binary`, so nothing staged goes unread. The two
      // context settings keep every hunk to added and removed lines only.
      diff = git(top, ['--literal-pathspecs', '-c', 'diff.suppressBlankEmpty=false', 'diff', '--cached', '-M', '--unified=0', '--inter-hunk-context=0', '--no-color', '--no-ext-diff', '--no-textconv', '--text', '--', ...(from ? [from] : []), file], maxBuffer);
    } catch (e) {
      if ((e as { code?: string }).code === 'ENOBUFS') {
        skipped.oversized++;
        continue;
      }
      throw e;
    }
    files.push(file);
    blocks.push(...addedBlocks(file, diff));
  }
  return { files, blocks, skipped };
}
