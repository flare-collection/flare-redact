// Print the CHANGELOG section of one version, for the GitHub Release body.
//
//   node scripts/release-notes.mjs 1.7.0 > notes.md
//   node scripts/release-notes.mjs          # the version in package.json
//
// Exits 1 when CHANGELOG.md has no section for that version, so a release is
// never published with an empty or wrong body.

import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const root = new URL('../', import.meta.url);
const version = process.argv[2] ?? JSON.parse(readFileSync(new URL('package.json', root), 'utf8')).version;

/** The body under `## <version>` up to the next `## ` heading, trimmed. */
export function releaseNotes(changelog, wanted) {
  const lines = changelog.split(/\r?\n/);
  const heading = new RegExp(`^## ${wanted.replace(/\./g, '\\.')}(?![0-9A-Za-z.-])`);
  const start = lines.findIndex((line) => heading.test(line));
  if (start === -1) return undefined;
  let end = lines.findIndex((line, i) => i > start && /^## /.test(line));
  if (end === -1) end = lines.length;
  const body = lines.slice(start + 1, end).join('\n').trim();
  return body || undefined;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const notes = releaseNotes(readFileSync(new URL('CHANGELOG.md', root), 'utf8'), version);
  if (!notes) {
    process.stderr.write(`CHANGELOG.md has no section for ${version}\n`);
    process.exit(1);
  }
  process.stdout.write(`${notes}\n`);
}
