import type { Detector } from './detectors.js';
import { expandDottedI } from './fold.js';

export type TermSpec = string | { term: string; replace?: string };

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function normalizeTerms(
  input: TermSpec[] | Record<string, string> | undefined,
): Array<{ term: string; replace?: string }> {
  if (!input) return [];
  const list = Array.isArray(input)
    ? input.map((t) => (typeof t === 'string' ? { term: t } : t))
    : Object.entries(input).map(([term, replace]) => ({ term, replace }));
  return list.filter((t) => t.term && t.term.length > 0);
}

/**
 * A term must not touch a letter, a combining mark, a number or `_` on either
 * side (SPEC §9). Marks count as part of a word, so `राज` does not match inside
 * `राजा` and `cafe` does not match a decomposed `café`.
 */
const WORD = '[\\p{L}\\p{M}\\p{N}_]';

/**
 * Build a detector from a user-supplied word/phrase list. Terms are matched
 * literally, longest first (in characters; ties keep the caller's order), with
 * Unicode-aware boundaries, so it works for names and codewords in any language.
 * In a vault/session the matches get reversible placeholders; in a one-way
 * `redact` they use each term's `replace` text (or `***`).
 */
export function buildTermsDetector(
  input: TermSpec[] | Record<string, string> | undefined,
  caseSensitive = false,
): Detector | null {
  const list = normalizeTerms(input);
  if (!list.length) return null;

  // Array.prototype.sort is stable, so equal lengths keep the caller's order.
  const ordered = [...list].sort((a, b) => [...b.term].length - [...a.term].length);
  const flags = caseSensitive ? 'u' : 'iu';
  const source = (term: string) => (caseSensitive ? escapeRe(term) : expandDottedI(escapeRe(term)));
  const alt = ordered.map((t) => source(t.term)).join('|');
  const pattern = new RegExp(`(?<!${WORD})(?:${alt})(?!${WORD})`, `g${flags}`);

  // The replacement belongs to the first term (in matching order) that matches
  // the text exactly, which is the alternative the scan above took.
  const exact = ordered.map((t) => ({ re: new RegExp(`^(?:${source(t.term)})$`, flags), replace: t.replace ?? '***' }));
  const replacementFor = (match: string): string => exact.find((t) => t.re.test(match))?.replace ?? '***';

  return {
    id: 'custom_term',
    label: 'Custom term',
    why: 'A term you configured as sensitive.',
    pattern,
    mask: replacementFor,
    default: true,
    tags: ['custom'],
  };
}
