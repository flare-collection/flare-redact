// Case handling shared by every FRS-1 engine (SPEC §2 "Flags", §9).
//
// Case-insensitive matching is Unicode simple case folding plus one merge: i, I,
// İ (U+0130) and ı (U+0131) form a single class. Simple folding alone keeps the
// two Turkish letters apart from i, so `ŞİFRE`, `GİZLİ` or an identifier that was
// upper-cased under a Turkish locale (`APİ_KEY`) would slip past every keyword.
// Python's `re.IGNORECASE` already merges the four; engines that fold exactly
// (JavaScript with `u`, Go, Rust) rewrite their patterns with expandDottedI.

const DOTTED: ReadonlySet<number> = new Set([0x69, 0x49, 0x130, 0x131]);
const DOTTED_CLASS = 'iI\u{130}\u{131}';

const SIMPLE_ESCAPES: Readonly<Record<string, number>> = { t: 9, n: 10, r: 13, f: 12 };

/** Read one class or literal atom at `index`; `code` is null for an escape whose set is opaque (`\d`, `\p{…}`). */
function readAtom(source: string, index: number): { code: number | null; next: number } {
  const ch = source[index]!;
  if (ch !== '\\') {
    const code = source.codePointAt(index)!;
    return { code, next: index + (code > 0xffff ? 2 : 1) };
  }
  const esc = source[index + 1];
  if (esc === undefined) return { code: null, next: index + 1 };
  if (esc === 'x' && /^[0-9A-Fa-f]{2}$/.test(source.slice(index + 2, index + 4))) {
    return { code: parseInt(source.slice(index + 2, index + 4), 16), next: index + 4 };
  }
  if (esc === 'p' || esc === 'P') {
    const close = source[index + 2] === '{' ? source.indexOf('}', index + 3) : -1;
    return { code: null, next: close >= 0 ? close + 1 : index + 2 };
  }
  if (esc in SIMPLE_ESCAPES) return { code: SIMPLE_ESCAPES[esc]!, next: index + 2 };
  if (/[A-Za-z0-9]/.test(esc)) return { code: null, next: index + 2 };
  return { code: esc.codePointAt(0)!, next: index + 2 };
}

/**
 * Rewrite a pattern that will be compiled case-insensitively so that i, I, İ and
 * ı are interchangeable. A literal becomes `[iIİı]`; a character class that holds
 * any of the four (directly or inside a range) gains the other three, which for a
 * negated class keeps all four out. Escapes with an opaque set (`\d`, `\p{L}`)
 * are left alone: FRS-1 patterns cannot contain them, and the built-in Node
 * patterns that do never rely on them for the letter i.
 */
export function expandDottedI(source: string): string {
  let out = '';
  let index = 0;
  while (index < source.length) {
    const ch = source[index]!;
    if (ch === '{' && source.startsWith('{{', index)) {
      const close = source.indexOf('}}', index + 2);
      const end = close < 0 ? source.length : close + 2;
      out += source.slice(index, end);
      index = end;
      continue;
    }
    if (ch === '(' && source.startsWith('(?<', index) && /[A-Za-z]/.test(source[index + 3] ?? '')) {
      // A named group header: its name is not a literal to rewrite.
      const close = source.indexOf('>', index);
      const end = close < 0 ? source.length : close + 1;
      out += source.slice(index, end);
      index = end;
      continue;
    }
    if (ch === '[') {
      const { text, next } = rewriteClass(source, index);
      out += text;
      index = next;
      continue;
    }
    const { code, next } = readAtom(source, index);
    out += code !== null && DOTTED.has(code) ? `[${DOTTED_CLASS}]` : source.slice(index, next);
    index = next;
  }
  return out;
}

function rewriteClass(source: string, start: number): { text: string; next: number } {
  let index = start + 1;
  if (source[index] === '^') index++;
  const bodyStart = index;
  if (source[index] === ']') index++;
  let holds = false;
  let lastDash = -1;
  while (index < source.length && source[index] !== ']') {
    const first = readAtom(source, index);
    let lo = first.code;
    let hi = first.code;
    index = first.next;
    lastDash = -1;
    if (source[index] === '-' && index + 1 < source.length && source[index + 1] !== ']') {
      const second = readAtom(source, index + 1);
      hi = second.code;
      index = second.next;
      if (lo === null || hi === null) lo = hi = null;
    } else if (source[index - 1] === '-' && source[index - 2] !== '\\') {
      lastDash = index - 1;
    }
    if (lo !== null && hi !== null) {
      for (const code of DOTTED) if (code >= lo && code <= hi) holds = true;
    }
  }
  // An unterminated class: leave it for the compiler to reject.
  if (index >= source.length) return { text: source.slice(start), next: source.length };
  const close = index;
  const head = source.slice(start, bodyStart);
  let body = source.slice(bodyStart, close);
  if (holds) {
    // Never append right after a trailing literal `-`: `[a-z-]` + `i` would
    // read as a range. Insert in front of that dash instead.
    body = lastDash === close - 1 ? `${body.slice(0, -1)}${DOTTED_CLASS}-` : `${body}${DOTTED_CLASS}`;
  }
  return { text: `${head}${body}]`, next: close + 1 };
}

/**
 * The form a key name is compared in (SPEC §9): İ and ı become i, every
 * character takes its simple lowercase mapping, and final sigma and long s fold
 * to σ and s. `toLowerCase` differs from simple lowercasing only for İ and the
 * final-sigma rule, both of which this erases, so every engine agrees.
 */
export function normalizeKeyName(name: string): string {
  return name
    .replace(/[\u{130}\u{131}]/gu, 'i')
    .toLowerCase()
    .replace(/\u{3c2}/gu, '\u{3c3}')
    .replace(/\u{17f}/gu, 's');
}

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * One case-insensitive search for any of `literals`, with the same case rules as
 * a detector pattern, so a prefilter never skips a detector that would match.
 */
export function prefilterPattern(literals: readonly string[]): RegExp {
  return new RegExp(literals.map((literal) => expandDottedI(escapeRe(literal))).join('|'), 'iu');
}
