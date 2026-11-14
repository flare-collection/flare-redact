/**
 * Is a `password = …` assignment code rather than a secret?
 *
 * `redact()` masks every such assignment, and must: hiding
 * `token = process.env.TOKEN` in a log costs nothing, while missing
 * `password=$ecret123` is a leak. A scan is different. It reports to a person
 * or stops a commit, and one that stops on `token = process.env.TOKEN` or
 * `password: string` is one people switch off. So this check is used only by
 * the CLI's scans, never by redaction.
 *
 * The detector's match stops at the first space or quote, so the match alone
 * is not enough to judge: `password: string = "hunter2"` and
 * `process.env.PASSWORD || "hunter2"` both start like code. The rest of the
 * line is read too, and a string literal anywhere in it that is not plainly
 * the name being looked up keeps the finding. When in doubt, report.
 */

import type { Finding } from './engine.js';

/** Longer values or lines are never treated as code; it also bounds the work. */
const MAX_VALUE = 256;
const MAX_REST = 600;

/** A whole value that is one variable reference or placeholder, quoted or not. */
const VARIABLE = new RegExp(
  '^(?:'
  // ${DB_PASSWORD}, ${config.token}: a bare name, no default after `:-`
  + '\\$\\{[A-Za-z_][A-Za-z0-9_.]*\\}'
  // $DB_PASSWORD: upper-case words joined by underscores, so `$TR0NGPASS`,
  // `$ecret123` and `$argon2id$…` stay reported
  + '|\\$[A-Z]+(?:_[A-Z0-9]+)*'
  // $db_password, and $password itself
  + '|\\$[a-z]+(?:_[a-z0-9]+)+'
  + '|\\$(?:password|passwd|pwd|pass|secret|token|apikey|key)'
  // %DB_PASSWORD%, %(password)s
  + '|%[A-Za-z_][A-Za-z0-9_]*%|%\\([A-Za-z_][A-Za-z0-9_]*\\)[sdr]'
  // <your-password>, [REDACTED], YOUR_API_KEY, xxxx, ****, ....
  + '|<[A-Za-z][A-Za-z _-]*>'
  + '|\\[(?:REDACTED|FILTERED|MASKED|HIDDEN|REMOVED|redacted|filtered|masked|hidden|removed)[A-Za-z _:-]*\\]'
  + '|(?:YOUR|Your|your)[_-][A-Za-z0-9_-]+|[xX]{3,}|\\*{3,}|\\.{3,}'
  + ')$',
);

/** From the value to the end of the line: `$(cat /run/secret)`, `{{ secret }}`, `${{ secrets.X }}`. */
const TEMPLATE_LINE = /^["']?(?:\$\([^()"'`]*\)|\$?\{\{[^{}"'`]*\}\})/;

/** A bare word that is a type or an empty value. */
const TYPE_OR_EMPTY = /^(?:string|str|String|number|int|integer|float|bool|boolean|any|unknown|bytes|SecretStr|Optional|None|null|nil|NULL|undefined|true|false|True|False|required|optional)$/;

/** `a.b?.c`, `f()`, `x[0]`, optionally cut off at an opening `(` or `[`. */
const CHAIN = /^[A-Za-z_$][A-Za-z0-9_$]*(?:\??\.[A-Za-z_$][A-Za-z0-9_$]*|\([^()]*\)|\[[^[\]]*\])*[([]?$/;

/** The object a field is read from holds configuration or input. */
const KNOWN_ROOT = /^(?:process\.env|import\.meta\.env|os\.environ|Deno\.env|Bun\.env|env|ENV|config|conf|cfg|settings|self|this|req|request|ctx|context|options|opts|args|params|props|secrets|vars|creds|credentials|System|window|globalThis)\??[.[(]/;

/** The last name of a field path is itself a sensitive name: `user.password`, `session.authToken`. */
const SENSITIVE_LAST = /^(?:[A-Za-z0-9$]+_)*(?:password|passwd|pwd|pass|secret|token|api_?key|key|credentials?)$|^[a-z0-9$]+(?:[A-Z][a-z0-9$]*)*(?:Password|Passwd|Pwd|Secret|Token|ApiKey|Key|Credentials?)$/;
const SENSITIVE_UPPER = /^(?:[A-Z0-9]+_)*(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_?KEY|KEY|CREDENTIALS?)$/;

/** The function or object a string is looked up in: `os.environ.get(`, `config[`, `headers.get(`. */
const LOOKUP = /(?:^|[.$_])(?:env|environ|getenv|config|conf|cfg|settings|secrets?|vault|headers?|params?|options|opts|args|get|getString|lookup|getpass|prompt|input)[([]$/i;

/** `"DB_PASSWORD"`: the name of an environment variable. */
const ENV_NAME = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/;
/** `"db.password"`, `"Authorization"`: words, not a random-looking value. */
const NAME_LIKE = /^[A-Za-z]+(?:[_.:/-](?:[A-Za-z]+|[0-9]+))*$/;

const STRING_LITERAL = /(["'`])((?:\\.|(?!\1)[^\\])*)\1/g;

/**
 * `text` is what was scanned, and `start`..`end` the span `generic_assignment`
 * matched: a sensitive name, `:` or `=`, then the value with its optional quotes.
 */
export function isCodeAssignment(text: string, start: number, end: number): boolean {
  const match = text.slice(start, end);
  const operatorAt = match.search(/[:=]/);
  if (operatorAt < 0) return false;
  const operator = match[operatorAt]!;

  const afterOperator = match.slice(operatorAt + 1);
  const valueOffset = start + operatorAt + 1 + (afterOperator.length - afterOperator.trimStart().length);
  const quote = /["']/.test(text[valueOffset] ?? '') ? text[valueOffset]! : '';
  const valueStart = valueOffset + quote.length;
  const value = /^[^\s"',;]*/.exec(text.slice(valueStart, valueStart + MAX_VALUE + 1))![0];
  if (!value || value.length > MAX_VALUE) return false;

  let lineEnd = text.indexOf('\n', valueStart);
  if (lineEnd < 0) lineEnd = text.length;
  if (lineEnd - valueOffset > MAX_REST) return false;
  /** From the value (with its quote) to the end of the line. */
  const rest = text.slice(valueOffset, lineEnd);

  // The whole name on the left: `MYSQL_ROOT_PASSWORD`, not just `PASSWORD`.
  const lineStart = text.lastIndexOf('\n', start - 1) + 1;
  const left = /[A-Za-z0-9_$.-]*$/.exec(text.slice(Math.max(lineStart, start - 128), start))![0];
  const key = (left + match.slice(0, operatorAt)).replace(/["'\s]/g, '');

  // One variable or placeholder is code wherever it stands, quoted or not,
  // as long as the string ends there.
  const closed = quote ? text[valueStart + value.length] === quote : true;
  if (closed && VARIABLE.test(value)) return true;
  if (TEMPLATE_LINE.test(rest)) return true;
  // Anything else in quotes is a string literal.
  if (quote) return false;

  // `DB_PASSWORD=value` and `DB_PASSWORD: value` are how .env files, shell and
  // YAML write a literal, so only a variable (handled above) counts there.
  // A type or an empty value is allowed after `:` (`API_KEY: string`).
  const spaced = /\s/.test(text[start + operatorAt - 1] ?? '') && /\s/.test(text[start + operatorAt + 1] ?? '');
  if (/^[A-Z][A-Z0-9_]*$/.test(key) && (operator === ':' || !spaced)) {
    return operator === ':' && TYPE_OR_EMPTY.test(value) && !/=(?![=>])/.test(rest.slice(value.length)) && !hasLiteral(rest, value);
  }

  const chain = CHAIN.test(value);
  const lastName = value.split(/\??\./).pop() ?? '';
  const type = TYPE_OR_EMPTY.test(value);
  const code = type
    || (chain && /[([]/.test(value))
    || (chain && KNOWN_ROOT.test(value))
    || (chain && (SENSITIVE_LAST.test(lastName) || SENSITIVE_UPPER.test(lastName)) && value.includes('.'))
    // `this.token = token`: the variable of the same name, with `=` only,
    // because `password: password` is how YAML writes a literal.
    || (operator === '=' && value === (key.split('.').pop() ?? '') && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(value));
  if (!code) return false;
  // `password: string = …` carries a value after the type.
  if (type && /=(?![=>])/.test(rest.slice(value.length))) return false;
  return !hasLiteral(rest, value);
}

/**
 * Does the rest of the line hold a string that could be the secret? The one
 * string that may be ignored is the first argument of a lookup, when it reads
 * as a name: `os.getenv("DB_PASSWORD")`, `config.get("db.password")`.
 */
function hasLiteral(rest: string, value: string): boolean {
  STRING_LITERAL.lastIndex = 0;
  for (let found = STRING_LITERAL.exec(rest); found; found = STRING_LITERAL.exec(rest)) {
    const content = found[2] ?? '';
    if (!content) continue;
    const firstArgument = found.index === value.length && /[([]$/.test(value);
    if (firstArgument && (ENV_NAME.test(content) || (NAME_LIKE.test(content) && LOOKUP.test(value)))) continue;
    return true;
  }
  // An opening quote with no partner on the line: a string that runs on.
  return /["'`]/.test(rest.replace(STRING_LITERAL, ''));
}

const overlaps = (a: Finding, b: Finding): boolean => a.start! < b.end! && b.start! < a.end!;

/**
 * Remove the `generic_assignment` findings in `text` that are code.
 * `rescan` runs the same scan with that detector off: an assignment finding
 * may have been standing in for a more specific one under it, which must
 * still be reported.
 */
export function withoutCodeAssignments(text: string, findings: Finding[], rescan: () => Finding[]): Finding[] {
  const dropped = findings.filter((f) =>
    f.detector === 'generic_assignment' && f.start !== undefined && f.end !== undefined && isCodeAssignment(text, f.start, f.end));
  if (!dropped.length) return findings;
  const kept = findings.filter((f) => !dropped.includes(f));
  const uncovered = rescan().filter((f) =>
    f.start !== undefined && f.end !== undefined
    && dropped.some((d) => overlaps(f, d))
    && !kept.some((k) => k.start !== undefined && k.end !== undefined && overlaps(f, k)));
  return [...kept, ...uncovered].sort((a, b) => (a.start ?? 0) - (b.start ?? 0));
}
