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
 * It does not try to understand code. Everything from the operator to the end
 * of the line must be exactly one of a few closed forms (a variable, an
 * environment read, a field named like a secret, a call with no arguments, a
 * type, a placeholder), followed by nothing but closing punctuation or a
 * comment. A default value, a second argument, a string, a number, anything
 * left over: the finding stays. Unknown shapes are reported, not guessed at.
 */

import type { Finding } from './engine.js';

/** How much of the line is read. A longer rest of line is never code. */
const MAX_REST = 300;

const NAME = '[A-Za-z_][A-Za-z0-9_]*';
const ENV_NAME = '[A-Z][A-Z0-9_]*';
const SENSITIVE = '(?:(?:[A-Za-z0-9]+_)*(?:password|passwd|pwd|pass|secret|token|api_?key|key|credentials?)|(?:[A-Z0-9]+_)*(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_?KEY|KEY|CREDENTIALS?)|[a-z0-9]+(?:[A-Z][a-z0-9]*)*(?:Password|Passwd|Pwd|Secret|Token|ApiKey|Key|Credentials?))';
const TYPE = '(?:string|str|String|number|int|integer|float|bool|boolean|any|unknown|bytes|SecretStr|None|null|nil|NULL|undefined|true|false|True|False)';
/** An empty default: `, ""`, `|| ''`, `?? null`. */
const EMPTY_ARGUMENT = '(?:\\s*,\\s*(?:""|\'\'|None|null|nil))?';
const EMPTY_FALLBACK = '(?:\\s*(?:\\|\\||\\?\\?|or)\\s*(?:""|\'\'|None|null|nil|undefined))?';
/** `"NAME"` or `'NAME'`. */
const quotedEnv = `(?:"${ENV_NAME}"|'${ENV_NAME}')`;

/** After a form: closing punctuation, then at most a comment. */
const TAIL = '[\\s;,)}\\]]*(?:(?://|#).*)?$';

/** One variable or template, with or without quotes around it. */
const VARIABLE = `(["']?)(?:`
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
  // {{ secret }}, ${{ secrets.NPM_TOKEN }}, {{ .Values.password | b64enc }}
  + '|\\$?\\{\\{\\s*\\.?[A-Za-z_][A-Za-z0-9_.]*(?:\\s*\\|\\s*[A-Za-z_][A-Za-z0-9_]*)*\\s*\\}\\}'
  + ')\\1';

/** A value that stands for one: `<your-password>`, `[REDACTED]`, `YOUR_API_KEY`, `****`. */
const PLACEHOLDER = `(["']?)(?:`
  + '<[A-Za-z][A-Za-z _-]*>'
  + '|\\[(?:REDACTED|FILTERED|MASKED|HIDDEN|REMOVED|redacted|filtered|masked|hidden|removed)[A-Za-z _:-]*\\]'
  + '|(?:YOUR|Your|your)[_-][A-Za-z0-9_-]+|[xX]{3,}|\\*{3,}|\\.{3,}'
  + ')\\1';

/** Reading the environment, in the languages that have one obvious way to. */
const ENV_READ = '(?:'
  + `process\\.env\\.${NAME}|process\\.env\\[${quotedEnv}\\]|import\\.meta\\.env\\.${NAME}|Bun\\.env\\.${NAME}`
  + `|Deno\\.env\\.get\\(${quotedEnv}\\)`
  + `|(?:os\\.)?environ\\[${quotedEnv}\\]|(?:os\\.)?environ\\.get\\(${quotedEnv}${EMPTY_ARGUMENT}\\)|(?:os\\.)?getenv\\(${quotedEnv}${EMPTY_ARGUMENT}\\)`
  + `|ENV\\[${quotedEnv}\\]|ENV\\.fetch\\(${quotedEnv}${EMPTY_ARGUMENT}\\)`
  + `|System\\.getenv\\(${quotedEnv}\\)|os\\.Getenv\\(${quotedEnv}\\)|env\\(${quotedEnv}${EMPTY_ARGUMENT}\\)`
  + `)${EMPTY_FALLBACK}`;

/** A field path whose last name is itself a sensitive name: `user.password`, `config.apiKey`. */
const SENSITIVE_FIELD = `${NAME}(?:\\??\\.${NAME})*\\??\\.${SENSITIVE}`;
/** A call with no arguments, or one short number: `getToken()`, `secrets.token_hex(32)`. */
const BARE_CALL = `${NAME}(?:\\??\\.${NAME})*\\(\\s*[0-9]{0,3}\\s*\\)`;
/** `string`, `string | null`, `string[]`, `Optional[str]`. */
const TYPES = `(?:${TYPE}(?:\\[\\])?(?:\\s*\\|\\s*${TYPE}(?:\\[\\])?)*|Optional\\[${TYPE}\\])`;

/** One anchored expression per form: each has its own quote group. */
const whole = (form: string, tail = TAIL): RegExp => new RegExp(`^(?:${form})${tail}`);
/**
 * After a type more declarations may follow on the line
 * (`(password: string, remember: boolean) =>`), but never a string or an
 * initialiser: no quote, and no `=` other than `=>` and the comparisons. Each
 * alternative starts with a different character, so it cannot backtrack.
 */
const TYPE_TAIL = '(?:\\s*[;,)}\\]|&](?:[^"\'`=!<>]|[!<>]=*|=>|==+)*)?$';

const VARIABLE_FORMS = [whole(VARIABLE), whole(PLACEHOLDER)];
const TYPE_FORM = whole(TYPES, TYPE_TAIL);
const CODE_FORMS = [...VARIABLE_FORMS, whole(ENV_READ), whole(SENSITIVE_FIELD), whole(BARE_CALL), TYPE_FORM];
const matches = (forms: readonly RegExp[], rest: string): boolean => forms.some((form) => form.test(rest));
const IDENTIFIER = new RegExp(`^(${NAME})${TAIL}`);

/**
 * `text` is what was scanned, and `start`..`end` the span `generic_assignment`
 * matched: a sensitive name, `:` or `=`, then the value with its optional quotes.
 */
export function isCodeAssignment(text: string, start: number, end: number): boolean {
  const match = text.slice(start, Math.min(end, start + 512));
  const operatorAt = match.search(/[:=]/);
  if (operatorAt < 0) return false;
  const operator = match[operatorAt]!;
  const operatorIndex = start + operatorAt;

  // From the first character after the operator to the end of the line.
  const window = text.slice(operatorIndex + 1, operatorIndex + 1 + MAX_REST + 1);
  const newline = window.search(/[\r\n]/);
  if (newline < 0 && window.length > MAX_REST) return false;
  const rest = (newline < 0 ? window : window.slice(0, newline)).trimStart();
  if (!rest) return false;

  // The whole name on the left: `MYSQL_ROOT_PASSWORD`, not just `PASSWORD`.
  const left = /[A-Za-z0-9_$.-]*$/.exec(text.slice(Math.max(0, start - 128), start))![0];
  const key = (left + match.slice(0, operatorAt)).replace(/["'\s]/g, '');
  const spaced = /\s/.test(text[operatorIndex - 1] ?? '') && /\s/.test(text[operatorIndex + 1] ?? '');

  // `DB_PASSWORD=value` and `DB_PASSWORD: value` are how .env files, shell and
  // YAML write a literal, so only a variable or a placeholder counts there
  // (and a type after `:`, for `API_KEY: string`).
  if (/^[A-Z][A-Z0-9_]*$/.test(key) && (operator === ':' || !spaced)) {
    return matches(VARIABLE_FORMS, rest) || (operator === ':' && TYPE_FORM.test(rest));
  }
  if (matches(CODE_FORMS, rest)) return true;
  // `this.token = token`: the variable of the same name. Only as `name = name`
  // with spaces, since `password=password` and `password: password` are how
  // properties files and YAML write a literal.
  const same = IDENTIFIER.exec(rest);
  return operator === '=' && spaced && same !== null && same[1] === (key.split('.').pop() ?? '');
}

/**
 * Remove the `generic_assignment` findings in `text` that are code.
 * `rescan` runs the same scan with that detector off: an assignment finding
 * may have been standing in for a more specific one under it, which must
 * still be reported.
 */
export function withoutCodeAssignments(text: string, findings: Finding[], rescan: () => Finding[]): Finding[] {
  const dropped: Finding[] = [];
  const kept: Finding[] = [];
  for (const finding of findings) {
    const code = finding.detector === 'generic_assignment'
      && finding.start !== undefined && finding.end !== undefined
      && isCodeAssignment(text, finding.start, finding.end);
    (code ? dropped : kept).push(finding);
  }
  if (!dropped.length) return findings;

  // Findings never overlap each other, so both lists are ordered by position
  // and one pass decides, for each rescanned finding, whether it lies under a
  // dropped one and clear of every kept one.
  const byStart = (a: Finding, b: Finding): number => (a.start ?? 0) - (b.start ?? 0);
  const droppedSpans = [...dropped].sort(byStart);
  const keptSpans = kept.filter((f) => f.start !== undefined && f.end !== undefined).sort(byStart);
  let d = 0;
  let k = 0;
  const uncovered: Finding[] = [];
  for (const finding of rescan().filter((f) => f.start !== undefined && f.end !== undefined).sort(byStart)) {
    const from = finding.start!;
    const to = finding.end!;
    while (d < droppedSpans.length && droppedSpans[d]!.end! <= from) d++;
    while (k < keptSpans.length && keptSpans[k]!.end! <= from) k++;
    const underDropped = d < droppedSpans.length && droppedSpans[d]!.start! < to;
    const underKept = k < keptSpans.length && keptSpans[k]!.start! < to;
    if (underDropped && !underKept) uncovered.push(finding);
  }
  return [...kept, ...uncovered].sort(byStart);
}
