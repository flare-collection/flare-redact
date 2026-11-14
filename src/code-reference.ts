/**
 * Is the value of a `password = …` assignment code rather than a secret?
 *
 * `redact()` masks every such assignment, and must: hiding
 * `token = process.env.TOKEN` in a log costs nothing, while missing
 * `password=$ecret123` is a leak. A scan is different. It reports to a person
 * or stops a commit, and one that stops on `token = process.env.TOKEN` or
 * `password: string` is one people switch off. So this check is used only by
 * the CLI's scans, never by redaction, and it prefers to keep reporting
 * whenever a value could be a literal.
 */

import type { Detector } from './detectors.js';

/** Longer values are never treated as code; it also bounds the work below. */
const MAX_VALUE = 256;

const SENSITIVE_NAME = '(?:password|passwd|pwd|pass|secret|token|api_?key|key|credentials?)';

/** `${VAR}`, `$(cmd)`, `{{ template }}`, `%(name)s`: these start a template, quoted or not. */
const TEMPLATE = /^(?:\$\{|\$\(|\{\{|%\()/;

/** A whole value that is one variable or placeholder, quoted or not. */
const VARIABLE = new RegExp(
  '^(?:'
  // $DB_PASSWORD, $TOKEN: shell variables are upper case by convention, so
  // `$ecret123` and `$argon2id$…` stay reported.
  + '\\$[A-Z_][A-Z0-9_]*'
  // $db_password, $password
  + '|\\$[a-z][a-z0-9]*(?:_[a-z0-9]+)+'
  + `|\\$${SENSITIVE_NAME}`
  // %DB_PASSWORD%
  + '|%[A-Za-z_][A-Za-z0-9_]*%'
  // <your-password>, [REDACTED]
  + '|<[^<>]{1,64}>|\\[[^\\[\\]]{1,64}\\]'
  // YOUR_API_KEY, your-token-here, xxxx, ****, ....
  + '|(?:YOUR|Your|your)[_-][A-Za-z0-9_-]+|[xX]{3,}|\\*{3,}|\\.{3,}'
  + ')$',
);

/** Unquoted only: a bare word here is a type or an empty value, not a string. */
const TYPE_OR_EMPTY = /^(?:string|str|String|number|int|integer|float|bool|boolean|any|unknown|bytes|SecretStr|Optional|None|null|nil|NULL|undefined|true|false|True|False|required|optional)$/;

/** Unquoted only: `getToken()`, `os.getenv(`, `os.environ[`, `ENV[`. */
const CALL_OR_INDEX = /^[A-Za-z_$][A-Za-z0-9_$.]*[([]/;

/** Unquoted only: a field of an object that holds configuration or input. */
const KNOWN_ROOT = /^(?:process\.env|import\.meta\.env|os\.environ|Deno\.env|Bun\.env|env|ENV|config|conf|cfg|settings|self|this|req|request|ctx|context|options|opts|args|params|props|secrets|vars|creds|credentials|System|window|globalThis)\??\.[A-Za-z_$]/;

/** Unquoted only: any field path that ends in a sensitive name (`user.password`). */
const SENSITIVE_FIELD = new RegExp(`^[A-Za-z_$][A-Za-z0-9_$]*(?:\\??\\.[A-Za-z_$][A-Za-z0-9_$]*)*\\??\\.[A-Za-z0-9_$]*${SENSITIVE_NAME}$`, 'i');

const identifier = (text: string): string => text.toLowerCase().replace(/[^\p{L}\p{N}]/gu, '');

/**
 * `assignment` is the text `generic_assignment` matched: a sensitive name, `:`
 * or `=`, then the value with its optional quotes.
 */
export function isCodeReference(assignment: string): boolean {
  const operator = assignment.search(/[:=]/);
  if (operator < 0) return false;
  let value = assignment.slice(operator + 1).trim();
  const quoted = /^["']/.test(value);
  value = value.replace(/^["']/, '').replace(/["']$/, '');
  if (!value || value.length > MAX_VALUE) return false;

  if (TEMPLATE.test(value) || VARIABLE.test(value)) return true;
  // Anything else in quotes is a string literal: report it.
  if (quoted) return false;

  if (TYPE_OR_EMPTY.test(value) || CALL_OR_INDEX.test(value) || KNOWN_ROOT.test(value) || SENSITIVE_FIELD.test(value)) return true;
  // `this.token = token`, `password = password`: the variable of the same name.
  const key = identifier(assignment.slice(0, operator));
  return key.length > 0 && identifier(value) === key && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(value);
}

/**
 * The detectors with `generic_assignment` taught to skip code. For scanning
 * source files and staged changes; redaction keeps the plain detectors.
 */
export function codeAwareDetectors(detectors: readonly Detector[]): Detector[] {
  return detectors.map((detector) => {
    if (detector.id !== 'generic_assignment') return detector;
    const { validate } = detector;
    return {
      ...detector,
      validate: (match: string) => (validate ? validate(match) : true) && !isCodeReference(match),
      // A detector with `validate` would otherwise start at 0.99; keep its own score.
      confidence: detector.confidence ?? 0.92,
    };
  });
}
