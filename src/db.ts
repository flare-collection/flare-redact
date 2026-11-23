/**
 * Redaction for database query logs: Prisma, Drizzle, TypeORM, Knex and
 * Sequelize.
 *
 * Query logging is turned on to debug a slow page and left on. ORMs log the
 * SQL and its bound parameters, and a parameter list is the hardest place to
 * see a secret: in `["ada@example.com", "hunter2"]` the password has no shape
 * any detector could recognise. Here each placeholder and literal is matched
 * to the column it is compared with or inserted into, so a value bound to
 * `password`, `token` or `api_key` is masked by name, and the rest is checked
 * by the usual detectors.
 */
import { compilePolicy, type RedactOptions } from './index.js';

type Token =
  | { kind: 'string'; text: string; start: number; end: number; quote: string }
  | { kind: 'placeholder'; text: string; start: number; end: number }
  | { kind: 'ident'; text: string; start: number; end: number }
  | { kind: 'punct'; text: string; start: number; end: number };

const WORD = /[A-Za-z_][\w$]*/y;

/** A small SQL tokenizer: enough to find literals, placeholders and the names next to them. */
function tokenize(sql: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < sql.length) {
    const c = sql[i]!;
    if (/\s/.test(c)) { i += 1; continue; }
    if (c === '-' && sql[i + 1] === '-') { const nl = sql.indexOf('\n', i); i = nl === -1 ? sql.length : nl; continue; }
    if (c === '/' && sql[i + 1] === '*') { const close = sql.indexOf('*/', i + 2); i = close === -1 ? sql.length : close + 2; continue; }
    if (c === "'") {
      let j = i + 1;
      while (j < sql.length) {
        if (sql[j] === '\\') { j += 2; continue; }
        if (sql[j] === "'") { if (sql[j + 1] === "'") { j += 2; continue; } break; }
        j += 1;
      }
      tokens.push({ kind: 'string', text: sql.slice(i + 1, j), start: i, end: Math.min(j + 1, sql.length), quote: "'" });
      i = j + 1;
      continue;
    }
    if (c === '"' || c === '`' || c === '[') {
      const closeChar = c === '[' ? ']' : c;
      const close = sql.indexOf(closeChar, i + 1);
      const end = close === -1 ? sql.length : close + 1;
      tokens.push({ kind: 'ident', text: sql.slice(i + 1, end - 1), start: i, end });
      i = end;
      continue;
    }
    const placeholder = /^(?:\$\d+|\?|:[A-Za-z_]\w*|@[A-Za-z_]\w*)/.exec(sql.slice(i, i + 64));
    if (placeholder && !(c === ':' && sql[i + 1] === ':')) {
      tokens.push({ kind: 'placeholder', text: placeholder[0], start: i, end: i + placeholder[0].length });
      i += placeholder[0].length;
      continue;
    }
    WORD.lastIndex = i;
    const word = WORD.exec(sql);
    if (word) {
      tokens.push({ kind: 'ident', text: word[0], start: i, end: i + word[0].length });
      i += word[0].length;
      continue;
    }
    const op = /^(?:<>|!=|<=|>=|::)/.exec(sql.slice(i, i + 2));
    const text = op ? op[0] : c;
    tokens.push({ kind: 'punct', text, start: i, end: i + text.length });
    i += text.length;
  }
  return tokens;
}

const COMPARE = new Set(['=', '<>', '!=', '<', '>', '<=', '>=']);
const COMPARE_WORDS = new Set(['like', 'ilike', 'is', 'in', 'not', 'similar', 'to']);

/** The column a value token at `index` is compared with, if there is one. */
function comparedColumn(tokens: Token[], index: number): string | undefined {
  let j = index - 1;
  // Inside IN (...): walk back over the list to the IN.
  let depth = 0;
  while (j >= 0) {
    const t = tokens[j]!;
    if (t.kind === 'punct' && t.text === ',' && depth === 0) { j -= 1; continue; }
    if (t.kind === 'punct' && t.text === ')') { depth += 1; j -= 1; continue; }
    if (t.kind === 'punct' && t.text === '(' && depth > 0) { depth -= 1; j -= 1; continue; }
    if (depth > 0 || t.kind === 'string' || t.kind === 'placeholder') { j -= 1; continue; }
    break;
  }
  if (j >= 0 && tokens[j]!.kind === 'punct' && tokens[j]!.text === '(') j -= 1;
  let sawOperator = false;
  while (j >= 0) {
    const t = tokens[j]!;
    if (t.kind === 'punct' && COMPARE.has(t.text)) { sawOperator = true; j -= 1; continue; }
    if (t.kind === 'ident' && COMPARE_WORDS.has(t.text.toLowerCase())) { sawOperator = true; j -= 1; continue; }
    break;
  }
  if (!sawOperator || j < 0) return undefined;
  const t = tokens[j]!;
  return t.kind === 'ident' ? t.text : undefined;
}

/**
 * For every literal and placeholder token, the column it binds to: by
 * comparison (`email = $1`, `token IN (?, ?)`) or by position in an
 * `INSERT INTO t (a, b) VALUES (..., ...)` row.
 */
function bindColumns(tokens: Token[]): Map<Token, string> {
  const names = new Map<Token, string>();
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i]!;
    if (t.kind === 'ident' && t.text.toLowerCase() === 'into') {
      // INSERT INTO table (cols...) VALUES (row), (row)
      let j = i + 1;
      while (j < tokens.length && !(tokens[j]!.kind === 'punct' && tokens[j]!.text === '(')) {
        if (tokens[j]!.kind === 'ident' && /^values$/i.test(tokens[j]!.text)) break;
        j += 1;
      }
      if (j >= tokens.length || tokens[j]!.text !== '(') continue;
      const columns: string[] = [];
      j += 1;
      while (j < tokens.length && tokens[j]!.text !== ')') {
        if (tokens[j]!.kind === 'ident') columns.push(tokens[j]!.text);
        j += 1;
      }
      j += 1;
      if (!(tokens[j]?.kind === 'ident' && /^values$/i.test(tokens[j]!.text))) continue;
      j += 1;
      while (tokens[j]?.kind === 'punct' && tokens[j]!.text === '(') {
        let position = 0;
        let depth = 0;
        j += 1;
        while (j < tokens.length) {
          const v = tokens[j]!;
          if (v.kind === 'punct' && v.text === '(') depth += 1;
          else if (v.kind === 'punct' && v.text === ')') { if (depth === 0) break; depth -= 1; }
          else if (v.kind === 'punct' && v.text === ',' && depth === 0) position += 1;
          else if ((v.kind === 'string' || v.kind === 'placeholder') && columns[position]) names.set(v, columns[position]!);
          j += 1;
        }
        j += 1;
        if (tokens[j]?.kind === 'punct' && tokens[j]!.text === ',') j += 1;
      }
      continue;
    }
    if ((t.kind === 'string' || t.kind === 'placeholder') && !names.has(t)) {
      const column = comparedColumn(tokens, i);
      if (column) names.set(t, column);
    }
  }
  return names;
}

const unquote = (column: string) => column.split('.').pop()!;

export interface RedactedQuery<P> {
  sql: string;
  params: P;
}

export interface QueryRedactor {
  /** Redact the SQL text: literals by the column they bind to, the rest by detectors. */
  sql(sql: string): string;
  /** Redact a query and its parameters together (array for `$1`/`?`, object for `:name`/`@name`). */
  query<P>(sql: string, params?: P): RedactedQuery<P>;
}

export function createQueryRedactor(opts: RedactOptions = {}): QueryRedactor {
  const policy = compilePolicy(opts);
  const byName = (name: string | undefined, value: unknown): unknown =>
    name ? policy.redact({ [name]: value })[name] : policy.redact(value);

  const analyse = (sql: string) => {
    const tokens = tokenize(sql);
    return { tokens, names: bindColumns(tokens) };
  };

  const rewrite = (sql: string, tokens: Token[], names: Map<Token, string>): string => {
    let out = '';
    let last = 0;
    for (const t of tokens) {
      if (t.kind !== 'string') continue;
      const column = names.get(t);
      const value = t.text.replace(/''/g, "'");
      const masked = String(byName(column && unquote(column), value));
      if (masked === value) continue;
      out += sql.slice(last, t.start) + `'${masked.replace(/'/g, "''")}'`;
      last = t.end;
    }
    return policy.redact(out + sql.slice(last));
  };

  return {
    sql(sql) {
      const { tokens, names } = analyse(sql);
      return rewrite(sql, tokens, names);
    },
    query<P>(sql: string, params?: P): RedactedQuery<P> {
      const { tokens, names } = analyse(sql);
      const out = rewrite(sql, tokens, names);
      if (params === undefined || params === null) return { sql: out, params: params as P };
      const placeholders = tokens.filter((t) => t.kind === 'placeholder');
      if (Array.isArray(params)) {
        const columnFor: (string | undefined)[] = [];
        let next = 0;
        for (const p of placeholders) {
          const column = names.get(p);
          if (p.text === '?') columnFor[next++] = column;
          else if (p.text.startsWith('$')) columnFor[Number(p.text.slice(1)) - 1] ??= column;
        }
        const redacted = params.map((value, i) => {
          const column = columnFor[i];
          return byName(column && unquote(column), value);
        });
        return { sql: out, params: redacted as P };
      }
      if (typeof params === 'object') {
        const record = params as Record<string, unknown>;
        const result: Record<string, unknown> = { ...(policy.redact(record) as Record<string, unknown>) };
        for (const p of placeholders) {
          const key = p.text.slice(1);
          const column = names.get(p);
          if (column && key in record) {
            const masked = byName(unquote(column), record[key]);
            if (masked !== record[key]) result[key] = masked;
          }
        }
        return { sql: out, params: result as P };
      }
      return { sql: out, params: policy.redact(params) };
    },
  };
}

/** Redact one query and its parameters. */
export function redactQuery<P>(sql: string, params?: P, opts: RedactOptions = {}): RedactedQuery<P> {
  return createQueryRedactor(opts).query(sql, params);
}

type Log = (...args: unknown[]) => void;

/** Prisma: `prisma.$on('query', prismaQueryLogger(log))`, with `log: [{ emit: 'event', level: 'query' }]`. */
export function prismaQueryLogger(log: Log = console.log, opts: RedactOptions = {}) {
  const redactor = createQueryRedactor(opts);
  return (event: { query: string; params?: string; duration?: number; target?: string; [key: string]: unknown }) => {
    let params: unknown = event.params;
    try {
      params = typeof event.params === 'string' ? JSON.parse(event.params) : event.params;
    } catch {
      // Prisma sends JSON; anything else is redacted as text below.
    }
    const out = redactor.query(event.query, params);
    log({
      ...event,
      query: out.sql,
      params: typeof event.params === 'string' ? JSON.stringify(out.params) : out.params,
    });
  };
}

/** Drizzle: `drizzle(client, { logger: drizzleLogger() })`. Writes like Drizzle's own logger. */
export function drizzleLogger(opts: RedactOptions = {}, log: Log = console.log) {
  const redactor = createQueryRedactor(opts);
  return {
    logQuery(query: string, params: unknown[]): void {
      const out = redactor.query(query, params);
      log(`Query: ${out.sql}${out.params.length ? ` -- params: ${JSON.stringify(out.params)}` : ''}`);
    },
  };
}

interface TypeOrmLoggerLike {
  logQuery(query: string, parameters?: unknown[], queryRunner?: unknown): unknown;
  logQueryError(error: string | Error, query: string, parameters?: unknown[], queryRunner?: unknown): unknown;
  logQuerySlow(time: number, query: string, parameters?: unknown[], queryRunner?: unknown): unknown;
  logSchemaBuild(message: string, queryRunner?: unknown): unknown;
  logMigration(message: string, queryRunner?: unknown): unknown;
  log(level: 'log' | 'info' | 'warn', message: unknown, queryRunner?: unknown): unknown;
}

/**
 * TypeORM: `new DataSource({ logger: typeormLogger(new SimpleConsoleLogger()) })`.
 * Wraps any TypeORM logger; without one it writes to the console.
 */
export function typeormLogger(inner?: Partial<TypeOrmLoggerLike>, opts: RedactOptions = {}): TypeOrmLoggerLike {
  const redactor = createQueryRedactor(opts);
  const policy = compilePolicy(opts);
  const q = (query: string, parameters?: unknown[]) => redactor.query(query, parameters);
  const line = (query: string, parameters?: unknown[]) =>
    `${query}${parameters?.length ? ` -- PARAMETERS: ${JSON.stringify(parameters)}` : ''}`;
  return {
    logQuery(query, parameters, runner) {
      const out = q(query, parameters);
      return inner?.logQuery ? inner.logQuery(out.sql, out.params, runner) : console.log(`query: ${line(out.sql, out.params)}`);
    },
    logQueryError(error, query, parameters, runner) {
      const out = q(query, parameters);
      const safeError = policy.redact(error);
      return inner?.logQueryError
        ? inner.logQueryError(safeError, out.sql, out.params, runner)
        : console.error(`query failed: ${line(out.sql, out.params)}\nerror: ${String(safeError)}`);
    },
    logQuerySlow(time, query, parameters, runner) {
      const out = q(query, parameters);
      return inner?.logQuerySlow
        ? inner.logQuerySlow(time, out.sql, out.params, runner)
        : console.warn(`query is slow: ${line(out.sql, out.params)}\nexecution time: ${time}`);
    },
    logSchemaBuild(message, runner) {
      const safe = redactor.sql(message);
      return inner?.logSchemaBuild ? inner.logSchemaBuild(safe, runner) : console.log(safe);
    },
    logMigration(message, runner) {
      const safe = redactor.sql(message);
      return inner?.logMigration ? inner.logMigration(safe, runner) : console.log(safe);
    },
    log(level, message, runner) {
      const safe = policy.redact(message);
      return inner?.log ? inner.log(level, safe, runner) : console[level](safe);
    },
  };
}

/** Knex: `knex.on('query', knexQueryLogger(log))`. Logs `{ sql, bindings, method }`. */
export function knexQueryLogger(log: Log = console.log, opts: RedactOptions = {}) {
  const redactor = createQueryRedactor(opts);
  return (data: { sql: string; bindings?: unknown[]; method?: string; [key: string]: unknown }) => {
    const out = redactor.query(data.sql, data.bindings);
    log({ method: data.method, sql: out.sql, bindings: out.params });
  };
}

/**
 * Split Sequelize's `logQueryParameters` line, `<sql>; <params>`, where the
 * params are a JSON object (`{"$1": ...}`) or a comma list of JSON values.
 */
function splitSequelize(line: string): { sql: string; params: unknown; list: boolean } | undefined {
  for (let at = line.indexOf('; '); at !== -1; at = line.indexOf('; ', at + 1)) {
    const rest = line.slice(at + 2).trim();
    if (!rest) continue;
    try {
      if (rest.startsWith('{')) return { sql: line.slice(0, at + 1), params: JSON.parse(rest), list: false };
      return { sql: line.slice(0, at + 1), params: JSON.parse(`[${rest}]`), list: true };
    } catch {
      // Not the boundary: a "; " inside the SQL.
    }
  }
  return undefined;
}

/**
 * Sequelize: `new Sequelize(url, { logging: sequelizeLogging(log) })`. Works
 * with `logQueryParameters: true` too: the bound values Sequelize appends are
 * matched to their placeholders' columns.
 */
export function sequelizeLogging(log: Log = console.log, opts: RedactOptions = {}) {
  const redactor = createQueryRedactor(opts);
  return (line: string, timing?: unknown) => {
    const extra = typeof timing === 'number' ? [timing] : [];
    const split = splitSequelize(line);
    if (!split) {
      log(redactor.sql(line), ...extra);
      return;
    }
    let params = split.params;
    // {"$1": a, "$2": b} binds by position: redact it as the list it is.
    const positional = !split.list && typeof params === 'object' && params !== null && !Array.isArray(params)
      && Object.keys(params).every((key) => /^\$\d+$/.test(key));
    if (positional) {
      const list: unknown[] = [];
      for (const [key, value] of Object.entries(params as Record<string, unknown>)) list[Number(key.slice(1)) - 1] = value;
      params = list;
    }
    const out = redactor.query(split.sql, params);
    const shown: unknown = positional
      ? Object.fromEntries((out.params as unknown[]).map((value, i) => ['$' + String(i + 1), value]))
      : out.params;
    const text = split.list
      ? (shown as unknown[]).map((value) => JSON.stringify(value)).join(', ')
      : JSON.stringify(shown);
    log(`${out.sql} ${text}`, ...extra);
  };
}
