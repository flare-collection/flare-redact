/**
 * Redaction for recorded HTTP traffic: HAR files (browser devtools, Playwright
 * `recordHar`, Polly.js) and anything shaped like a request or response that a
 * test suite writes to disk and commits.
 *
 * A recording leaks in places a log line does not: credential headers whose
 * names carry an `x-` prefix, cookies whose values are opaque session ids, and
 * bodies stored as JSON text, form text or base64. Each is handled here.
 */
import { compilePolicy, type RedactOptions } from './index.js';
import { Buffer } from 'node:buffer';
import { SENSITIVE_KEY_RE } from './detectors.js';

const MASK = '***';

/** Header and parameter names that always carry a credential, after dropping `x-`. */
const CREDENTIAL_NAMES = new Set([
  'access_token',
  'api_token',
  'apikey',
  'auth_token',
  'csrf_token',
  'id_token',
  'private_token',
  'proxy_authorization',
  'set_cookie',
  'vault_token',
  'xsrf_token',
  'amz_security_token',
  'amz_credential',
  'amz_signature',
  'goog_api_key',
  'signature',
]);

/**
 * Whether a header, query parameter or form field name carries a credential.
 * `X-Api-Key`, `Proxy-Authorization`, `Set-Cookie` and `access_token` all do;
 * the plain sensitive-key list matches whole names only and would miss them.
 */
export function isCredentialName(name: string): boolean {
  const normal = name.trim().toLowerCase().replace(/^x-/, '').replace(/-/g, '_');
  return SENSITIVE_KEY_RE.test(normal) || CREDENTIAL_NAMES.has(normal);
}

interface NameValue {
  name: string;
  value: string;
  [key: string]: unknown;
}

interface HarContent {
  text?: string;
  encoding?: string;
  mimeType?: string;
  size?: number;
  [key: string]: unknown;
}

interface HarMessage {
  url?: string;
  headers?: NameValue[];
  cookies?: NameValue[];
  queryString?: NameValue[];
  postData?: { text?: string; mimeType?: string; params?: NameValue[]; [key: string]: unknown };
  content?: HarContent;
  [key: string]: unknown;
}

export interface HarEntry {
  request?: HarMessage;
  response?: HarMessage;
  [key: string]: unknown;
}

export interface Har {
  log: { entries?: HarEntry[]; [key: string]: unknown };
  [key: string]: unknown;
}

const TEXTUAL = /^(?:text\/|application\/(?:[\w.+-]*\+)?(?:json|xml|javascript|x-www-form-urlencoded|graphql))/i;

/**
 * A redactor for recordings. Bodies are redacted as JSON when they parse as
 * JSON (so field names count), as form fields when they are form-encoded, and
 * as text otherwise; a body that needs no change keeps its exact bytes.
 */
export function createRecordingRedactor(opts: RedactOptions = {}) {
  const policy = compilePolicy(opts);

  const value = (name: string, raw: string): string =>
    isCredentialName(name) ? MASK : policy.redact({ [name]: raw })[name] as string;

  const pairs = (list: NameValue[] | undefined, always = false): NameValue[] | undefined =>
    list?.map((pair) => ({ ...pair, value: always ? MASK : value(pair.name, String(pair.value ?? '')) }));

  const decode = (part: string): string => {
    try {
      return decodeURIComponent(part.replace(/\+/g, ' '));
    } catch {
      return part;
    }
  };

  /** Form-encoded text, one field at a time; untouched fields keep their bytes. */
  const form = (text: string): string => {
    let changed = false;
    const parts = text.split('&').map((part) => {
      if (!part) return part;
      const eq = part.indexOf('=');
      const rawName = eq === -1 ? part : part.slice(0, eq);
      const raw = eq === -1 ? '' : decode(part.slice(eq + 1));
      const next = value(decode(rawName), raw);
      if (next === raw) return part;
      changed = true;
      return `${rawName}=${encodeURIComponent(next).replace(/%20/g, '+')}`;
    });
    return changed ? parts.join('&') : text;
  };

  /** Redact a body held as text, given its media type when known. */
  const body = (text: string, mimeType = ''): string => {
    if (/x-www-form-urlencoded/i.test(mimeType)) return form(text);
    const trimmed = text.trimStart();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try {
        const parsed: unknown = JSON.parse(text);
        if (policy.isClean(parsed)) return text;
        return JSON.stringify(policy.redact(parsed));
      } catch {
        // Not JSON after all: fall through to text.
      }
    }
    return policy.redact(text);
  };

  /**
   * The query string is redacted one parameter at a time: run over the whole
   * URL, an assignment detector would read `token=x&page=2` as one value and
   * swallow the parameters after it.
   */
  const url = (raw: string): string => {
    const hashAt = raw.indexOf('#');
    const beforeHash = hashAt === -1 ? raw : raw.slice(0, hashAt);
    const hash = hashAt === -1 ? '' : policy.redact(raw.slice(hashAt));
    const queryAt = beforeHash.indexOf('?');
    if (queryAt === -1) return policy.redact(beforeHash) + hash;
    const base = policy.redact(beforeHash.slice(0, queryAt));
    return `${base}?${form(beforeHash.slice(queryAt + 1))}${hash}`;
  };

  const content = (input: HarContent | undefined): HarContent | undefined => {
    if (!input || typeof input.text !== 'string') return input;
    const mimeType = input.mimeType ?? '';
    if (input.encoding === 'base64') {
      if (!TEXTUAL.test(mimeType)) return input;
      const decoded = Buffer.from(input.text, 'base64').toString('utf8');
      const next = body(decoded, mimeType);
      if (next === decoded) return input;
      return { ...input, text: Buffer.from(next, 'utf8').toString('base64'), size: Buffer.byteLength(next) };
    }
    const next = body(input.text, mimeType);
    return next === input.text ? input : { ...input, text: next, size: Buffer.byteLength(next) };
  };

  const fixLength = (headers: NameValue[] | undefined, before: HarContent | undefined, after: HarContent | undefined) => {
    if (!headers || before === after || typeof after?.size !== 'number') return headers;
    return headers.map((header) =>
      header.name.toLowerCase() === 'content-length' ? { ...header, value: String(after.size) } : header);
  };

  const message = (input: HarMessage | undefined): HarMessage | undefined => {
    if (!input) return input;
    const out: HarMessage = { ...input };
    if (typeof input.url === 'string') out.url = url(input.url);
    if (input.headers) out.headers = pairs(input.headers);
    if (input.cookies) out.cookies = pairs(input.cookies, true);
    if (input.queryString) out.queryString = pairs(input.queryString);
    if (input.postData) {
      const postData = { ...input.postData };
      if (typeof postData.text === 'string') postData.text = body(postData.text, postData.mimeType);
      if (postData.params) postData.params = pairs(postData.params);
      out.postData = postData;
    }
    if (input.content) {
      out.content = content(input.content);
      out.headers = fixLength(out.headers, input.content, out.content);
    }
    if (typeof input.redirectURL === 'string' && input.redirectURL) out.redirectURL = url(input.redirectURL);
    return out;
  };

  const entry = (input: HarEntry): HarEntry => ({
    ...input,
    request: message(input.request),
    response: message(input.response),
  });

  return {
    /** A redacted copy of one HAR entry (or Polly.js recording). */
    entry,
    /** A redacted copy of a whole HAR document. */
    har: (input: Har): Har => ({ ...input, log: { ...input.log, entries: input.log.entries?.map(entry) } }),
    /** Redact a body held as text; JSON and form bodies keep their field names. */
    body,
    /** Redact a URL; credential query parameters are masked by name. */
    url,
    /** Redact a header value, masking it whole when the name carries a credential. */
    header: value,
  };
}

/** A redacted copy of a HAR document. */
export function redactHar(har: Har, opts: RedactOptions = {}): Har {
  return createRecordingRedactor(opts).har(har);
}

/** A redacted copy of one HAR entry. */
export function redactHarEntry(entry: HarEntry, opts: RedactOptions = {}): HarEntry {
  return createRecordingRedactor(opts).entry(entry);
}

/**
 * A Polly.js `beforePersist` handler: `server.any().on('beforePersist', pollyBeforePersist())`.
 * Polly persists the recording object it passes in, so it is updated in place.
 */
export function pollyBeforePersist(opts: RedactOptions = {}) {
  const redactor = createRecordingRedactor(opts);
  return (_request: unknown, recording: HarEntry): void => {
    Object.assign(recording, redactor.entry(recording));
  };
}
