/**
 * Masking for session replay: rrweb, and the tools built on it (Sentry Session
 * Replay, PostHog, Highlight, OpenReplay-style recorders).
 *
 * A replay tool either masks every character, which makes replays hard to use,
 * or masks only what a CSS selector names, which misses the email typed into a
 * search box and the API key pasted into a support form. These functions mask
 * what is sensitive and keep the rest readable. Each masked character becomes
 * `*` by default, as rrweb's own masking does, so the replayed layout does not
 * shift.
 *
 * Browser-safe: no Node built-ins.
 */
import { compilePolicy, type RedactOptions } from './index.js';

export interface ReplayMaskOptions extends RedactOptions {
  /**
   * Replace each masked character with `*`, keeping spaces, so text keeps its
   * length and the replayed layout does not shift. Default `true`; set `false`
   * to use the usual masks (`a***@***`) or the chosen `mode`.
   */
  preserveLength?: boolean;
  /** Distinct texts remembered between calls, since a page repeats them. Default 2000. */
  cacheSize?: number;
}

/** The parts of a DOM element the masker reads; any real element has them. */
interface ElementLike {
  tagName?: string;
  type?: string;
  id?: string;
  getAttribute?(name: string): string | null;
}

/** `autocomplete` tokens of fields that hold a credential or a card in full. */
const CREDENTIAL_AUTOCOMPLETE =
  /(?:^|\s)(?:current-password|new-password|one-time-code|cc-number|cc-csc|cc-exp|cc-exp-month|cc-exp-year)(?:\s|$)/i;

const FORM_FIELD = /^(?:input|textarea|select)$/i;

const hide = (value: string): string => value.replace(/\S/g, '*');

/**
 * A mask function `(text, element?) => string` for rrweb's `maskTextFn` and
 * `maskInputFn`, or Sentry's `maskFn`. Text that holds nothing sensitive is
 * returned as it is.
 *
 * A form field is masked whole when it is a password field, when its
 * `autocomplete` names a password, one-time code or card, or when its `name`
 * or `id` is a credential name such as `password` or `api_key`; anything else
 * typed into it is masked where a detector finds something.
 *
 * Without detector options the `pii` group is on, so phone numbers count too.
 */
export function replayMaskFn(opts: ReplayMaskOptions = {}): (text: string, element?: unknown) => string {
  const { preserveLength = true, cacheSize = 2000, ...rest } = opts;
  const chooses = rest.only !== undefined || rest.enable !== undefined || rest.preset !== undefined;
  const options: RedactOptions = { ...(chooses ? {} : { enable: ['pii'] }), ...rest };
  if (preserveLength && options.mask === undefined && (options.mode ?? 'mask') === 'mask') {
    options.mask = ({ value }) => hide(value);
  }
  const policy = compilePolicy(options);
  const whole = (value: string): string => (preserveLength ? hide(value) : '***');

  const cache = new Map<string, string>();
  const text = (value: string): string => {
    const known = cache.get(value);
    if (known !== undefined) return known;
    const out = policy.redact(value);
    if (cache.size >= cacheSize) cache.delete(cache.keys().next().value as string);
    cache.set(value, out);
    return out;
  };

  return (value, element) => {
    if (typeof value !== 'string' || value === '') return value;
    const el = element as ElementLike | undefined;
    if (!el || typeof el.tagName !== 'string' || !FORM_FIELD.test(el.tagName)) return text(value);
    const attr = (name: string) => el.getAttribute?.(name) ?? '';
    if ((el.type ?? attr('type')).toLowerCase() === 'password') return whole(value);
    if (CREDENTIAL_AUTOCOMPLETE.test(attr('autocomplete'))) return whole(value);
    const field = attr('name') || el.id || '';
    if (field) return policy.redact({ [field]: value })[field] as string;
    return text(value);
  };
}

/**
 * Options to spread into rrweb's `record()` (or PostHog's `session_recording`):
 * every text node and every input goes through {@link replayMaskFn}, which
 * keeps clean text readable.
 *
 * ```js
 * rrweb.record({ emit, ...rrwebMasking() });
 * posthog.init(key, { session_recording: rrwebMasking() });
 * ```
 */
export function rrwebMasking(opts: ReplayMaskOptions = {}) {
  const mask = replayMaskFn(opts);
  return {
    maskAllInputs: true,
    maskTextSelector: '*',
    maskTextFn: (text: string, element?: unknown) => mask(text, element),
    maskInputFn: (text: string, element?: unknown) => mask(text, element),
  };
}
