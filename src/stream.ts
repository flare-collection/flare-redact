import { Transform } from 'node:stream';
import { redact, RedactionLimitError, type RedactOptions } from './index.js';

export interface RedactStreamOptions extends RedactOptions {
  /** Maximum buffered multiline record size before the stream fails closed. */
  maxRecordLength?: number;
}

const PEM_BEGIN = /-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----/;
// Any footer closes the record, matching the private_key detector: a key whose
// END line carries the wrong label is still a key.
const PEM_END = /-----END [A-Z0-9 ]{1,60}-----/;

export function redactStream(opts: RedactStreamOptions = {}): Transform {
  let carry = '';
  let multiline = '';
  const maxRecordLength = opts.maxRecordLength ?? opts.limits?.maxInputLength ?? 16 * 1024 * 1024;

  const processLine = (line: string): string => {
    if (multiline) {
      multiline += line;
      if (multiline.length > maxRecordLength) {
        throw new RedactionLimitError(`Multiline stream record exceeds the configured limit of ${maxRecordLength}.`);
      }
      if (!PEM_END.test(line)) return '';
      const out = redact(multiline, opts);
      multiline = '';
      return out;
    }
    const begin = line.search(PEM_BEGIN);
    if (begin !== -1 && !PEM_END.test(line.slice(begin))) {
      multiline = line;
      return '';
    }
    return redact(line, opts);
  };

  const processCompleteLines = (text: string): string => {
    const data = carry + text;
    const lastNewline = data.lastIndexOf('\n');
    if (lastNewline === -1) {
      carry = data;
      return '';
    }
    carry = data.slice(lastNewline + 1);
    const complete = data.slice(0, lastNewline + 1);
    let out = '';
    let start = 0;
    for (let i = 0; i < complete.length; i++) {
      if (complete.charCodeAt(i) !== 10) continue;
      out += processLine(complete.slice(start, i + 1));
      start = i + 1;
    }
    return out;
  };

  return new Transform({
    transform(chunk, _enc, cb) {
      try {
        cb(null, processCompleteLines(chunk.toString()));
      } catch (error) {
        cb(error as Error);
      }
    },
    flush(cb) {
      try {
        const pending = multiline + carry;
        if (!pending) {
          cb(null, '');
          return;
        }
        if (pending.length > maxRecordLength) {
          throw new RedactionLimitError(`Multiline stream record exceeds the configured limit of ${maxRecordLength}.`);
        }
        const begin = pending.search(PEM_BEGIN);
        const hasCompletePem = begin !== -1 && PEM_END.test(pending.slice(begin));
        if (begin === -1 || hasCompletePem) {
          cb(null, redact(pending, opts));
          return;
        }
        const prefix = begin > 0 ? redact(pending.slice(0, begin), opts) : '';
        cb(null, `${prefix}[REDACTED PRIVATE KEY]`);
      } catch (error) {
        cb(error as Error);
      }
    },
  });
}
