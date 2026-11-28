import { expandDottedI, normalizeKeyName } from './fold.js';

/**
 * Words that name a secret, across languages. Used to catch `password=…` style
 * assignments and sensitive object keys in non-English codebases. Every entry is
 * identifier-shaped (no spaces) so it works as both a key name and an assignment
 * keyword. Structured secrets (API keys, JWTs, cards) are language-independent
 * and handled by their own detectors — this list is only for the word-based ones.
 */
export const SECRET_KEYWORDS: string[] = Array.from(
  new Set(
    [
      // 1. English
      'password', 'passwd', 'pwd', 'secret', 'token', 'apikey', 'api_key', 'api-key',
      'access_key', 'access-key', 'accesskey', 'secret_key', 'client_secret',
      'private_key', 'privatekey', 'credential', 'credentials', 'auth_token', 'passphrase',
      // 2. Chinese
      '密码', '密碼', '秘密', '令牌', '密钥', '私钥', '口令',
      // 3. Hindi
      'पासवर्ड', 'गुप्त', 'कुंजी', 'टोकन',
      // 4. Spanish
      'contraseña', 'contrasena', 'clave', 'secreto', 'credencial',
      // 5. Arabic
      'كلمةالمرور', 'كلمةالسر', 'سر', 'رمز', 'مفتاح', 'سري',
      // 6. French
      'motdepasse', 'mot_de_passe', 'motdepass', 'clé', 'clef', 'clésecrète', 'secret',
      // 7. Portuguese
      'senha', 'segredo', 'chavesecreta', 'chave',
      // 8. Russian
      'пароль', 'секрет', 'токен', 'ключ', 'секретныйключ',
      // 9. Japanese
      'パスワード', '秘密', 'トークン', '暗証番号', '合言葉',
      // 10. German
      'passwort', 'kennwort', 'geheimnis', 'geheim', 'schlüssel', 'schluessel', 'zugangsschlüssel',
      // 11. Korean
      '비밀번호', '암호', '비밀', '토큰', '비밀키',
      // 12. Turkish
      'şifre', 'sifre', 'parola', 'gizli', 'anahtar', 'gizlianahtar',
      // 13. Italian
      'segreto', 'chiave', 'parolachiave', 'parola_chiave', 'credenziale',
      // 14. Persian
      'رمز', 'رمزعبور', 'گذرواژه', 'کلمهعبور', 'کلید', 'محرمانه',
      // 15. Polish
      'hasło', 'haslo', 'tajne', 'klucz', 'poufne',
      // 16. Ukrainian
      'пароль', 'секрет', 'ключ', 'таємний',
      // 17. Dutch
      'wachtwoord', 'geheim', 'sleutel',
      // 18. Vietnamese
      'matkhau', 'mat_khau', 'bimat', 'khoa',
      // 19. Indonesian
      'katasandi', 'kata_sandi', 'sandi', 'rahasia', 'kunci',
      // 20. Thai
      'รหัสผ่าน', 'ความลับ',
      // 21. Greek
      'κωδικός', 'μυστικό', 'κλειδί',
      // 22. Hebrew
      'סיסמה', 'סוד', 'מפתח',
      // 23. Azerbaijani
      'şifrə', 'parol', 'gizli', 'açar', 'məxfi',
      // 24. Romanian
      'parolă', 'parola', 'cheie',
    ].map((w) => w.toLowerCase()),
  ),
);

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Alternation of all keywords, longest first so `api_key` wins over any prefix. */
function keywordAlternation(): string {
  return [...SECRET_KEYWORDS]
    .sort((a, b) => b.length - a.length)
    .map(escapeRe)
    .join('|');
}

/** `password = value` / `密码: value` in any listed language. Unicode-aware. */
export function assignmentPattern(): RegExp {
  const source = `(?:${keywordAlternation()})["'\\s]*[:=]\\s*["']?([^\\s"',;]{4,})["']?`;
  return new RegExp(expandDottedI(source), 'giu');
}

/** Object keys that are sensitive by name, in any listed language. */
export const MULTILANG_KEY_SET: ReadonlySet<string> = new Set(SECRET_KEYWORDS);

/** The keywords in the form normalizeKeyName produces, so `ŞİFRE` and `ΚΩΔΙΚΌΣ` hit. */
const NORMALIZED_KEYWORDS: ReadonlySet<string> = new Set(SECRET_KEYWORDS.map(normalizeKeyName));

/**
 * English names a field is sensitive under, compared against the normalised key
 * (SPEC §9). Two shapes match:
 *
 * - the key ends with a credential word, glued or not: `password`, `secret`,
 *   `token`, `credentials`, `cookie`, `passphrase`, `mnemonic`, or a two-word
 *   name such as `api_key`, `private_key`, `session_id` or `card_number`, so
 *   `db_password`, `DbPassword`, `accessToken`, `apiSecret` and
 *   `aws_secret_access_key` all hit;
 * - the key is, or ends in `_`, `-`, `.` or a space followed by, a short word
 *   that is only safe as a whole word: `pass`, `auth`, `authorization`, `bearer`,
 *   `csrf`, `xsrf`, `jwt`, `pin`, `otp`, `totp`, `hotp`, `cvv`, `cvv2`, `cvc`,
 *   `ssn`, `dsn`, `creds`, `pwd`.
 *
 * Look-alikes such as `author`, `monkey`, `keyboard`, `publicKey`, `tokenizer`,
 * `max_tokens` and `secret_name` do not end in one of these and stay readable.
 * Kept here rather than next to the detectors so key matching has one home.
 */
export const SENSITIVE_KEY_RE = new RegExp(
  '^(?:' +
    '[\\s\\S]*(?:pass(?:word|wd|phrase)|secret|token|credentials?|cookies?|mnemonic' +
    '|(?:api|access|secret|private|encryption|signing|master|client)[_. -]?keys?' +
    '|session[_. -]?id|credit[_. -]?card|card[_. -]?number|connection[_. -]?string' +
    '|(?:seed|recovery)[_. -]?phrase)' +
    '|(?:[\\s\\S]*[_. -])?(?:pass|auth|authorization|bearer|csrf|xsrf|jwt|pin|otp|totp|hotp|cvv2?|cvc|ssn|dsn|creds|pwd)' +
    ')$',
);

/**
 * Keys that end in `token` but name a pagination cursor or a count, not a
 * credential: `next_token`, `nextPageToken`, `continuation_token`, `max_token`.
 * A key that matches this is not sensitive by name unless it is a keyword.
 */
export const NON_SECRET_TOKEN_KEY_RE =
  /^[\s\S]*(?:next|page|continuation|pagination|cursor|sync|resume|max)[_. -]?token$/;

/**
 * Whether a key is sensitive by name (SPEC §9): its normalised form matches the
 * English rule above and is not a pagination token, or is one of the
 * multilingual keywords.
 */
export function isSensitiveKeyName(key: string): boolean {
  const name = normalizeKeyName(key);
  return (
    (SENSITIVE_KEY_RE.test(name) && !NON_SECRET_TOKEN_KEY_RE.test(name)) ||
    NORMALIZED_KEYWORDS.has(name)
  );
}
