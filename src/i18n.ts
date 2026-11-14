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
  return new RegExp(`(?:${keywordAlternation()})["'\\s]*[:=]\\s*["']?([^\\s"',;]{4,})["']?`, 'giu');
}

const WS = '[ \\t\\n\\x0B\\f\\r]';

/**
 * Values in `password = …` that are code, not a secret: an environment or
 * template reference, a call, an index, a field of a well-known object or one
 * ending in a sensitive name, a type annotation, an empty value, the variable
 * of the same name, or a placeholder. Without this a scan of source code (or
 * a pre-commit hook) stops on `token = process.env.TOKEN`, and people learn
 * to ignore it. A quoted value is a literal and never matches.
 *
 * Written in the FRS-1 subset and shipped verbatim as the pack's `reject` for
 * `generic_assignment`, so the four engines agree. It is a prefix match on the
 * whole assignment, case-insensitive, and every quantifier is bounded or
 * unambiguous, so it stays linear on hostile input.
 */
export const ASSIGNMENT_REJECT: string = [
  `[^:=]*[:=]${WS}*(?:`,
  [
    // $VAR, ${VAR}, $(cmd), ${{ ... }}
    '\\$[A-Za-z_{(]',
    // {{ template }}, <placeholder>, [REDACTED] or a list, %(name)s
    '\\{\\{', '<', '\\[', '%\\(',
    // %WINDOWS_VAR%
    '%[A-Za-z_][A-Za-z0-9_]{0,63}%',
    // a call or an index: getToken(), os.getenv(, os.environ[, ENV[
    '[A-Za-z_$][A-Za-z0-9_$.]{0,127}[(\\[]',
    // a field of a well-known object: process.env.TOKEN, config.apiKey, req.body.password
    '(?:process\\.env|import\\.meta\\.env|os\\.environ|deno\\.env|bun\\.env|env|config|conf|cfg|settings|self|this|req|request|ctx|context|options|opts|args|params|props|secrets|vars|creds|credentials|system|window|globalthis)\\??\\.[A-Za-z_$]',
    // a field path ending in a sensitive name: user.password, session.authToken
    '[A-Za-z_$][A-Za-z0-9_$.?]{0,127}\\.[A-Za-z0-9_$]{0,40}(?:password|passwd|pwd|secret|token|key|credentials?)["\']?$',
    // a type, an empty value, the variable of the same name, or a placeholder
    '(?:string|str|number|int|integer|bool|boolean|any|unknown|bytes|secretstr|none|null|nil|undefined|true|false|required|optional|password|passwd|pwd|secret|token|apikey|api_key|key|your[_-][A-Za-z0-9_-]{0,64}|x{3,64}|\\*{3,64})["\']?$',
  ].join('|'),
  ')',
].join('');

/** Object keys that are sensitive by name, in any listed language. */
export const MULTILANG_KEY_SET: ReadonlySet<string> = new Set(SECRET_KEYWORDS);
