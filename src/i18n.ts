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

/** Object keys that are sensitive by name, in any listed language. */
export const MULTILANG_KEY_SET: ReadonlySet<string> = new Set(SECRET_KEYWORDS);
