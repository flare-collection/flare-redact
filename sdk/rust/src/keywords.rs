//! Field names that are sensitive by convention, in 24 major languages.
//!
//! Structured secrets — API keys, JWTs, card numbers — carry their own shape and
//! are found by pattern. Word-based secrets are not: `password`, `密码`, `şifrə`
//! and `كلمةالمرور` are only recognisable as *names*. This list is what lets
//! `{"parola": "hunter2"}` be redacted in an Italian codebase.

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;

use crate::fold::normalize_key_name;

const RAW: &[&str] = &[
    // 1. English
    "password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "api-key",
    "access_key", "access-key", "accesskey", "secret_key", "client_secret",
    "private_key", "privatekey", "credential", "credentials", "auth_token", "passphrase",
    // 2. Chinese
    "密码", "密碼", "秘密", "令牌", "密钥", "私钥", "口令",
    // 3. Hindi
    "पासवर्ड", "गुप्त", "कुंजी", "टोकन",
    // 4. Spanish
    "contraseña", "contrasena", "clave", "secreto", "credencial",
    // 5. Arabic
    "كلمةالمرور", "كلمةالسر", "سر", "رمز", "مفتاح", "سري",
    // 6. French
    "motdepasse", "mot_de_passe", "motdepass", "clé", "clef", "clésecrète",
    // 7. Portuguese
    "senha", "segredo", "chavesecreta", "chave",
    // 8. Russian
    "пароль", "секрет", "токен", "ключ", "секретныйключ",
    // 9. Japanese
    "パスワード", "トークン", "暗証番号", "合言葉",
    // 10. German
    "passwort", "kennwort", "geheimnis", "geheim", "schlüssel", "schluessel", "zugangsschlüssel",
    // 11. Korean
    "비밀번호", "암호", "비밀", "토큰", "비밀키",
    // 12. Turkish
    "şifre", "sifre", "parola", "gizli", "anahtar", "gizlianahtar",
    // 13. Italian
    "segreto", "chiave", "parolachiave", "parola_chiave", "credenziale",
    // 14. Persian
    "رمزعبور", "گذرواژه", "کلمهعبور", "کلید", "محرمانه",
    // 15. Polish
    "hasło", "haslo", "tajne", "klucz", "poufne",
    // 16. Ukrainian
    "таємний",
    // 17. Dutch
    "wachtwoord", "sleutel",
    // 18. Vietnamese
    "matkhau", "mat_khau", "bimat", "khoa",
    // 19. Indonesian
    "katasandi", "kata_sandi", "sandi", "rahasia", "kunci",
    // 20. Thai
    "รหัสผ่าน", "ความลับ",
    // 21. Greek
    "κωδικός", "μυστικό", "κλειδί",
    // 22. Hebrew
    "סיסמה", "סוד", "מפתח",
    // 23. Azerbaijani
    "şifrə", "parol", "açar", "məxfi",
    // 24. Romanian
    "parolă", "cheie",
];

fn keyword_set() -> &'static HashSet<String> {
    static SET: OnceLock<HashSet<String>> = OnceLock::new();
    SET.get_or_init(|| RAW.iter().map(|word| word.to_lowercase()).collect())
}

/// The vocabulary in the form key names are compared in.
fn normalized_keyword_set() -> &'static HashSet<String> {
    static SET: OnceLock<HashSet<String>> = OnceLock::new();
    SET.get_or_init(|| RAW.iter().map(|word| normalize_key_name(word)).collect())
}

/// The multilingual key-name vocabulary, sorted.
pub fn secret_keywords() -> Vec<String> {
    let mut out: Vec<String> = keyword_set().iter().cloned().collect();
    out.sort();
    out
}

/// The English rule of SPEC §9, matched against the normalised key. A key is
/// sensitive when it ends with a credential word, glued or not (`db_password`,
/// `DbPassword`, `accessToken`, `apiSecret`, `aws_secret_access_key`), or when it
/// is, or ends in `_`, `-`, `.` or a space followed by, a short word that is only
/// safe whole (`pass`, `auth`, `pin`, `otp`, `cvv`, `ssn`, `dsn`, `pwd` and the
/// rest). Look-alikes such as `author`, `monkey`, `publicKey`, `tokenizer` and
/// `max_tokens` stay readable.
const SENSITIVE_KEY_PATTERN: &str = concat!(
    r"^(?:[\s\S]*(?:pass(?:word|wd|phrase)|secret|token|credentials?|cookies?|mnemonic",
    r"|(?:api|access|secret|private|encryption|signing|master|client)[_. -]?keys?",
    r"|session[_. -]?id|credit[_. -]?card|card[_. -]?number|connection[_. -]?string",
    r"|(?:seed|recovery)[_. -]?phrase)",
    r"|(?:[\s\S]*[_. -])?(?:pass|auth|authorization|bearer|csrf|xsrf|jwt|pin|otp|totp|hotp",
    r"|cvv2?|cvc|ssn|dsn|creds|pwd))$",
);

/// Keys that end in `token` but name a pagination cursor or a count, not a
/// credential (`next_token`, `nextPageToken`, `max_token`).
const NON_SECRET_TOKEN_KEY_PATTERN: &str =
    r"^[\s\S]*(?:next|page|continuation|pagination|cursor|sync|resume|max)[_. -]?token$";

fn sensitive_key_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(SENSITIVE_KEY_PATTERN).expect("sensitive key pattern compiles"))
}

fn non_secret_token_key_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(NON_SECRET_TOKEN_KEY_PATTERN).expect("non-secret token pattern compiles")
    })
}

/// Whether a field name is sensitive by convention, in any supported language:
/// its normalised form (SPEC §9) matches the English rule and is not a
/// pagination token, or is a keyword.
pub fn is_sensitive_key_name(name: &str) -> bool {
    let normalized = normalize_key_name(name);
    (sensitive_key_regex().is_match(&normalized)
        && !non_secret_token_key_regex().is_match(&normalized))
        || normalized_keyword_set().contains(&normalized)
}
