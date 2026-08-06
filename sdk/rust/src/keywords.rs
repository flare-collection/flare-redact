//! Field names that are sensitive by convention, in 24 major languages.
//!
//! Structured secrets — API keys, JWTs, card numbers — carry their own shape and
//! are found by pattern. Word-based secrets are not: `password`, `密码`, `şifrə`
//! and `كلمةالمرور` are only recognisable as *names*. This list is what lets
//! `{"parola": "hunter2"}` be redacted in an Italian codebase.

use std::collections::HashSet;
use std::sync::OnceLock;

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

/// The multilingual key-name vocabulary, sorted.
pub fn secret_keywords() -> Vec<String> {
    let mut out: Vec<String> = keyword_set().iter().cloned().collect();
    out.sort();
    out
}

/// English key names that are sensitive by convention, matched case-insensitively.
const ENGLISH_KEYS: &[&str] = &[
    "password", "passwd", "pass", "secret", "token", "apikey", "api_key", "api-key",
    "accesskey", "access_key", "access-key", "clientsecret", "client_secret", "client-secret",
    "privatekey", "private_key", "private-key", "auth", "authorization", "cookie",
    "sessionid", "session_id", "session-id", "refreshtoken", "refresh_token", "refresh-token",
    "creditcard", "credit_card", "credit-card", "cardnumber", "card_number", "card-number",
    "cvv", "ssn",
];

/// Whether a field name is sensitive by convention, in any supported language.
pub fn is_sensitive_key_name(name: &str) -> bool {
    let lowered = name.to_lowercase();
    ENGLISH_KEYS.contains(&lowered.as_str()) || keyword_set().contains(&lowered)
}
