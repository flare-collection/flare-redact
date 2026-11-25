using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text.RegularExpressions;

namespace FlareRedact
{
    /// <summary>
    /// Field names that are sensitive by convention, in the 24 supported languages (SPEC §9).
    /// A value stored under one of them is redacted without pattern matching, because
    /// <c>{"password": "hunter2"}</c> is a secret even though <c>hunter2</c> looks like nothing
    /// in particular.
    /// </summary>
    public static class Keywords
    {
        private static readonly string[] Raw =
        {
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
            "motdepasse", "mot_de_passe", "motdepass", "clé", "clef", "clésecrète", "secret",
            // 7. Portuguese
            "senha", "segredo", "chavesecreta", "chave",
            // 8. Russian
            "пароль", "секрет", "токен", "ключ", "секретныйключ",
            // 9. Japanese
            "パスワード", "秘密", "トークン", "暗証番号", "合言葉",
            // 10. German
            "passwort", "kennwort", "geheimnis", "geheim", "schlüssel", "schluessel", "zugangsschlüssel",
            // 11. Korean
            "비밀번호", "암호", "비밀", "토큰", "비밀키",
            // 12. Turkish
            "şifre", "sifre", "parola", "gizli", "anahtar", "gizlianahtar",
            // 13. Italian
            "segreto", "chiave", "parolachiave", "parola_chiave", "credenziale",
            // 14. Persian
            "رمز", "رمزعبور", "گذرواژه", "کلمهعبور", "کلید", "محرمانه",
            // 15. Polish
            "hasło", "haslo", "tajne", "klucz", "poufne",
            // 16. Ukrainian
            "пароль", "секрет", "ключ", "таємний",
            // 17. Dutch
            "wachtwoord", "geheim", "sleutel",
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
            "şifrə", "parol", "gizli", "açar", "məxfi",
            // 24. Romanian
            "parolă", "parola", "cheie",
        };

        private static readonly HashSet<string> Normalized;

        /// <summary>English names a field is sensitive under, compared against the normalised key.</summary>
        private static readonly Regex SensitiveKey = new Regex(
            "^(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key"
            + "|auth(?:orization)?|cookie|session[_-]?id|refresh[_-]?token|credit[_-]?card|card[_-]?number|cvv|ssn)\\z",
            RegexOptions.CultureInvariant);

        static Keywords()
        {
            var words = new List<string>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (string word in Raw)
            {
                string lower = word.ToLowerInvariant();
                if (seen.Add(lower)) words.Add(lower);
            }
            words.Sort(StringComparer.Ordinal);
            SecretKeywords = new ReadOnlyCollection<string>(words);
            Normalized = new HashSet<string>(StringComparer.Ordinal);
            foreach (string word in words) Normalized.Add(NormalizeKeyName(word));
        }

        /// <summary>The multilingual key-name vocabulary, lower-cased and sorted.</summary>
        public static IReadOnlyList<string> SecretKeywords { get; }

        /// <summary>
        /// The form a key name is compared in (SPEC §9): İ and ı become i, every character takes
        /// its lowercase mapping, then final sigma becomes σ and long s becomes s.
        /// </summary>
        public static string NormalizeKeyName(string name) =>
            name.Replace('\u0130', 'i').Replace('\u0131', 'i')
                .ToLowerInvariant()
                .Replace('\u03C2', '\u03C3')
                .Replace('\u017F', 's');

        /// <summary>Whether a field name is sensitive by convention, in any supported language.</summary>
        public static bool IsSensitiveKeyName(string name)
        {
            string normalized = NormalizeKeyName(name);
            return SensitiveKey.IsMatch(normalized) || Normalized.Contains(normalized);
        }
    }
}
