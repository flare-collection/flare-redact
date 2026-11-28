package io.github.flarecollection.redact;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Field names that are sensitive by convention, in the 24 supported languages
 * (SPEC §9). A value stored under one of them is redacted without pattern
 * matching, because {@code {"password": "hunter2"}} is a secret even though
 * {@code hunter2} looks like nothing in particular.
 */
public final class Keywords {
    private Keywords() {
    }

    private static final String[] RAW = {
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

    private static final List<String> SECRET_KEYWORDS;
    private static final Set<String> NORMALIZED;

    static {
        Set<String> words = new LinkedHashSet<>();
        for (String word : RAW) {
            words.add(word.toLowerCase(Locale.ROOT));
        }
        List<String> sorted = new ArrayList<>(words);
        Collections.sort(sorted);
        SECRET_KEYWORDS = Collections.unmodifiableList(sorted);
        Set<String> normalized = new HashSet<>();
        for (String word : words) {
            normalized.add(normalizeKeyName(word));
        }
        NORMALIZED = Collections.unmodifiableSet(normalized);
    }

    /**
     * The English rule of SPEC §9, matched against the normalised key. A key is
     * sensitive when it ends with a credential word, glued or not
     * ({@code db_password}, {@code DbPassword}, {@code accessToken},
     * {@code apiSecret}), or when it is, or ends in {@code _}, {@code -},
     * {@code .} or a space followed by, a short word that is only safe whole
     * ({@code pass}, {@code auth}, {@code pin}, {@code otp}, {@code cvv},
     * {@code ssn}, {@code dsn}, {@code pwd} and the rest).
     */
    private static final Pattern SENSITIVE_KEY = Pattern.compile(
        "[\\s\\S]*(?:pass(?:word|wd|phrase)|secret|token|credentials?|cookies?|mnemonic"
            + "|(?:api|access|secret|private|encryption|signing|master|client)[_. -]?keys?"
            + "|session[_. -]?id|credit[_. -]?card|card[_. -]?number|connection[_. -]?string"
            + "|(?:seed|recovery)[_. -]?phrase)"
            + "|(?:[\\s\\S]*[_. -])?(?:pass|auth|authorization|bearer|csrf|xsrf|jwt|pin|otp|totp|hotp"
            + "|cvv2?|cvc|ssn|dsn|creds|pwd)");

    /** Keys ending in {@code token} that name a pagination cursor or a count, not a credential. */
    private static final Pattern NON_SECRET_TOKEN_KEY = Pattern.compile(
        "[\\s\\S]*(?:next|page|continuation|pagination|cursor|sync|resume|max)[_. -]?token");

    /** @return the multilingual key-name vocabulary, lower-cased and sorted */
    public static List<String> secretKeywords() {
        return SECRET_KEYWORDS;
    }

    /**
     * The form a key name is compared in (SPEC §9): İ and ı become i, every
     * character takes its lowercase mapping, then final sigma becomes σ and long s
     * becomes s. A locale-free full lowercase differs from the simple mapping only
     * in İ and the final-sigma rule, both of which this form erases.
     *
     * @param name a field name
     * @return its normalised form
     */
    public static String normalizeKeyName(String name) {
        return name.replace((char) 0x130, 'i').replace((char) 0x131, 'i')
            .toLowerCase(Locale.ROOT)
            .replace((char) 0x3C2, (char) 0x3C3)
            .replace((char) 0x17F, 's');
    }

    /**
     * Whether a field name is sensitive by convention, in any supported language.
     *
     * @param name a field name
     * @return true when its normalised form is a conventional English name or a keyword
     */
    public static boolean isSensitiveKeyName(String name) {
        String normalized = normalizeKeyName(name);
        return (SENSITIVE_KEY.matcher(normalized).matches()
                && !NON_SECRET_TOKEN_KEY.matcher(normalized).matches())
            || NORMALIZED.contains(normalized);
    }
}
