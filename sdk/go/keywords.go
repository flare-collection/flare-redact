package flareredact

import (
	"regexp"
	"sort"
	"strings"
)

// Field names that are sensitive by convention, in 24 major languages.
//
// Structured secrets — API keys, JWTs, card numbers — carry their own shape and
// are found by pattern. Word-based secrets are not: "password", "密码", "şifrə"
// and "كلمةالمرور" are only recognisable as names. This list is what lets
// map[string]any{"parola": "hunter2"} be redacted in an Italian codebase.

var secretKeywords = dedupeLower([]string{
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
})

func dedupeLower(words []string) map[string]struct{} {
	out := make(map[string]struct{}, len(words))
	for _, word := range words {
		out[strings.ToLower(word)] = struct{}{}
	}
	return out
}

// SecretKeywords returns the multilingual key-name vocabulary, sorted for
// stable output.
func SecretKeywords() []string {
	out := make([]string, 0, len(secretKeywords))
	for word := range secretKeywords {
		out = append(out, word)
	}
	sort.Strings(out)
	return out
}

// sensitiveKeyPattern is the English rule of SPEC §9, matched against the
// normalised key. A key is sensitive when it ends with a credential word, glued
// or not (db_password, DbPassword, accessToken, apiSecret,
// aws_secret_access_key), or when it is, or ends in _, -, . or a space followed
// by, a short word that is only safe whole (pass, auth, pin, otp, cvv, ssn, dsn,
// pwd and the rest). Look-alikes such as author, monkey, publicKey, tokenizer
// and max_tokens stay readable.
var sensitiveKeyPattern = regexp.MustCompile(`^(?:` +
	`[\s\S]*(?:pass(?:word|wd|phrase)|secret|token|credentials?|cookies?|mnemonic` +
	`|(?:api|access|secret|private|encryption|signing|master|client)[_. -]?keys?` +
	`|session[_. -]?id|credit[_. -]?card|card[_. -]?number|connection[_. -]?string` +
	`|(?:seed|recovery)[_. -]?phrase)` +
	`|(?:[\s\S]*[_. -])?(?:pass|auth|authorization|bearer|csrf|xsrf|jwt|pin|otp|totp|hotp|cvv2?|cvc|ssn|dsn|creds|pwd)` +
	`)$`)

// nonSecretTokenKeyPattern matches keys that end in token but name a pagination
// cursor or a count (next_token, nextPageToken, max_token); they are not
// sensitive by name unless they are a keyword.
var nonSecretTokenKeyPattern = regexp.MustCompile(`^[\s\S]*(?:next|page|continuation|pagination|cursor|sync|resume|max)[_. -]?token$`)

// normalizedKeywords holds secretKeywords in the form key names are compared in.
var normalizedKeywords = func() map[string]struct{} {
	out := make(map[string]struct{}, len(secretKeywords))
	for word := range secretKeywords {
		out[normalizeKeyName(word)] = struct{}{}
	}
	return out
}()

// isSensitiveKeyName reports whether a key is sensitive by name (SPEC §9): its
// normalised form matches the English rule and is not a pagination token, or is
// a multilingual keyword.
func isSensitiveKeyName(name string) bool {
	normalized := normalizeKeyName(name)
	if sensitiveKeyPattern.MatchString(normalized) && !nonSecretTokenKeyPattern.MatchString(normalized) {
		return true
	}
	_, ok := normalizedKeywords[normalized]
	return ok
}
