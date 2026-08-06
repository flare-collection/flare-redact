package flareredact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
)

// ErrMissingSecret is returned when a keyed transform is requested without a
// TransformSecret. Falling back to unkeyed output would silently produce
// pseudonyms anyone could reproduce, so this is an error rather than a default.
var ErrMissingSecret = errors.New("flareredact: a non-empty TransformSecret is required for keyed transforms")

func hmacSHA256(secret, message string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return mac.Sum(nil)
}

// HMACFingerprint returns the lowercase hex of the first n bytes of
// HMAC-SHA256(secret, value). It is the basis of ModeHash.
func HMACFingerprint(secret, value string, n int) string {
	sum := hmacSHA256(secret, value)
	if n > len(sum) {
		n = len(sum)
	}
	return hex.EncodeToString(sum[:n])
}

// DeriveBytes expands secret into n bytes bound to context, using counter-mode
// HMAC. Block i is HMAC(secret, context + "\x00" + itoa(i)), which is what makes
// the derived stream identical in every flare-redact engine.
func DeriveBytes(secret, context string, n int) []byte {
	if n <= 0 {
		return nil
	}
	out := make([]byte, 0, n)
	for counter := 0; len(out) < n; counter++ {
		out = append(out, hmacSHA256(secret, context+"\x00"+strconv.Itoa(counter))...)
	}
	return out[:n]
}
