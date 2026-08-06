package flareredact

import (
	"fmt"
	"strings"
)

// Keyed, shape-preserving replacements.
//
// Masking destroys a dataset for analytics: every card becomes "**** 1234" and
// joins stop working. These transforms keep the shape and the distinctness of a
// value while removing its meaning, so a staging database still exercises the
// same code paths as production. Neither is reversible — use a Vault for that.

const (
	lowerAlphabet = "abcdefghijklmnopqrstuvwxyz"
	upperAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitAlphabet = "0123456789"
)

var (
	givenNames  = [...]string{"Alex", "Avery", "Casey", "Emery", "Jordan", "Morgan", "Riley", "Robin"}
	familyNames = [...]string{"Arden", "Blake", "Hayes", "Lane", "Parker", "Reed", "Shaw", "Vale"}
	streetNames = [...]string{"Cedar", "Harbor", "Juniper", "Maple", "Orchard", "River", "Willow", "Summit"}
)

func alphabetFor(r rune) string {
	switch {
	case r >= '0' && r <= '9':
		return digitAlphabet
	case r >= 'a' && r <= 'z':
		return lowerAlphabet
	case r >= 'A' && r <= 'Z':
		return upperAlphabet
	default:
		return ""
	}
}

// Pseudonymize returns a deterministic, keyed, shape-preserving substitution.
//
// It is deliberately not called format-preserving encryption: it is not
// reversible and does not implement NIST FF1. It is a stable pseudonym, so the
// same input and key always give the same output and joins survive.
func Pseudonymize(value, secret string) string {
	runes := []rune(value)
	stream := DeriveBytes(secret, "pseudonym:"+value, len(runes))
	var out strings.Builder
	out.Grow(len(value))
	for i, r := range runes {
		alphabet := alphabetFor(r)
		if alphabet == "" {
			out.WriteRune(r)
			continue
		}
		out.WriteByte(alphabet[int(stream[i])%len(alphabet)])
	}
	return out.String()
}

func digitSurrogate(value, secret string) string {
	runes := []rune(value)
	stream := DeriveBytes(secret, "digits:"+value, len(runes))
	var out strings.Builder
	out.Grow(len(value))
	for i, r := range runes {
		if r >= '0' && r <= '9' {
			out.WriteByte(digitAlphabet[int(stream[i])%10])
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}

func luhnCheckDigit(prefix string) string {
	d := digitsOf(prefix)
	sum := 0
	double := true
	for i := len(d) - 1; i >= 0; i-- {
		n := atoiByte(d[i])
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return fmt.Sprintf("%d", (10-(sum%10))%10)
}

// cardSurrogate keeps the card shape and recomputes the Luhn digit, so the
// synthetic number still passes the validation your code already does.
func cardSurrogate(value, secret string) string {
	shaped := []rune(digitSurrogate(value, secret))
	last := -1
	for i, r := range shaped {
		if r >= '0' && r <= '9' {
			last = i
		}
	}
	if last < 0 {
		return string(shaped)
	}
	prefix := string(shaped[:last])
	return prefix + luhnCheckDigit(prefix) + string(shaped[last+1:])
}

func emailSurrogate(value, secret string) string {
	return "user_" + HMACFingerprint(secret, "email:"+value, 6) + "@example.invalid"
}

func personSurrogate(value, secret string) string {
	stream := DeriveBytes(secret, "person:"+value, 2)
	return givenNames[int(stream[0])%len(givenNames)] + " " + familyNames[int(stream[1])%len(familyNames)]
}

func addressSurrogate(value, secret string) string {
	stream := DeriveBytes(secret, "address:"+value, 3)
	number := 100 + ((int(stream[0])<<8 | int(stream[1])) % 9800)
	return fmt.Sprintf("%d %s Street", number, streetNames[int(stream[2])%len(streetNames)])
}

// Surrogate returns a deterministic, type-consistent synthetic value for the
// given detector: an email stays an email, a card stays a valid card.
func Surrogate(value, detectorID, secret string) string {
	switch detectorID {
	case "email":
		return emailSurrogate(value, secret)
	case "credit_card":
		return cardSurrogate(value, secret)
	case "phone":
		return digitSurrogate(value, secret)
	case "person_name":
		return personSurrogate(value, secret)
	case "street_address":
		return addressSurrogate(value, secret)
	default:
		return Pseudonymize(value, secret)
	}
}
