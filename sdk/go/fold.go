package flareredact

// Case handling shared by every FRS-1 engine (SPEC §2 "Flags", §9).
//
// Case-insensitive matching is Unicode simple case folding plus one merge: i, I,
// İ (U+0130) and ı (U+0131) form a single class. Simple folding alone keeps the
// two Turkish letters apart from i, so ŞİFRE, GİZLİ or an identifier that was
// upper-cased under a Turkish locale (APİ_KEY) would slip past every keyword.
// RE2's (?i) folds exactly, so case-insensitive patterns are rewritten with
// expandDottedI before they are compiled.

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

const dottedClass = "iI\U00000130\U00000131"

var dottedRunes = [...]rune{'i', 'I', 0x130, 0x131}

func isDottedRune(r rune) bool {
	return r == 'i' || r == 'I' || r == 0x130 || r == 0x131
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func hexValue(b byte) rune {
	switch {
	case b >= '0' && b <= '9':
		return rune(b - '0')
	case b >= 'a' && b <= 'f':
		return rune(b-'a') + 10
	default:
		return rune(b-'A') + 10
	}
}

// readAtom reads one class or literal atom at index. ok is false for an escape
// whose set is opaque (\d, \p{…}).
func readAtom(source string, index int) (code rune, ok bool, next int) {
	if source[index] != '\\' {
		r, size := utf8.DecodeRuneInString(source[index:])
		return r, true, index + size
	}
	if index+1 >= len(source) {
		return 0, false, index + 1
	}
	esc := source[index+1]
	switch {
	case esc == 'x' && index+4 <= len(source) && isHexDigit(source[index+2]) && isHexDigit(source[index+3]):
		return hexValue(source[index+2])<<4 | hexValue(source[index+3]), true, index + 4
	case esc == 'p' || esc == 'P':
		if index+2 < len(source) && source[index+2] == '{' {
			if close := strings.IndexByte(source[index+3:], '}'); close >= 0 {
				return 0, false, index + 3 + close + 1
			}
		}
		return 0, false, index + 2
	case esc == 't':
		return '\t', true, index + 2
	case esc == 'n':
		return '\n', true, index + 2
	case esc == 'r':
		return '\r', true, index + 2
	case esc == 'f':
		return '\f', true, index + 2
	case (esc >= 'A' && esc <= 'Z') || (esc >= 'a' && esc <= 'z') || (esc >= '0' && esc <= '9'):
		return 0, false, index + 2
	}
	r, size := utf8.DecodeRuneInString(source[index+1:])
	return r, true, index + 1 + size
}

// expandDottedI rewrites a pattern that will be compiled case-insensitively so
// that i, I, İ and ı are interchangeable. A literal becomes [iIİı]; a character
// class that holds any of the four (directly or inside a range) gains the other
// three, which for a negated class keeps all four out.
func expandDottedI(source string) string {
	var out strings.Builder
	out.Grow(len(source) + 16)
	for index := 0; index < len(source); {
		ch := source[index]
		if ch == '{' && strings.HasPrefix(source[index:], "{{") {
			end := len(source)
			if close := strings.Index(source[index+2:], "}}"); close >= 0 {
				end = index + 2 + close + 2
			}
			out.WriteString(source[index:end])
			index = end
			continue
		}
		if ch == '(' && isNamedGroup(source[index:]) {
			// A named group header: its name is not a literal to rewrite.
			end := len(source)
			if close := strings.IndexByte(source[index:], '>'); close >= 0 {
				end = index + close + 1
			}
			out.WriteString(source[index:end])
			index = end
			continue
		}
		if ch == '[' {
			text, next := rewriteClass(source, index)
			out.WriteString(text)
			index = next
			continue
		}
		code, ok, next := readAtom(source, index)
		if ok && isDottedRune(code) {
			out.WriteString("[" + dottedClass + "]")
		} else {
			out.WriteString(source[index:next])
		}
		index = next
	}
	return out.String()
}

func isNamedGroup(rest string) bool {
	for _, head := range []string{"(?<", "(?P<"} {
		if strings.HasPrefix(rest, head) && len(rest) > len(head) {
			b := rest[len(head)]
			if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') {
				return true
			}
		}
	}
	return false
}

func rewriteClass(source string, start int) (string, int) {
	index := start + 1
	if index < len(source) && source[index] == '^' {
		index++
	}
	bodyStart := index
	if index < len(source) && source[index] == ']' {
		index++
	}
	holds := false
	lastDash := -1
	for index < len(source) && source[index] != ']' {
		lo, okLo, next := readAtom(source, index)
		hi, okHi := lo, okLo
		index = next
		lastDash = -1
		if index+1 < len(source) && source[index] == '-' && source[index+1] != ']' {
			hi, okHi, next = readAtom(source, index+1)
			index = next
			if !okLo || !okHi {
				okLo, okHi = false, false
			}
		} else if source[index-1] == '-' && (index < 2 || source[index-2] != '\\') {
			lastDash = index - 1
		}
		if okLo && okHi {
			for _, code := range dottedRunes {
				if code >= lo && code <= hi {
					holds = true
				}
			}
		}
	}
	if index >= len(source) {
		// An unterminated class: leave it for the compiler to reject.
		return source[start:], len(source)
	}
	head := source[start:bodyStart]
	body := source[bodyStart:index]
	if holds {
		// Never append right after a trailing literal '-': [a-z-] + i would read
		// as a range. Insert in front of that dash instead.
		if lastDash == index-1 {
			body = body[:len(body)-1] + dottedClass + "-"
		} else {
			body += dottedClass
		}
	}
	return head + body + "]", index + 1
}

var (
	dottedToI     = strings.NewReplacer("\U00000130", "i", "\U00000131", "i")
	foldLowerTail = strings.NewReplacer("\U000003C2", "\U000003C3", "\U0000017F", "s")
)

// normalizeKeyName is the form a key name is compared in (SPEC §9): İ and ı
// become i, every character takes its simple lowercase mapping, and final sigma
// and long s fold to σ and s.
func normalizeKeyName(name string) string {
	return foldLowerTail.Replace(strings.ToLower(dottedToI.Replace(name)))
}

// compilePrefilter builds one case-insensitive search for any of literals, with
// the same case rules as a detector pattern, so a prefilter never skips a
// detector that would match.
func compilePrefilter(literals []string) (*regexp.Regexp, error) {
	if len(literals) == 0 {
		return nil, nil
	}
	parts := make([]string, len(literals))
	for i, literal := range literals {
		parts[i] = expandDottedI(regexp.QuoteMeta(literal))
	}
	return regexp.Compile("(?i)" + strings.Join(parts, "|"))
}

// asciiLower maps A-Z to a-z and leaves every other byte alone, so a
// case-sensitive search over the result is ASCII-only case folding.
func asciiLower(text string) string {
	for i := 0; i < len(text); i++ {
		if c := text[i]; c >= 'A' && c <= 'Z' {
			b := []byte(text)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return text
}
