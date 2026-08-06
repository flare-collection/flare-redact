package flareredact

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Named validators referenced by an FRS-1 detector pack.
//
// A checksum is the difference between "eleven digits" and "a Turkish national
// identity number". Every national identifier here is validated, which is what
// keeps the opt-in country detectors usable on real logs instead of drowning
// them in false positives.

var nonDigit = regexp.MustCompile(`[^0-9]`)

func digitsOf(value string) string { return nonDigit.ReplaceAllString(value, "") }

func allSameDigits(digits string) bool {
	if digits == "" {
		return false
	}
	for i := 1; i < len(digits); i++ {
		if digits[i] != digits[0] {
			return false
		}
	}
	return true
}

func atoiByte(b byte) int { return int(b - '0') }

// Luhn reports whether the digits of value satisfy the mod-10 Luhn checksum,
// with an optional length window. maxDigits of 0 means unbounded.
func Luhn(value string, minDigits, maxDigits int) bool {
	d := digitsOf(value)
	if len(d) < minDigits {
		return false
	}
	if maxDigits > 0 && len(d) > maxDigits {
		return false
	}
	sum := 0
	double := false
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
	return sum%10 == 0
}

// ShannonEntropy returns bits per symbol over Unicode code points.
func ShannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	freq := map[rune]int{}
	total := 0
	for _, r := range value {
		freq[r]++
		total++
	}
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}

var (
	phoneYearTail  = regexp.MustCompile(`(?:19|20)[0-9]{2}$`)
	phoneDatedTail = regexp.MustCompile("[. \t\n\x0B\f\r-](?:19|20)[0-9]{2}$")
)

// validPhone applies E.164 digit bounds and rejects dotted dates such as
// 07.24.2026, which otherwise look exactly like a national number.
func validPhone(value string) bool {
	d := digitsOf(value)
	if len(d) < 8 || len(d) > 15 {
		return false
	}
	if !strings.HasPrefix(value, "+") {
		if len(d) < 9 {
			return false
		}
		if phoneYearTail.MatchString(d) && phoneDatedTail.MatchString(value) {
			return false
		}
	}
	return true
}

var ibanShape = regexp.MustCompile(`^[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}$`)

// validIBAN implements the ISO 13616 mod-97 check.
func validIBAN(value string) bool {
	text := strings.ToUpper(strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", "\f", "", "\v", "", "-", "").Replace(value))
	if !ibanShape.MatchString(text) {
		return false
	}
	rearranged := text[4:] + text[:4]
	remainder := 0
	for i := 0; i < len(rearranged); i++ {
		ch := rearranged[i]
		var chunk string
		if ch >= 'A' && ch <= 'Z' {
			chunk = strconv.Itoa(int(ch) - 55)
		} else {
			chunk = string(ch)
		}
		for j := 0; j < len(chunk); j++ {
			remainder = (remainder*10 + atoiByte(chunk[j])) % 97
		}
	}
	return remainder == 1
}

// validTCKN checks the two Turkish T.C. Kimlik No check digits.
func validTCKN(value string) bool {
	d := digitsOf(value)
	if len(d) != 11 || d[0] == '0' {
		return false
	}
	odd := atoiByte(d[0]) + atoiByte(d[2]) + atoiByte(d[4]) + atoiByte(d[6]) + atoiByte(d[8])
	even := atoiByte(d[1]) + atoiByte(d[3]) + atoiByte(d[5]) + atoiByte(d[7])
	if ((odd*7-even)%10+10)%10 != atoiByte(d[9]) {
		return false
	}
	sum := 0
	for i := 0; i < 10; i++ {
		sum += atoiByte(d[i])
	}
	return sum%10 == atoiByte(d[10])
}

// validCPF checks the two mod-11 digits of a Brazilian CPF.
func validCPF(value string) bool {
	c := digitsOf(value)
	if len(c) != 11 || allSameDigits(c) {
		return false
	}
	check := func(length int) int {
		sum := 0
		for i := 0; i < length; i++ {
			sum += atoiByte(c[i]) * (length + 1 - i)
		}
		r := (sum * 10) % 11
		if r == 10 {
			return 0
		}
		return r
	}
	return check(9) == atoiByte(c[9]) && check(10) == atoiByte(c[10])
}

const dniLetters = "TRWAGMYFPDXBNJZSQVHLCKE"

var dniShape = regexp.MustCompile(`^([XYZ]?)([0-9]{7,8})([A-Z])$`)

// validDNI maps a Spanish DNI/NIE number mod 23 to its control letter.
func validDNI(value string) bool {
	text := strings.ToUpper(strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", "\f", "", "\v", "", "-", "").Replace(value))
	m := dniShape.FindStringSubmatch(text)
	if m == nil {
		return false
	}
	prefix := ""
	if m[1] != "" {
		prefix = strconv.Itoa(strings.Index("XYZ", m[1]))
	}
	n, err := strconv.Atoi(prefix + m[2])
	if err != nil {
		return false
	}
	return string(dniLetters[n%23]) == m[3]
}

// validBSN applies the Dutch 11-test, whose final weight is −1.
func validBSN(value string) bool {
	d := digitsOf(value)
	if len(d) != 9 || d == "000000000" {
		return false
	}
	sum := 0
	for i := 0; i < 8; i++ {
		sum += atoiByte(d[i]) * (9 - i)
	}
	sum -= atoiByte(d[8])
	return sum%11 == 0
}

// validPESEL applies the Polish weighted mod-10 check.
func validPESEL(value string) bool {
	d := digitsOf(value)
	if len(d) != 11 {
		return false
	}
	weights := [10]int{1, 3, 7, 9, 1, 3, 7, 9, 1, 3}
	sum := 0
	for i := 0; i < 10; i++ {
		sum += atoiByte(d[i]) * weights[i]
	}
	return (10-(sum%10))%10 == atoiByte(d[10])
}

// validDETaxID applies ISO 7064 MOD 11,10 to a German Steuer-IdNr.
func validDETaxID(value string) bool {
	d := digitsOf(value)
	if len(d) != 11 {
		return false
	}
	product := 10
	for i := 0; i < 10; i++ {
		sum := (atoiByte(d[i]) + product) % 10
		if sum == 0 {
			sum = 10
		}
		product = (sum * 2) % 11
	}
	return (11-product)%10 == atoiByte(d[10])
}

var cfOdd = map[byte]int{
	'0': 1, '1': 0, '2': 5, '3': 7, '4': 9, '5': 13, '6': 15, '7': 17, '8': 19, '9': 21,
	'A': 1, 'B': 0, 'C': 5, 'D': 7, 'E': 9, 'F': 13, 'G': 15, 'H': 17, 'I': 19, 'J': 21,
	'K': 2, 'L': 4, 'M': 18, 'N': 20, 'O': 11, 'P': 3, 'Q': 6, 'R': 8, 'S': 12, 'T': 14,
	'U': 16, 'V': 10, 'W': 22, 'X': 25, 'Y': 24, 'Z': 23,
}

var cfShape = regexp.MustCompile(`^[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]$`)

// validCodiceFiscale applies the Italian odd/even table checksum.
func validCodiceFiscale(value string) bool {
	cf := strings.ToUpper(value)
	if !cfShape.MatchString(cf) {
		return false
	}
	sum := 0
	for i := 0; i < 15; i++ {
		ch := cf[i]
		if i%2 == 0 {
			sum += cfOdd[ch]
		} else if ch >= '0' && ch <= '9' {
			sum += int(ch - '0')
		} else {
			sum += int(ch - 'A')
		}
	}
	return byte('A'+(sum%26)) == cf[15]
}

var nirShape = regexp.MustCompile(`^([12][0-9]{4})([0-9]{2}|2[AB])([0-9]{6})([0-9]{2})$`)

// validFRNIR checks the French INSEE key, 97 − (n mod 97), with Corsica's
// 2A and 2B mapped to 19 and 18 before the modulo.
func validFRNIR(value string) bool {
	nir := strings.ToUpper(strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", "\f", "", "\v", "", ".", "", "-", "").Replace(value))
	m := nirShape.FindStringSubmatch(nir)
	if m == nil {
		return false
	}
	dept := m[2]
	switch dept {
	case "2A":
		dept = "19"
	case "2B":
		dept = "18"
	}
	n, err := strconv.ParseInt(m[1]+dept+m[3], 10, 64)
	if err != nil {
		return false
	}
	key, err := strconv.Atoi(m[4])
	if err != nil {
		return false
	}
	return int(97-(n%97)) == key
}

var verhoeffD = [10][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
	{2, 3, 4, 0, 1, 7, 8, 9, 5, 6}, {3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
	{4, 0, 1, 2, 3, 9, 5, 6, 7, 8}, {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
	{6, 5, 9, 8, 7, 1, 0, 4, 3, 2}, {7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
	{8, 7, 6, 5, 9, 3, 2, 1, 0, 4}, {9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
}

var verhoeffP = [8][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
	{5, 8, 0, 3, 7, 9, 6, 1, 4, 2}, {8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
	{9, 4, 5, 3, 1, 2, 6, 8, 7, 0}, {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
	{2, 7, 9, 3, 8, 0, 6, 4, 1, 5}, {7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
}

// validAadhaar applies the Verhoeff checksum; the first digit is never 0 or 1.
func validAadhaar(value string) bool {
	d := digitsOf(value)
	if len(d) != 12 || d[0] == '0' || d[0] == '1' {
		return false
	}
	c := 0
	for i := 0; i < 12; i++ {
		c = verhoeffD[c][verhoeffP[i%8][atoiByte(d[11-i])]]
	}
	return c == 0
}

// validTFN checks that the Australian weighted sum is divisible by 11.
func validTFN(value string) bool {
	d := digitsOf(value)
	if len(d) != 9 || allSameDigits(d) {
		return false
	}
	weights := [9]int{1, 4, 3, 7, 5, 8, 6, 9, 10}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += atoiByte(d[i]) * weights[i]
	}
	return sum%11 == 0
}

var (
	cnWeights = [17]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	cnCheck   = "10X98765432"
	cnShape   = regexp.MustCompile(`^[1-9][0-9]{5}(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9X]$`)
)

// validCNResidentID applies ISO 7064 MOD 11-2 to a Chinese resident ID.
func validCNResidentID(value string) bool {
	id := strings.ToUpper(value)
	if !cnShape.MatchString(id) {
		return false
	}
	sum := 0
	for i := 0; i < 17; i++ {
		sum += atoiByte(id[i]) * cnWeights[i]
	}
	return cnCheck[sum%11] == id[17]
}

// validJPMyNumber applies the Japanese weighted mod-11 check digit.
func validJPMyNumber(value string) bool {
	d := digitsOf(value)
	if len(d) != 12 {
		return false
	}
	sum := 0
	for n := 1; n <= 11; n++ {
		weight := n + 1
		if n > 6 {
			weight = n - 5
		}
		sum += atoiByte(d[11-n]) * weight
	}
	r := sum % 11
	check := 0
	if r > 1 {
		check = 11 - r
	}
	return check == atoiByte(d[11])
}

var ssnShape = regexp.MustCompile(`^([0-9]{3})-?([0-9]{2})-?([0-9]{4})$`)

// validSSN rejects the ranges the US never issued. There is no checksum.
func validSSN(value string) bool {
	m := ssnShape.FindStringSubmatch(value)
	if m == nil {
		return false
	}
	area, _ := strconv.Atoi(m[1])
	group, _ := strconv.Atoi(m[2])
	serial, _ := strconv.Atoi(m[3])
	if area == 0 || area == 666 || area >= 900 {
		return false
	}
	return group != 0 && serial != 0
}

// validABA applies the US routing number's weighted 3-7-1 mod-10 check.
func validABA(value string) bool {
	d := digitsOf(value)
	if len(d) != 9 {
		return false
	}
	sum := 0
	for i := 0; i < 9; i += 3 {
		sum += 3*atoiByte(d[i]) + 7*atoiByte(d[i+1]) + atoiByte(d[i+2])
	}
	return sum != 0 && sum%10 == 0
}

// validNHS applies the UK weighted mod-11 check digit.
func validNHS(value string) bool {
	d := digitsOf(value)
	if len(d) != 10 || allSameDigits(d) {
		return false
	}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += atoiByte(d[i]) * (10 - i)
	}
	check := 11 - (sum % 11)
	if check == 11 {
		check = 0
	}
	if check == 10 {
		return false
	}
	return check == atoiByte(d[9])
}

var (
	vinTrans = map[byte]int{
		'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6, 'G': 7, 'H': 8, 'J': 1, 'K': 2,
		'L': 3, 'M': 4, 'N': 5, 'P': 7, 'R': 9, 'S': 2, 'T': 3, 'U': 4, 'V': 5, 'W': 6,
		'X': 7, 'Y': 8, 'Z': 9,
	}
	vinWeights = [17]int{8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2}
	vinShape   = regexp.MustCompile(`^[A-HJ-NPR-Z0-9]{17}$`)
)

// validVIN applies the transliterated weighted mod-11 check at position 9.
func validVIN(value string) bool {
	v := strings.ToUpper(value)
	if !vinShape.MatchString(v) {
		return false
	}
	sum := 0
	for i := 0; i < 17; i++ {
		ch := v[i]
		var t int
		if ch >= '0' && ch <= '9' {
			t = atoiByte(ch)
		} else {
			mapped, ok := vinTrans[ch]
			if !ok {
				return false
			}
			t = mapped
		}
		sum += t * vinWeights[i]
	}
	check := sum % 11
	expected := strconv.Itoa(check)
	if check == 10 {
		expected = "X"
	}
	return string(v[8]) == expected
}

// namedValidators is the vocabulary a pack may reference by name. An unknown
// name is a load error, never a skipped check.
var namedValidators = map[string]func(string) bool{
	"phone":           validPhone,
	"iban":            validIBAN,
	"tckn":            validTCKN,
	"cpf":             validCPF,
	"dni":             validDNI,
	"bsn":             validBSN,
	"pesel":           validPESEL,
	"de_tax_id":       validDETaxID,
	"codice_fiscale":  validCodiceFiscale,
	"fr_nir":          validFRNIR,
	"aadhaar":         validAadhaar,
	"tfn":             validTFN,
	"cn_resident_id":  validCNResidentID,
	"jp_my_number":    validJPMyNumber,
	"us_ssn":          validSSN,
	"aba":             validABA,
	"nhs":             validNHS,
	"vin":             validVIN,
}
