package flareredact

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Structured redaction.
//
// The supported shapes are the ones json.Unmarshal produces — map[string]any,
// []any, string and scalars — plus map[string]string and []string, because Go
// code carries those everywhere. Anything else is returned unchanged: a
// redactor that reaches into arbitrary structs with reflection would silently
// skip unexported fields, which is a worse failure than an honest no-op. For a
// struct, marshal it and use RedactJSON.
//
// Everything under a sensitive key is masked whatever its type (SPEC §9):
// strings, numbers (as their decimal text), byte slices (as lowercase hex) and
// every string or number inside a map or slice at any depth. Booleans and nil
// are kept, because they are flags, not secrets.
//
// Map entries are visited in ascending key order. Go's map iteration is
// deliberately randomised, and finding order and vault placeholder numbering
// are observable, so the engine imposes an order rather than inheriting one.

// ErrTooDeep reports a value nested past the recursion limit, which in practice
// means a cyclic structure.
var ErrTooDeep = fmt.Errorf("flareredact: value nests deeper than %d levels", maxDepth)

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Redact rewrites every string reachable from value, preserving its shape.
func (p *Policy) Redact(value any) (any, error) {
	return p.redactValue(value, 0, false)
}

// redactValue walks value. hot is true under a sensitive key, where every
// string and number is replaced whole instead of being pattern matched.
func (p *Policy) redactValue(value any, depth int, hot bool) (any, error) {
	if depth > maxDepth {
		return nil, ErrTooDeep
	}
	switch typed := value.(type) {
	case nil:
		return nil, nil

	case string:
		return p.redactText(typed, hot)

	case map[string]any:
		out := make(map[string]any, len(typed))
		for _, key := range sortedKeys(typed) {
			replaced, err := p.redactValue(typed[key], depth+1, hot || p.matchKey(key))
			if err != nil {
				return nil, err
			}
			out[key] = replaced
		}
		return out, nil

	case map[string]string:
		out := make(map[string]string, len(typed))
		for _, key := range sortedKeys(typed) {
			replaced, err := p.redactText(typed[key], hot || p.matchKey(key))
			if err != nil {
				return nil, err
			}
			out[key] = replaced
		}
		return out, nil

	case []any:
		out := make([]any, len(typed))
		for i, entry := range typed {
			replaced, err := p.redactValue(entry, depth+1, hot)
			if err != nil {
				return nil, err
			}
			out[i] = replaced
		}
		return out, nil

	case []string:
		out := make([]string, len(typed))
		for i, entry := range typed {
			replaced, err := p.redactText(entry, hot)
			if err != nil {
				return nil, err
			}
			out[i] = replaced
		}
		return out, nil

	default:
		if !hot {
			return value, nil
		}
		if text, ok := sensitiveText(value); ok {
			if p.allow(text) {
				return value, nil
			}
			return p.replace(text, sensitiveKeyDetector), nil
		}
		if shaped, ok := sensitiveShape(value); ok {
			return p.redactValue(shaped, depth+1, true)
		}
		return value, nil
	}
}

// redactText masks a string whole under a sensitive key, unless the allowlist
// keeps it, and pattern matches it otherwise. That is how {"password":
// "hunter2"} is caught even though "hunter2" looks like nothing in particular.
func (p *Policy) redactText(text string, hot bool) (string, error) {
	if hot && !p.allow(text) {
		return p.replace(text, sensitiveKeyDetector), nil
	}
	return p.RedactString(text)
}

// sensitiveText is the text a number or byte slice is replaced as when it sits
// under a sensitive key: a number as its decimal text, bytes as lowercase hex.
// ok is false for every other type.
func sensitiveText(value any) (text string, ok bool) {
	switch typed := value.(type) {
	case float64:
		return jsFloat(typed, 64), true
	case float32:
		return jsFloat(float64(typed), 32), true
	case int:
		return strconv.Itoa(typed), true
	case int8:
		return strconv.FormatInt(int64(typed), 10), true
	case int16:
		return strconv.FormatInt(int64(typed), 10), true
	case int32:
		return strconv.FormatInt(int64(typed), 10), true
	case int64:
		return strconv.FormatInt(typed, 10), true
	case uint:
		return strconv.FormatUint(uint64(typed), 10), true
	case uint8:
		return strconv.FormatUint(uint64(typed), 10), true
	case uint16:
		return strconv.FormatUint(uint64(typed), 10), true
	case uint32:
		return strconv.FormatUint(uint64(typed), 10), true
	case uint64:
		return strconv.FormatUint(typed, 10), true
	case json.Number:
		return jsonNumberText(typed), true
	case []byte:
		return hex.EncodeToString(typed), true
	}
	return "", false
}

// sensitiveShape turns a value the walker does not know into one it does, for
// use under a sensitive key, where nothing may pass unmasked: the printed text
// of an error, Stringer or TextMarshaler, the value of a named string or number
// type, a []any or map[string]any for any other slice, array or map, and the
// JSON form of a struct. ok is false for what is kept there: booleans, times,
// durations, nil, and channels or functions, which hold no data.
func sensitiveShape(value any) (any, bool) {
	switch value.(type) {
	case nil, bool, time.Time, *time.Time, time.Duration:
		return nil, false
	}
	if text, ok := printedText(value); ok {
		return text, true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Bool, reflect.Chan, reflect.Func, reflect.UnsafePointer:
		return nil, false
	case reflect.String:
		return reflected.String(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return reflected.Int(), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return reflected.Uint(), true
	case reflect.Float32:
		return float32(reflected.Float()), true
	case reflect.Float64:
		return reflected.Float(), true
	case reflect.Pointer, reflect.Interface:
		if reflected.IsNil() {
			return nil, false
		}
		return reflected.Elem().Interface(), true
	case reflect.Slice, reflect.Array:
		if reflected.Kind() == reflect.Slice && reflected.IsNil() {
			return nil, false
		}
		if reflected.Type().Elem().Kind() == reflect.Uint8 {
			out := make([]byte, reflected.Len())
			reflect.Copy(reflect.ValueOf(out), reflected)
			return out, true
		}
		out := make([]any, reflected.Len())
		for i := range out {
			out[i] = reflected.Index(i).Interface()
		}
		return out, true
	case reflect.Map:
		if reflected.IsNil() {
			return nil, false
		}
		out := make(map[string]any, reflected.Len())
		iterator := reflected.MapRange()
		for iterator.Next() {
			key := iterator.Key()
			name := fmt.Sprint(key.Interface())
			if key.Kind() == reflect.String {
				name = key.String()
			}
			out[name] = iterator.Value().Interface()
		}
		return out, true
	case reflect.Struct:
		document, err := json.Marshal(value)
		if err != nil {
			return fmt.Sprintf("%+v", value), true
		}
		decoder := json.NewDecoder(bytes.NewReader(document))
		decoder.UseNumber()
		var decoded any
		if err := decoder.Decode(&decoded); err != nil {
			return fmt.Sprintf("%+v", value), true
		}
		return decoded, true
	}
	return fmt.Sprintf("%+v", value), true
}

// jsonNumberText keeps an integer literal's digits exactly and writes any other
// number the way the JavaScript engine does.
func jsonNumberText(number json.Number) string {
	literal := string(number)
	if literal == "-0" {
		return "0"
	}
	if !strings.ContainsAny(literal, ".eE") {
		return literal
	}
	value, err := number.Float64()
	if err != nil {
		return literal
	}
	return jsFloat(value, 64)
}

// jsFloat writes a floating point number as ECMAScript's Number::toString does,
// so every engine hashes and mints the same text: the shortest digits that
// round-trip, in full from 1e-6 up to 1e21 and in exponent form outside.
func jsFloat(value float64, bits int) string {
	switch {
	case math.IsNaN(value):
		return "NaN"
	case math.IsInf(value, 1):
		return "Infinity"
	case math.IsInf(value, -1):
		return "-Infinity"
	case value == 0:
		return "0"
	}
	sign := ""
	if value < 0 {
		sign, value = "-", -value
	}
	mantissa, exponent, _ := strings.Cut(strconv.FormatFloat(value, 'e', -1, bits), "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	power, _ := strconv.Atoi(exponent)
	n, k := power+1, len(digits)
	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits
	}
	out := digits[:1]
	if k > 1 {
		out += "." + digits[1:]
	}
	if n-1 >= 0 {
		return sign + out + "e+" + strconv.Itoa(n-1)
	}
	return sign + out + "e-" + strconv.Itoa(1-n)
}

// RedactJSON redacts a JSON document and returns a JSON document. This is the
// entry point for structs: marshal, redact, unmarshal.
func (p *Policy) RedactJSON(document []byte) ([]byte, error) {
	var value any
	if err := json.Unmarshal(document, &value); err != nil {
		return nil, fmt.Errorf("flareredact: input is not valid JSON: %w", err)
	}
	redacted, err := p.Redact(value)
	if err != nil {
		return nil, err
	}
	return json.Marshal(redacted)
}

// Scan lists what would be redacted anywhere in value, with paths.
func (p *Policy) Scan(value any) ([]Finding, error) {
	var findings []Finding
	err := p.scanValue(value, "", 0, "", &findings)
	return findings, err
}

// scanValue walks value. under is the sensitive key the value sits beneath, or
// empty when it is not beneath one.
func (p *Policy) scanValue(value any, path string, depth int, under string, out *[]Finding) error {
	if depth > maxDepth {
		return ErrTooDeep
	}
	child := func(key string) string {
		if under == "" && p.matchKey(key) {
			return key
		}
		return under
	}
	switch typed := value.(type) {
	case string:
		if under != "" && p.appendKeyFinding(under, typed, path, out) {
			return nil
		}
		found, err := p.ScanString(typed)
		if err != nil {
			return err
		}
		for _, finding := range found {
			finding.Path = path
			*out = append(*out, finding)
		}
		return nil

	case map[string]any:
		for _, key := range sortedKeys(typed) {
			if err := p.scanValue(typed[key], joinPath(path, key), depth+1, child(key), out); err != nil {
				return err
			}
		}
		return nil

	case map[string]string:
		for _, key := range sortedKeys(typed) {
			if err := p.scanValue(typed[key], joinPath(path, key), depth+1, child(key), out); err != nil {
				return err
			}
		}
		return nil

	case []any:
		for i, entry := range typed {
			if err := p.scanValue(entry, path+"["+strconv.Itoa(i)+"]", depth+1, under, out); err != nil {
				return err
			}
		}
		return nil

	case []string:
		for i, entry := range typed {
			if err := p.scanValue(entry, path+"["+strconv.Itoa(i)+"]", depth+1, under, out); err != nil {
				return err
			}
		}
		return nil

	default:
		if under == "" {
			return nil
		}
		if text, ok := sensitiveText(value); ok {
			p.appendKeyFinding(under, text, path, out)
			return nil
		}
		if shaped, ok := sensitiveShape(value); ok {
			return p.scanValue(shaped, path, depth+1, under, out)
		}
		return nil
	}
}

// appendKeyFinding reports value as sitting under the sensitive key, unless the
// allowlist keeps it, and says whether it did.
func (p *Policy) appendKeyFinding(key, value, path string, out *[]Finding) bool {
	if p.allow(value) {
		return false
	}
	finding := Finding{
		Detector:   sensitiveKeyDetector.ID,
		Label:      sensitiveKeyDetector.Label,
		Why:        `Value stored under a sensitive field name ("` + key + `").`,
		Risk:       RiskCritical,
		Confidence: 0.98,
		Start:      -1,
		End:        -1,
		Line:       -1,
		Column:     -1,
		Path:       path,
	}
	if p.options.IncludeValues {
		finding.Value = value
	}
	*out = append(*out, finding)
	return true
}

func joinPath(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "." + name
}

// IsClean reports whether nothing in value would be redacted.
func (p *Policy) IsClean(value any) (bool, error) {
	findings, err := p.Scan(value)
	return len(findings) == 0, err
}

// Summarise counts findings by detector and by risk. The result contains no
// matched values and is safe to log.
func (p *Policy) Summarise(value any) (Summary, error) {
	findings, err := p.Scan(value)
	if err != nil {
		return Summary{}, err
	}
	summary := Summary{ByDetector: map[string]int{}, ByRisk: map[string]int{}, Total: len(findings)}
	for _, finding := range findings {
		summary.ByDetector[finding.Detector]++
		summary.ByRisk[finding.Risk]++
	}
	return summary, nil
}

// ---------------------------------------------------------------------------
// One-shot helpers
// ---------------------------------------------------------------------------
//
// Each of these compiles a policy and throws it away. That is fine for a script
// and wasteful in a request path — compile once with Compile and reuse it.

// RedactString redacts a single string with the given options.
func RedactString(text string, options Options) (string, error) {
	policy, err := Compile(options)
	if err != nil {
		return "", err
	}
	return policy.RedactString(text)
}

// Redact redacts any supported value with the given options.
func Redact(value any, options Options) (any, error) {
	policy, err := Compile(options)
	if err != nil {
		return nil, err
	}
	return policy.Redact(value)
}

// Scan lists what would be redacted, with the given options.
func Scan(value any, options Options) ([]Finding, error) {
	policy, err := Compile(options)
	if err != nil {
		return nil, err
	}
	return policy.Scan(value)
}
