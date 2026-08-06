package flareredact

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
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
	return p.redactValue(value, 0)
}

func (p *Policy) redactValue(value any, depth int) (any, error) {
	if depth > maxDepth {
		return nil, ErrTooDeep
	}
	switch typed := value.(type) {
	case nil:
		return nil, nil

	case string:
		return p.RedactString(typed)

	case map[string]any:
		out := make(map[string]any, len(typed))
		for _, key := range sortedKeys(typed) {
			entry := typed[key]
			if text, ok := entry.(string); ok {
				replaced, err := p.redactField(key, text)
				if err != nil {
					return nil, err
				}
				out[key] = replaced
				continue
			}
			replaced, err := p.redactValue(entry, depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = replaced
		}
		return out, nil

	case map[string]string:
		out := make(map[string]string, len(typed))
		for _, key := range sortedKeys(typed) {
			replaced, err := p.redactField(key, typed[key])
			if err != nil {
				return nil, err
			}
			out[key] = replaced
		}
		return out, nil

	case []any:
		out := make([]any, len(typed))
		for i, entry := range typed {
			replaced, err := p.redactValue(entry, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = replaced
		}
		return out, nil

	case []string:
		out := make([]string, len(typed))
		for i, entry := range typed {
			replaced, err := p.RedactString(entry)
			if err != nil {
				return nil, err
			}
			out[i] = replaced
		}
		return out, nil

	default:
		return value, nil
	}
}

// redactField applies the "sensitive by field name" rule before falling back to
// pattern matching, so {"password": "hunter2"} is caught even though "hunter2"
// looks like nothing in particular.
func (p *Policy) redactField(key, value string) (string, error) {
	if p.matchKey(key) && !p.allow(value) {
		return p.replace(value, sensitiveKeyDetector), nil
	}
	return p.RedactString(value)
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
	err := p.scanValue(value, "", 0, &findings)
	return findings, err
}

func (p *Policy) scanValue(value any, path string, depth int, out *[]Finding) error {
	if depth > maxDepth {
		return ErrTooDeep
	}
	switch typed := value.(type) {
	case string:
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
			child := joinPath(path, key)
			if text, ok := typed[key].(string); ok {
				if p.appendKeyFinding(key, text, child, out) {
					continue
				}
			}
			if err := p.scanValue(typed[key], child, depth+1, out); err != nil {
				return err
			}
		}
		return nil

	case map[string]string:
		for _, key := range sortedKeys(typed) {
			child := joinPath(path, key)
			if p.appendKeyFinding(key, typed[key], child, out) {
				continue
			}
			if err := p.scanValue(typed[key], child, depth+1, out); err != nil {
				return err
			}
		}
		return nil

	case []any:
		for i, entry := range typed {
			if err := p.scanValue(entry, path+"["+strconv.Itoa(i)+"]", depth+1, out); err != nil {
				return err
			}
		}
		return nil

	case []string:
		for i, entry := range typed {
			if err := p.scanValue(entry, path+"["+strconv.Itoa(i)+"]", depth+1, out); err != nil {
				return err
			}
		}
		return nil

	default:
		return nil
	}
}

func (p *Policy) appendKeyFinding(key, value, path string, out *[]Finding) bool {
	if !p.matchKey(key) || p.allow(value) {
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
