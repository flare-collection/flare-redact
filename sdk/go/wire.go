package flareredact

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Translation between Go options and the JSON wire format used by the gateway
// and the conformance corpus.
//
// The wire format is the JavaScript library's option set (camelCase), so one
// document configures every engine. Keeping the mapping in one small file means
// the Go API can stay idiomatic without the two drifting.

var wireOptionNames = map[string]struct{}{
	"only": {}, "enable": {}, "disable": {}, "mode": {}, "mask": {},
	"transformSecret": {}, "redactKeys": {}, "allow": {}, "terms": {},
	"termsCaseSensitive": {}, "minConfidence": {}, "refineConfidence": {},
	"includeValues": {}, "limits": {},
}

func wireStrings(value any, field string) ([]string, error) {
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("flareredact: %q must be an array of strings", field)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("flareredact: %q must be an array of strings", field)
		}
		out = append(out, text)
	}
	return out, nil
}

func wireTerms(value any) ([]Term, error) {
	switch typed := value.(type) {
	case []any:
		out := make([]Term, 0, len(typed))
		for _, item := range typed {
			switch entry := item.(type) {
			case string:
				out = append(out, Term{Term: entry})
			case map[string]any:
				term, _ := entry["term"].(string)
				replace, _ := entry["replace"].(string)
				out = append(out, Term{Term: term, Replace: replace})
			default:
				return nil, fmt.Errorf("flareredact: %q entries must be strings or objects", "terms")
			}
		}
		return out, nil
	case map[string]any:
		// A {term: replacement} object. Sort so the detector alternation is
		// built in the same order on every run.
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out := make([]Term, 0, len(keys))
		for _, key := range keys {
			replace, _ := typed[key].(string)
			out = append(out, Term{Term: key, Replace: replace})
		}
		return out, nil
	}
	return nil, fmt.Errorf("flareredact: %q must be an array or an object", "terms")
}

// OptionsFromWire builds Options from the JSON wire representation.
func OptionsFromWire(payload map[string]any) (Options, error) {
	var options Options
	for key := range payload {
		if _, ok := wireOptionNames[key]; !ok {
			return options, fmt.Errorf("flareredact: unknown option %q", key)
		}
	}

	var err error
	if value, ok := payload["only"]; ok {
		if options.Only, err = wireStrings(value, "only"); err != nil {
			return options, err
		}
	}
	if value, ok := payload["enable"]; ok {
		if options.Enable, err = wireStrings(value, "enable"); err != nil {
			return options, err
		}
	}
	if value, ok := payload["disable"]; ok {
		if options.Disable, err = wireStrings(value, "disable"); err != nil {
			return options, err
		}
	}
	if value, ok := payload["allow"]; ok {
		if options.Allow, err = wireStrings(value, "allow"); err != nil {
			return options, err
		}
	}
	if value, ok := payload["mode"].(string); ok {
		options.Mode = Mode(value)
	}
	if value, ok := payload["mask"].(string); ok {
		options.Mask = value
	}
	if value, ok := payload["transformSecret"].(string); ok {
		options.TransformSecret = value
	}
	if value, ok := payload["redactKeys"]; ok {
		switch typed := value.(type) {
		case bool:
			options.DisableKeyRedaction = !typed
		default:
			if options.KeyNames, err = wireStrings(value, "redactKeys"); err != nil {
				return options, err
			}
		}
	}
	if value, ok := payload["terms"]; ok {
		if options.Terms, err = wireTerms(value); err != nil {
			return options, err
		}
	}
	if value, ok := payload["termsCaseSensitive"].(bool); ok {
		options.TermsCaseSensitive = value
	}
	if value, ok := payload["minConfidence"].(float64); ok {
		options.MinConfidence = value
	}
	if value, ok := payload["refineConfidence"].(bool); ok {
		options.RefineConfidence = value
	}
	if value, ok := payload["includeValues"].(bool); ok {
		options.IncludeValues = value
	}
	if limits, ok := payload["limits"].(map[string]any); ok {
		if value, ok := limits["maxInputLength"].(float64); ok {
			options.MaxInputLength = int(value)
		}
		if value, ok := limits["maxFindings"].(float64); ok {
			options.MaxFindings = int(value)
		}
	}
	return options, nil
}

// OptionsToWire serialises the options a gateway will accept, omitting defaults.
//
// TransformSecret is deliberately not included: a keyed transform's whole value
// is that the key stays where it was configured, so it is set on the gateway
// rather than shipped with every request.
func OptionsToWire(options Options) map[string]any {
	wire := map[string]any{}
	if len(options.Only) > 0 {
		wire["only"] = options.Only
	}
	if len(options.Enable) > 0 {
		wire["enable"] = options.Enable
	}
	if len(options.Disable) > 0 {
		wire["disable"] = options.Disable
	}
	if len(options.Allow) > 0 {
		wire["allow"] = options.Allow
	}
	if options.Mode != "" && options.Mode != ModeMask {
		wire["mode"] = string(options.Mode)
	}
	if options.Mask != "" {
		wire["mask"] = options.Mask
	}
	if options.DisableKeyRedaction {
		wire["redactKeys"] = false
	} else if len(options.KeyNames) > 0 {
		wire["redactKeys"] = options.KeyNames
	}
	if len(options.Terms) > 0 {
		terms := make([]any, 0, len(options.Terms))
		for _, term := range options.Terms {
			if term.Replace == "" {
				terms = append(terms, term.Term)
				continue
			}
			terms = append(terms, map[string]any{"term": term.Term, "replace": term.Replace})
		}
		wire["terms"] = terms
	}
	if options.TermsCaseSensitive {
		wire["termsCaseSensitive"] = true
	}
	if options.MinConfidence > 0 {
		wire["minConfidence"] = options.MinConfidence
	}
	if options.RefineConfidence {
		wire["refineConfidence"] = true
	}
	if options.IncludeValues {
		wire["includeValues"] = true
	}
	limits := map[string]any{}
	if options.MaxInputLength > 0 {
		limits["maxInputLength"] = options.MaxInputLength
	}
	if options.MaxFindings > 0 {
		limits["maxFindings"] = options.MaxFindings
	}
	if len(limits) > 0 {
		wire["limits"] = limits
	}
	return wire
}

// MarshalWire is OptionsToWire followed by JSON encoding.
func MarshalWire(options Options) ([]byte, error) { return json.Marshal(OptionsToWire(options)) }
