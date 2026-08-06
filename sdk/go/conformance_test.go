package flareredact

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The Go engine must agree with the JavaScript, Python and Rust engines, case
// for case. See spec/SPEC.md §13 — this file is the Go half of that promise.

type conformanceCase struct {
	Name    string         `json:"name"`
	Input   any            `json:"input"`
	Options map[string]any `json:"options"`
	Checks  []string       `json:"checks"`
	Vault   *struct {
		PlaceholderStyle string `json:"placeholderStyle"`
	} `json:"vault"`
}

type conformanceCorpus struct {
	Cases []conformanceCase `json:"cases"`
}

func specPath(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "spec"}, parts...)...)
}

func readJSON(t *testing.T, path string, into any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatalf("cannot parse %s: %v", path, err)
	}
}

func round6(value float64) float64 { return math.Round(value*1e6) / 1e6 }

func normaliseFinding(finding Finding) map[string]any {
	out := map[string]any{
		"detector":   finding.Detector,
		"risk":       finding.Risk,
		"confidence": round6(finding.Confidence),
	}
	if finding.Start >= 0 {
		out["start"] = finding.Start
		out["end"] = finding.End
		out["line"] = finding.Line
		out["column"] = finding.Column
	}
	if finding.Path != "" {
		out["path"] = finding.Path
	}
	if finding.Value != "" {
		out["value"] = finding.Value
	}
	return out
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func runConformanceCase(t *testing.T, testCase conformanceCase) map[string]any {
	t.Helper()
	options, err := OptionsFromWire(testCase.Options)
	if err != nil {
		t.Fatalf("%s: %v", testCase.Name, err)
	}
	checks := testCase.Checks
	if len(checks) == 0 {
		checks = []string{"redact", "scan"}
	}

	result := map[string]any{}

	if contains(checks, "redact") {
		policy, err := Compile(options)
		if err != nil {
			t.Fatalf("%s: %v", testCase.Name, err)
		}
		redacted, err := policy.Redact(testCase.Input)
		if err != nil {
			t.Fatalf("%s: %v", testCase.Name, err)
		}
		result["redact"] = redacted
	}

	if contains(checks, "scan") {
		policy, err := Compile(options)
		if err != nil {
			t.Fatalf("%s: %v", testCase.Name, err)
		}
		findings, err := policy.Scan(testCase.Input)
		if err != nil {
			t.Fatalf("%s: %v", testCase.Name, err)
		}
		normalised := make([]map[string]any, 0, len(findings))
		for _, finding := range findings {
			normalised = append(normalised, normaliseFinding(finding))
		}
		result["findings"] = normalised
	}

	if contains(checks, "vault") {
		style := PlaceholderOpaque
		if testCase.Vault != nil && testCase.Vault.PlaceholderStyle == "readable" {
			style = PlaceholderReadable
		}
		vault, err := NewVault(options, VaultOptions{Style: style})
		if err != nil {
			t.Fatalf("%s: %v", testCase.Name, err)
		}
		redacted, err := vault.Redact(testCase.Input)
		if err != nil {
			t.Fatalf("%s: %v", testCase.Name, err)
		}
		entries := make([][]string, 0, vault.Size())
		for _, entry := range vault.Entries() {
			entries = append(entries, []string{entry[0], entry[1]})
		}
		result["vault"] = map[string]any{
			"redacted": redacted,
			"restored": vault.Restore(redacted),
			"entries":  entries,
		}
	}

	return result
}

// throughJSON puts a value through an encode/decode round trip so both sides of
// a comparison use the same concrete types (float64 for every number, and so on).
func throughJSON(t *testing.T, value any) any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("cannot encode result: %v", err)
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("cannot decode result: %v", err)
	}
	return decoded
}

func TestConformanceCorpus(t *testing.T) {
	var corpus conformanceCorpus
	readJSON(t, specPath("conformance", "cases.json"), &corpus)
	expected := map[string]any{}
	readJSON(t, specPath("conformance", "expected.json"), &expected)

	if len(corpus.Cases) != len(expected) {
		t.Fatalf("cases.json has %d cases but expected.json has %d; regenerate with npm run spec:conformance",
			len(corpus.Cases), len(expected))
	}

	for _, testCase := range corpus.Cases {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			want, ok := expected[testCase.Name]
			if !ok {
				t.Fatalf("no expectation for %q", testCase.Name)
			}
			got := throughJSON(t, runConformanceCase(t, testCase))
			if !reflect.DeepEqual(got, want) {
				gotJSON, _ := json.MarshalIndent(got, "", "  ")
				wantJSON, _ := json.MarshalIndent(want, "", "  ")
				t.Errorf("mismatch\n got: %s\nwant: %s", gotJSON, wantJSON)
			}
		})
	}
}

func TestVendoredPackMatchesSpecification(t *testing.T) {
	var canonical, vendored any
	readJSON(t, specPath("detectors.json"), &canonical)
	readJSON(t, "detectors.json", &vendored)
	if !reflect.DeepEqual(canonical, vendored) {
		t.Fatal("the vendored pack has drifted from spec/detectors.json; run `npm run spec:sync`")
	}
}
