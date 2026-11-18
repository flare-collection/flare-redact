package flareredact

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// Restoring into JSON text: tool-call arguments and JSON-mode output stay valid
// JSON with the same structure, whatever the restored value contains.

// awkward holds a quote, a backslash and control characters.
const awkward = "Q\"uo\\te\nline\ttab\x01end"

// quotedURL has credentials holding a quoted fragment; a default detector
// captures it whole.
const quotedURL = `https://user:pa","extra":true,"note":"x@example.com/pay`

var placeholderPattern = regexp.MustCompile(`\[FR_[A-Z_]+_[0-9a-f]{24}\]`)

func awkwardVault(t *testing.T) (*Vault, string) {
	t.Helper()
	vault, err := NewVault(Options{Terms: []Term{{Term: awkward}}}, VaultOptions{})
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	redacted, err := vault.RedactString("say " + awkward)
	if err != nil {
		t.Fatalf("RedactString: %v", err)
	}
	return vault, strings.TrimPrefix(redacted, "say ")
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	out, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func decode(t *testing.T, text string) any {
	t.Helper()
	var out any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, text)
	}
	return out
}

func TestRestoreEscapesOriginalsInsideJSONDocuments(t *testing.T) {
	vault, placeholder := awkwardVault(t)
	args := mustJSON(t, map[string]any{"n": 1, "text": placeholder})
	want := map[string]any{"n": float64(1), "text": awkward}

	if got := decode(t, vault.RestoreString(args)); !reflect.DeepEqual(got, want) {
		t.Errorf("RestoreString = %v", got)
	}
	restored := vault.Restore(map[string]any{"args": args}).(map[string]any)
	if got := decode(t, restored["args"].(string)); !reflect.DeepEqual(got, want) {
		t.Errorf("Restore leaf = %v", got)
	}
	if got := decode(t, BuildJSONAwareRestorer(vault.Entries())("\n [\""+placeholder+"\"]")); !reflect.DeepEqual(got, []any{awkward}) {
		t.Errorf("BuildJSONAwareRestorer = %v", got)
	}
	session := &Session{vault: vault}
	if got := decode(t, session.Restore(args).(string)); !reflect.DeepEqual(got, want) {
		t.Errorf("Session.Restore = %v", got)
	}
}

func TestRestoreLeavesOtherStringsVerbatim(t *testing.T) {
	vault, placeholder := awkwardVault(t)
	cases := map[string]string{
		"say " + placeholder:           "say " + awkward,
		"{ not json " + placeholder:    "{ not json " + awkward,
		`"` + placeholder + `"`:        `"` + awkward + `"`,
		"[" + placeholder + " is fine": "[" + awkward + " is fine",
	}
	for input, want := range cases {
		if got := vault.RestoreString(input); got != want {
			t.Errorf("RestoreString(%q) = %q, want %q", input, got, want)
		}
	}
	got := vault.Restore(map[string]any{"input": map[string]any{"text": placeholder}})
	if !reflect.DeepEqual(got, map[string]any{"input": map[string]any{"text": awkward}}) {
		t.Errorf("object leaf = %v", got)
	}
}

func TestRestoredValueKeepsTheStructureOfJSONText(t *testing.T) {
	vault, err := NewVault(Options{}, VaultOptions{})
	if err != nil {
		t.Fatal(err)
	}
	redacted, err := vault.RedactString("call back " + quotedURL)
	if err != nil {
		t.Fatal(err)
	}
	placeholder := placeholderPattern.FindString(redacted)
	if placeholder == "" {
		t.Fatalf("no placeholder in %q", redacted)
	}
	args := `{"amount":10,"callback":"` + placeholder + `"}`
	parsed := decode(t, vault.RestoreString(args)).(map[string]any)
	if parsed["amount"] != float64(10) || len(parsed) != 2 {
		t.Fatalf("structure changed: %v", parsed)
	}
	if !strings.HasPrefix(quotedURL, parsed["callback"].(string)) {
		t.Errorf("callback = %q", parsed["callback"])
	}
}

func TestJSONStreamRestorerEscapesAcrossChunkSplits(t *testing.T) {
	vault, placeholder := awkwardVault(t)
	text := mustJSON(t, map[string]any{"note": placeholder})
	at := strings.Index(text, placeholder) + 6
	for name, restorer := range map[string]*StreamRestorer{
		"Vault.StreamJSON":      vault.StreamJSON(),
		"Session.StreamJSON":    (&Session{vault: vault}).StreamJSON(),
		"NewJSONStreamRestorer": NewJSONStreamRestorer(vault.Entries()),
	} {
		out := restorer.Push(text[:at]) + restorer.Push(text[at:]) + restorer.Flush()
		if got := decode(t, out); !reflect.DeepEqual(got, map[string]any{"note": awkward}) {
			t.Errorf("%s = %v", name, got)
		}
	}
	plain := vault.Stream()
	if got := plain.Push("<"+placeholder+">") + plain.Flush(); got != "<"+awkward+">" {
		t.Errorf("plain stream = %q", got)
	}
}

func TestEscapeEntriesForJSON(t *testing.T) {
	got := EscapeEntriesForJSON([][2]string{{"[A_1]", "a\"b\\c\nd\x1f é"}})
	want := [][2]string{{"[A_1]", `a\"b\\c\nd\u001f` + " é"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("EscapeEntriesForJSON = %q", got)
	}
}

func TestIsJSONDocument(t *testing.T) {
	for _, text := range []string{" \n{\"a\": [1]}\t", "[]"} {
		if !IsJSONDocument(text) {
			t.Errorf("IsJSONDocument(%q) = false", text)
		}
	}
	for _, text := range []string{`"text"`, "42", "{ not json", "[NaN]", " {}", ""} {
		if IsJSONDocument(text) {
			t.Errorf("IsJSONDocument(%q) = true", text)
		}
	}
}
