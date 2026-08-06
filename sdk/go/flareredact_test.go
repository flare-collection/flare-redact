package flareredact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mustCompile(t *testing.T, options Options) *Policy {
	t.Helper()
	policy, err := Compile(options)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return policy
}

func mustRedact(t *testing.T, policy *Policy, text string) string {
	t.Helper()
	out, err := policy.RedactString(text)
	if err != nil {
		t.Fatalf("RedactString: %v", err)
	}
	return out
}

func TestRedactString(t *testing.T) {
	policy := mustCompile(t, Options{})
	cases := []struct{ in, want string }{
		{"contact ada@example.com", "contact a***@***"},
		{"AKIAIOSFODNN7EXAMPLE", "AKIA***"},
		{"nothing sensitive here", "nothing sensitive here"},
		{"password=hunter2000", "password=***"},
		{"card 4111 1111 1111 1111", "card **** **** **** 1111"},
	}
	for _, testCase := range cases {
		if got := mustRedact(t, policy, testCase.in); got != testCase.want {
			t.Errorf("RedactString(%q) = %q, want %q", testCase.in, got, testCase.want)
		}
	}
}

func TestRedactStructured(t *testing.T) {
	policy := mustCompile(t, Options{})
	input := map[string]any{
		"password": "hunter2",
		"count":    7,
		"user":     map[string]any{"email": "ada@example.com"},
		"list":     []any{"grace@example.org", true, nil},
	}
	redacted, err := policy.Redact(input)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	out := redacted.(map[string]any)
	if out["password"] != "***" {
		t.Errorf("sensitive key not redacted: %v", out["password"])
	}
	if out["count"] != 7 {
		t.Errorf("scalars must survive unchanged, got %v", out["count"])
	}
	if got := out["user"].(map[string]any)["email"]; got != "a***@***" {
		t.Errorf("nested email = %v", got)
	}
	if got := out["list"].([]any)[0]; got != "g***@***" {
		t.Errorf("list email = %v", got)
	}
	if input["password"] != "hunter2" {
		t.Error("Redact must not mutate its input")
	}
}

func TestRedactJSON(t *testing.T) {
	policy := mustCompile(t, Options{})
	out, err := policy.RedactJSON([]byte(`{"email":"ada@example.com","n":1}`))
	if err != nil {
		t.Fatalf("RedactJSON: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if parsed["email"] != "a***@***" {
		t.Errorf("email = %v", parsed["email"])
	}
}

func TestModes(t *testing.T) {
	label := mustCompile(t, Options{Mode: ModeLabel})
	if got := mustRedact(t, label, "ada@example.com"); got != "[REDACTED:email]" {
		t.Errorf("label mode = %q", got)
	}

	hashed := mustCompile(t, Options{Mode: ModeHash, TransformSecret: "k"})
	first := mustRedact(t, hashed, "ada@example.com")
	second := mustRedact(t, hashed, "ada@example.com")
	if first != second {
		t.Error("hash mode must be deterministic")
	}
	if !strings.HasPrefix(first, "email_") {
		t.Errorf("hash mode = %q", first)
	}

	if _, err := Compile(Options{Mode: ModeHash}); !errors.Is(err, ErrMissingSecret) {
		t.Errorf("keyed mode without a secret must fail, got %v", err)
	}
	if _, err := Compile(Options{Mode: "encrypt"}); err == nil {
		t.Error("an unknown mode must be rejected")
	}
}

func TestSurrogateCardStaysValid(t *testing.T) {
	policy := mustCompile(t, Options{Mode: ModeSurrogate, TransformSecret: "k"})
	got := mustRedact(t, policy, "4111 1111 1111 1111")
	if got == "4111 1111 1111 1111" {
		t.Fatal("the card was not replaced")
	}
	if !Luhn(got, 13, 19) {
		t.Errorf("surrogate card %q does not pass Luhn", got)
	}
}

func TestSelectionAndTerms(t *testing.T) {
	only := mustCompile(t, Options{Only: []string{"email"}})
	if got := mustRedact(t, only, "ada@example.com AKIAIOSFODNN7EXAMPLE"); got != "a***@*** AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("only = %q", got)
	}

	terms := mustCompile(t, Options{Terms: []Term{{Term: "Bluebird", Replace: "[PROJECT]"}}})
	if got := mustRedact(t, terms, "Bluebirds follow Bluebird"); got != "Bluebirds follow [PROJECT]" {
		t.Errorf("terms = %q", got)
	}
}

func TestLimitsFailClosed(t *testing.T) {
	policy := mustCompile(t, Options{MaxInputLength: 8})
	if _, err := policy.RedactString(strings.Repeat("x", 64)); err == nil {
		t.Fatal("oversized input must be an error")
	} else {
		var limit *LimitError
		if !errors.As(err, &limit) {
			t.Errorf("want *LimitError, got %T", err)
		}
	}
}

func TestScanReportsLocations(t *testing.T) {
	policy := mustCompile(t, Options{})
	findings, err := policy.Scan(map[string]any{"note": "line one\nwrite to ada@example.com"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	finding := findings[0]
	if finding.Path != "note" || finding.Line != 2 || finding.Column != 10 {
		t.Errorf("location = %s %d:%d", finding.Path, finding.Line, finding.Column)
	}
	if finding.Value != "" {
		t.Error("findings must not carry values unless IncludeValues is set")
	}
}

func TestSummarise(t *testing.T) {
	policy := mustCompile(t, Options{})
	summary, err := policy.Summarise("ada@example.com AKIAIOSFODNN7EXAMPLE")
	if err != nil {
		t.Fatalf("Summarise: %v", err)
	}
	if summary.Total != 2 || summary.ByDetector["email"] != 1 || summary.ByRisk["critical"] != 1 {
		t.Errorf("summary = %+v", summary)
	}
}

func TestVaultRoundTrip(t *testing.T) {
	vault, err := NewVault(Options{}, VaultOptions{Style: PlaceholderReadable})
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	redacted, err := vault.RedactString("mail ada@example.com and ada@example.com")
	if err != nil {
		t.Fatalf("RedactString: %v", err)
	}
	if redacted != "mail [EMAIL_1] and [EMAIL_1]" {
		t.Errorf("redacted = %q", redacted)
	}
	if got := vault.RestoreString(redacted); got != "mail ada@example.com and ada@example.com" {
		t.Errorf("restored = %q", got)
	}
	if vault.Size() != 1 {
		t.Errorf("size = %d, want 1", vault.Size())
	}
}

func TestOpaquePlaceholdersAreUnpredictable(t *testing.T) {
	first, _ := NewVault(Options{}, VaultOptions{})
	second, _ := NewVault(Options{}, VaultOptions{})
	a, _ := first.RedactString("ada@example.com")
	b, _ := second.RedactString("ada@example.com")
	if a == b {
		t.Error("opaque placeholders must not repeat across vaults")
	}
	if !strings.HasPrefix(a, "[FR_EMAIL_") {
		t.Errorf("placeholder = %q", a)
	}
}

func TestStreamRestorerAcrossChunks(t *testing.T) {
	vault, _ := NewVault(Options{}, VaultOptions{Style: PlaceholderReadable})
	if _, err := vault.RedactString("ada@example.com"); err != nil {
		t.Fatalf("RedactString: %v", err)
	}
	restorer := vault.Stream()
	out := restorer.Push("reply to [EMA")
	out += restorer.Push("IL_1] soon")
	out += restorer.Flush()
	if out != "reply to ada@example.com soon" {
		t.Errorf("streamed restore = %q", out)
	}
}

func TestSlogHandlerRedactsRecords(t *testing.T) {
	var buffer bytes.Buffer
	policy := mustCompile(t, Options{})
	logger := slog.New(NewSlogHandler(slog.NewJSONHandler(&buffer, nil), policy))

	logger.Info("charge failed for ada@example.com", "password", "hunter2", "ok", true)

	line := buffer.String()
	if strings.Contains(line, "ada@example.com") || strings.Contains(line, "hunter2") {
		t.Errorf("sensitive data reached the log: %s", line)
	}
	if !strings.Contains(line, "a***@***") || !strings.Contains(line, `"ok":true`) {
		t.Errorf("log line lost information: %s", line)
	}
}

func TestTransportRedactsOnlyNamedHosts(t *testing.T) {
	var received string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	policy := mustCompile(t, Options{})
	client := &http.Client{Transport: &Transport{Policy: policy, Hosts: []string{"127.0.0.1"}}}

	response, err := client.Post(upstream.URL, "application/json", strings.NewReader(`{"email":"ada@example.com"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	response.Body.Close()
	if strings.Contains(received, "ada@example.com") {
		t.Errorf("the address reached the upstream: %s", received)
	}

	other := &http.Client{Transport: &Transport{Policy: policy, Hosts: []string{"example.invalid"}}}
	response, err = other.Post(upstream.URL, "application/json", strings.NewReader(`{"email":"ada@example.com"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	response.Body.Close()
	if !strings.Contains(received, "ada@example.com") {
		t.Errorf("an unlisted host must pass through untouched: %s", received)
	}
}

func TestGatewayClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":"ERR_UNAUTHORIZED","message":"nope"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output":"a***@***"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, ClientOptions{Token: "s3cret"})
	out, err := client.Redact(context.Background(), "ada@example.com", Options{Enable: []string{"pii"}})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if out != "a***@***" {
		t.Errorf("output = %v", out)
	}

	anonymous := NewClient(server.URL, ClientOptions{})
	if _, err := anonymous.Redact(context.Background(), "x", Options{}); err == nil {
		t.Fatal("an unauthenticated call must fail")
	} else {
		var gatewayErr *GatewayError
		if !errors.As(err, &gatewayErr) || gatewayErr.Status != http.StatusUnauthorized {
			t.Errorf("want a 401 GatewayError, got %v", err)
		}
	}
}

func TestPackRejectsNonPortablePatterns(t *testing.T) {
	// A construct whose meaning differs between engines must not load at all.
	// Loading it and quietly skipping the check is how a redactor leaks.
	const template = `{"spec":"FRS-1","id":"t","version":"1","detectors":[` +
		`{"id":"a","label":"A","why":"w.","pattern":%q,"mask":{"type":"fixed","text":"*"},` +
		`"default":true,"risk":"low","confidence":0.5}]}`
	for _, pattern := range []string{`TICKET-(?!0)[0-9]{4}`, `\bTICKET-[0-9]{4}`, `TICKET-\d+`, `^TICKET-[0-9]{4}`, `[0-9]*`} {
		if _, err := LoadPack([]byte(fmt.Sprintf(template, pattern))); err == nil {
			t.Errorf("pattern %q should not load", pattern)
		}
	}
	if _, err := LoadPack([]byte(`{"spec":"FRS-2","id":"t","version":"1","detectors":[]}`)); err == nil {
		t.Error("an unknown spec revision should not load")
	}
}
