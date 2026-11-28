package flareredact

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

// A value under a sensitive key is masked whatever its type (SPEC §9):
// numbers, byte slices and every string or number inside a map or slice at
// any depth. Booleans and nil are kept.

func TestSensitiveKeyMasksNumbersAndContainers(t *testing.T) {
	policy := mustCompile(t, Options{})
	got, err := policy.Redact(map[string]any{
		"cvv":         123,
		"pin":         int64(1234),
		"amount":      1000,
		"cookie":      map[string]any{"name": "connect.sid", "value": "s%3A_SID_abc"},
		"password":    []any{"hunter2", []any{"letmein", 7.5}},
		"credentials": map[string]string{"user": "ada"},
		"api_key":     []string{"k1", "k2"},
		"hasPassword": true,
		"token":       nil,
		"secret":      false,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"cvv":         "***",
		"pin":         "***",
		"amount":      1000,
		"cookie":      map[string]any{"name": "***", "value": "***"},
		"password":    []any{"***", []any{"***", "***"}},
		"credentials": map[string]string{"user": "***"},
		"api_key":     []string{"***", "***"},
		"hasPassword": true,
		"token":       nil,
		"secret":      false,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
}

func TestSensitiveKeyReplacesNumbersAndBytesAsText(t *testing.T) {
	hash := mustCompile(t, Options{Mode: ModeHash, TransformSecret: "k"})
	asText, _ := hash.Redact(map[string]any{"pin": "1234", "secret": "0102ff"})
	asValue, _ := hash.Redact(map[string]any{"pin": json.Number("1234"), "secret": []byte{1, 2, 255}})
	if !reflect.DeepEqual(asText, asValue) {
		t.Fatalf("a number or bytes must hash as its text: %v vs %v", asText, asValue)
	}
	data := []byte{9}
	out, _ := mustCompile(t, Options{}).Redact(map[string]any{"data": data})
	if got := out.(map[string]any)["data"]; !reflect.DeepEqual(got, data) {
		t.Fatalf("bytes elsewhere must be kept, got %v", got)
	}
	allowed, _ := mustCompile(t, Options{Allow: []string{"1234"}}).Redact(map[string]any{"pin": 1234})
	if got := allowed.(map[string]any)["pin"]; got != 1234 {
		t.Fatalf("an allowlisted number must be kept, got %v", got)
	}
}

func TestNumberTextMatchesECMAScript(t *testing.T) {
	cases := map[float64]string{
		1.5: "1.5", 0.1: "0.1", 1e-7: "1e-7", 1.2e-5: "0.000012", 1e21: "1e+21", 1.5e21: "1.5e+21",
		1e16: "10000000000000000", 100: "100", 123456789012345680000: "123456789012345680000",
		0.30000000000000004: "0.30000000000000004", 5e-324: "5e-324", -42.25: "-42.25",
		math.Copysign(0, -1): "0", math.Inf(-1): "-Infinity",
	}
	for value, want := range cases {
		if got := jsFloat(value, 64); got != want {
			t.Errorf("jsFloat(%v) = %q, want %q", value, got, want)
		}
	}
	if got := jsFloat(math.NaN(), 64); got != "NaN" {
		t.Errorf("jsFloat(NaN) = %q", got)
	}
	if got, _ := sensitiveText(float32(1.1)); got != "1.1" {
		t.Errorf("float32 1.1 = %q", got)
	}
	for literal, want := range map[string]string{"12345678901234567890": "12345678901234567890", "-0": "0", "100.0": "100", "1E3": "1000"} {
		if got := jsonNumberText(json.Number(literal)); got != want {
			t.Errorf("json.Number(%s) = %q, want %q", literal, got, want)
		}
	}
}

func TestScanReportsEveryValueUnderASensitiveKey(t *testing.T) {
	policy := mustCompile(t, Options{IncludeValues: true})
	findings, err := policy.Scan(map[string]any{
		"cvv":    123,
		"cookie": map[string]any{"name": "sid", "value": "abc", "secure": true},
		"ok":     1,
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, finding := range findings {
		got = append(got, finding.Detector+" "+finding.Path+" "+finding.Value)
	}
	want := []string{"sensitive_key cookie.name sid", "sensitive_key cookie.value abc", "sensitive_key cvv 123"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestVaultMintsAndRestoresSensitiveValues(t *testing.T) {
	vault, err := NewVault(Options{}, VaultOptions{Style: PlaceholderReadable})
	if err != nil {
		t.Fatal(err)
	}
	out, err := vault.Redact(map[string]any{"otp": 482913, "cookie": map[string]any{"value": "abc"}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"otp": "[SENSITIVE_KEY_2]", "cookie": map[string]any{"value": "[SENSITIVE_KEY_1]"}}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("got %#v", out)
	}
	restored := vault.Restore(out)
	if !reflect.DeepEqual(restored, map[string]any{"otp": "482913", "cookie": map[string]any{"value": "abc"}}) {
		t.Fatalf("restored %#v", restored)
	}
}

func TestSlogHandlerMasksNumbersAndGroupsUnderSensitiveKeys(t *testing.T) {
	var buffer bytes.Buffer
	logger := slog.New(NewSlogHandler(slog.NewJSONHandler(&buffer, nil), mustCompile(t, Options{})))
	logger.Info("charge",
		"cvv", 123,
		"amount", 1000,
		slog.Group("cookie", "name", "connect.sid", "value", "s%3A_SID_abc", "secure", true),
		"credentials", map[string]any{"user": "ada", "id": 7},
		"api_key", slogConfig{Name: "prod", DSN: "x"},
	)
	line := buffer.String()
	for _, leak := range []string{"123", "connect.sid", "s%3A_SID_abc", "ada", `"id":7`, "prod"} {
		if strings.Contains(line, leak) {
			t.Errorf("%q leaked: %s", leak, line)
		}
	}
	for _, kept := range []string{`"amount":1000`, `"secure":true`} {
		if !strings.Contains(line, kept) {
			t.Errorf("%s missing: %s", kept, line)
		}
	}
}

type pinCode int
type apiToken string

type loginForm struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Attempts int    `json:"attempts"`
}

// Under a sensitive key nothing passes unmasked, whatever Go type carries it.
func TestSensitiveKeyMasksTypesTheWalkerDoesNotKnow(t *testing.T) {
	policy := mustCompile(t, Options{})
	secret := "hunter2"
	when := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	got, err := policy.Redact(map[string]any{
		"pin":         pinCode(1234),
		"token":       apiToken("abc"),
		"pins":        []int{1, 2},
		"password":    &secret,
		"credentials": loginForm{User: "ada", Password: "x", Attempts: 3},
		"secret":      map[string]int{"a": 7},
		"api_key":     errors.New("key sk-live-123"),
		"session":     when,
		"auth":        []pinCode{5},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"pin":         "***",
		"token":       "***",
		"pins":        []int{1, 2},
		"password":    "***",
		"credentials": map[string]any{"user": "***", "password": "***", "attempts": "***"},
		"secret":      map[string]any{"a": "***"},
		"api_key":     "***",
		"session":     when,
		"auth":        []any{"***"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
	findings, err := policy.Scan(map[string]any{"credentials": loginForm{User: "ada"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 || findings[0].Path != "credentials.attempts" {
		t.Fatalf("findings %+v", findings)
	}
}
