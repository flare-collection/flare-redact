// Package flareredact hides secrets and PII before they reach a log, a model,
// or a vendor.
//
// It implements the FRS-1 detector specification, the same one the JavaScript,
// Python and Rust engines implement, so a policy written once behaves
// identically everywhere in a polyglot system. The shared conformance corpus in
// spec/conformance is run by every engine's test suite; a change that makes them
// disagree fails CI.
//
// The dependency list is the standard library, and nothing else.
//
// # Getting started
//
//	policy, err := flareredact.Compile(flareredact.Options{Enable: []string{"pii"}})
//	if err != nil {
//	    return err
//	}
//	safe, err := policy.RedactString("contact ada@example.com")
//	// "contact a***@***"
//
// Compile once and reuse the policy: it resolves the detector list, the mask
// function and the key tests a single time, and reusing it is what guarantees
// your logs, your HTTP layer and your prompts agree on what "sensitive" means.
//
// # Structured values
//
// Policy.Redact handles the shapes json.Unmarshal produces — map[string]any,
// []any, string and scalars — plus map[string]string and []string. For a struct,
// use Policy.RedactJSON, which marshals, redacts and returns JSON. Reflection
// over arbitrary structs is deliberately not attempted: it would silently skip
// unexported fields, which is a worse failure than an honest no-op.
//
// # Logging
//
// NewSlogHandler wraps any slog.Handler, so one line at the root protects every
// log statement in the process, including those in libraries you do not control.
//
// # Outbound HTTP
//
// Transport wraps an http.RoundTripper and redacts request bodies for the hosts
// you name — an analytics endpoint, a webhook, a log shipper.
//
// # Reversible redaction
//
// A Vault swaps each secret for a stable placeholder and remembers the mapping,
// so a prompt can be sent to a model and the model's answer restored. A Session
// keeps one vault across the turns of a conversation. StreamRestorer handles a
// placeholder split across streamed chunks.
//
// # Failure behaviour
//
// Limits fail closed. An oversized input returns a *LimitError rather than
// partially redacted text, because a caller cannot tell partially redacted
// output from clean output. A detector pack that uses a construct this engine
// cannot execute exactly — a lookahead, a checksum it does not implement — fails
// to load rather than loading with the check quietly skipped.
package flareredact
