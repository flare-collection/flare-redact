package flareredact

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
)

// Drop-in integrations for the two places data leaves a Go process: the logger
// and the HTTP client.

// SlogHandler wraps another slog.Handler and redacts every record before it is
// written. Attach it once at the root and every log line in the process is
// covered, including the ones in libraries you do not control.
//
//	logger := slog.New(flareredact.NewSlogHandler(
//	    slog.NewJSONHandler(os.Stdout, nil),
//	    policy,
//	))
//	slog.SetDefault(logger)
type SlogHandler struct {
	inner  slog.Handler
	policy *Policy
}

// NewSlogHandler wraps inner so its records are redacted with policy.
func NewSlogHandler(inner slog.Handler, policy *Policy) *SlogHandler {
	return &SlogHandler{inner: inner, policy: policy}
}

// Enabled reports whether the wrapped handler handles this level.
func (h *SlogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle redacts the message and every attribute, then forwards the record.
func (h *SlogHandler) Handle(ctx context.Context, record slog.Record) error {
	redacted := slog.NewRecord(record.Time, record.Level, h.text(record.Message), record.PC)
	record.Attrs(func(attr slog.Attr) bool {
		redacted.AddAttrs(h.attr(attr))
		return true
	})
	return h.inner.Handle(ctx, redacted)
}

// WithAttrs redacts the attributes as they are bound, so a value attached once
// to a child logger is not re-scanned on every record.
func (h *SlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, len(attrs))
	for i, attr := range attrs {
		redacted[i] = h.attr(attr)
	}
	return &SlogHandler{inner: h.inner.WithAttrs(redacted), policy: h.policy}
}

// WithGroup opens a group on the wrapped handler.
func (h *SlogHandler) WithGroup(name string) slog.Handler {
	return &SlogHandler{inner: h.inner.WithGroup(name), policy: h.policy}
}

// redactionFailed is what a record becomes when redaction itself errors — for
// example on an oversized value. Emitting the original would be the one
// outcome this package exists to prevent.
const redactionFailed = "[REDACTION FAILED]"

func (h *SlogHandler) text(value string) string {
	out, err := h.policy.RedactString(value)
	if err != nil {
		return redactionFailed
	}
	return out
}

func (h *SlogHandler) attr(attr slog.Attr) slog.Attr {
	// A sensitive key name is decided by the attribute key, exactly as it is
	// for a map entry: logger.Info("x", "password", pw) must not print pw.
	if attr.Value.Kind() == slog.KindString && h.policy.matchKey(attr.Key) && !h.policy.allow(attr.Value.String()) {
		return slog.String(attr.Key, h.policy.replace(attr.Value.String(), sensitiveKeyDetector))
	}
	return slog.Attr{Key: attr.Key, Value: h.value(attr.Value)}
}

func (h *SlogHandler) value(value slog.Value) slog.Value {
	switch value.Kind() {
	case slog.KindString:
		return slog.StringValue(h.text(value.String()))
	case slog.KindGroup:
		attrs := value.Group()
		out := make([]slog.Attr, len(attrs))
		for i, attr := range attrs {
			out[i] = h.attr(attr)
		}
		return slog.GroupValue(out...)
	case slog.KindLogValuer:
		return h.value(value.Resolve())
	case slog.KindAny:
		redacted, err := h.policy.Redact(value.Any())
		if err != nil {
			return slog.StringValue(redactionFailed)
		}
		return slog.AnyValue(redacted)
	default:
		return value
	}
}

// Transport wraps an http.RoundTripper and redacts request bodies before they
// leave the process.
//
// Hosts is an allow-by-destination list: with none set nothing is redacted, so
// you opt in the sinks you do not want data flowing to — an analytics endpoint,
// a webhook, a log shipper — rather than paying to scan every request.
//
//	client := &http.Client{Transport: &flareredact.Transport{
//	    Policy: policy,
//	    Hosts:  []string{"api.segment.io", "hooks.slack.com"},
//	}}
type Transport struct {
	// Policy is required.
	Policy *Policy
	// Base defaults to http.DefaultTransport.
	Base http.RoundTripper
	// Hosts to redact for: an exact host, or a parent domain such as "segment.io".
	Hosts []string
	// MaxBodyBytes caps the request body this transport will buffer. A larger
	// body is forwarded untouched, because silently truncating a request is
	// worse than not redacting one. 0 uses DefaultMaxInputLength.
	MaxBodyBytes int64
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

func (t *Transport) matches(host string) bool {
	if host == "" {
		return false
	}
	for _, candidate := range t.Hosts {
		if host == candidate || strings.HasSuffix(host, "."+candidate) {
			return true
		}
	}
	return false
}

// RoundTrip redacts the outgoing body when the destination is one of Hosts.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Policy == nil || req.Body == nil || !t.matches(req.URL.Hostname()) {
		return t.base().RoundTrip(req)
	}
	limit := t.MaxBodyBytes
	if limit <= 0 {
		limit = DefaultMaxInputLength
	}
	if req.ContentLength > limit {
		return t.base().RoundTrip(req)
	}

	body, err := io.ReadAll(io.LimitReader(req.Body, limit+1))
	closeErr := req.Body.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(body)) > limit {
		// The body outgrew the cap after we started reading it; forwarding what
		// we have would truncate the request, so hand back an unredacted but
		// intact one only if it was never going to be scanned anyway.
		req = req.Clone(req.Context())
		req.Body = io.NopCloser(bytes.NewReader(body))
		return t.base().RoundTrip(req)
	}

	redacted, err := t.redact(body, req.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}

	clone := req.Clone(req.Context())
	clone.Body = io.NopCloser(bytes.NewReader(redacted))
	clone.ContentLength = int64(len(redacted))
	clone.Header.Set("Content-Length", strconv.Itoa(len(redacted)))
	clone.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(redacted)), nil
	}
	return t.base().RoundTrip(clone)
}

func (t *Transport) redact(body []byte, contentType string) ([]byte, error) {
	if strings.Contains(strings.ToLower(contentType), "json") {
		if out, err := t.Policy.RedactJSON(body); err == nil {
			return out, nil
		}
		// Not valid JSON despite the header: fall through to text redaction
		// rather than forwarding it untouched.
	}
	out, err := t.Policy.RedactString(string(body))
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}
