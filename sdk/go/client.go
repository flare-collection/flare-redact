package flareredact

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// A client for the flare-redact gateway.
//
// The local engine implements the portable FRS-1 profile. The gateway runs the
// full JavaScript detector set and holds server-side sessions, so point a client
// at your sidecar when you want the policy configured in one place for every
// language in the estate.
//
//	gateway := flareredact.NewClient("http://127.0.0.1:8787", flareredact.ClientOptions{
//	    Token: os.Getenv("FLARE_GATEWAY_TOKEN"),
//	})
//	safe, err := gateway.Redact(ctx, payload, flareredact.Options{Enable: []string{"pii"}})

// ClientOptions configures a gateway client.
type ClientOptions struct {
	// Token is the bearer token the gateway's /v1 API requires.
	Token string
	// HTTPClient defaults to a client with Timeout.
	HTTPClient *http.Client
	// Timeout applies when HTTPClient is not set. Defaults to 10s.
	Timeout time.Duration
	// Defaults are merged under the per-call options.
	Defaults Options
}

// Client talks to a gateway's /v1 API.
type Client struct {
	baseURL  string
	token    string
	http     *http.Client
	defaults Options
}

// GatewayError is a non-2xx response from the gateway.
type GatewayError struct {
	Status  int
	Code    string
	Message string
}

func (e *GatewayError) Error() string {
	return fmt.Sprintf("flareredact: gateway responded %d (%s): %s", e.Status, e.Code, e.Message)
}

// NewClient returns a client for the gateway at baseURL.
func NewClient(baseURL string, options ClientOptions) *Client {
	httpClient := options.HTTPClient
	if httpClient == nil {
		timeout := options.Timeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		httpClient = &http.Client{Timeout: timeout}
	}
	return &Client{
		baseURL:  strings.TrimRight(baseURL, "/"),
		token:    options.Token,
		http:     httpClient,
		defaults: options.Defaults,
	}
}

func (c *Client) do(ctx context.Context, method, path string, payload any, out any) error {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("flareredact: gateway at %s is unreachable: %w", c.baseURL, err)
	}
	defer response.Body.Close()

	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode >= 300 {
		failure := &GatewayError{Status: response.StatusCode, Message: strings.TrimSpace(string(raw))}
		var parsed struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &parsed) == nil && parsed.Message != "" {
			failure.Code, failure.Message = parsed.Code, parsed.Message
		}
		return failure
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func (c *Client) wire(options Options) map[string]any {
	merged := OptionsToWire(c.defaults)
	for key, value := range OptionsToWire(options) {
		merged[key] = value
	}
	return merged
}

// Redact redacts any JSON-serialisable value using the gateway's policy.
func (c *Client) Redact(ctx context.Context, value any, options Options) (any, error) {
	var response struct {
		Output any `json:"output"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/redact", map[string]any{
		"input":   value,
		"options": c.wire(options),
	}, &response)
	if err != nil {
		return nil, err
	}
	return response.Output, nil
}

// Scan lists what the gateway would redact, and why.
func (c *Client) Scan(ctx context.Context, value any, options Options) ([]Finding, error) {
	var response struct {
		Findings []Finding `json:"findings"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/scan", map[string]any{
		"input":   value,
		"options": c.wire(options),
	}, &response)
	if err != nil {
		return nil, err
	}
	return response.Findings, nil
}

// Health reports the gateway's liveness and version.
func (c *Client) Health(ctx context.Context) (map[string]any, error) {
	var response map[string]any
	if err := c.do(ctx, http.MethodGet, "/healthz", nil, &response); err != nil {
		return nil, err
	}
	return response, nil
}

// RemoteSession is a gateway-held vault. Always Close it: the mapping it holds
// is exactly as sensitive as the data it protects.
type RemoteSession struct {
	client *Client
	ID     string
}

// OpenSession creates a server-side session whose placeholders persist across calls.
func (c *Client) OpenSession(ctx context.Context, options Options) (*RemoteSession, error) {
	var response struct {
		ID string `json:"id"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/sessions", map[string]any{"options": c.wire(options)}, &response)
	if err != nil {
		return nil, err
	}
	return &RemoteSession{client: c, ID: response.ID}, nil
}

// Redact masks a message before it reaches the model.
func (s *RemoteSession) Redact(ctx context.Context, value any) (any, error) {
	return s.call(ctx, "redact", value)
}

// Restore puts the originals back into the model's reply.
func (s *RemoteSession) Restore(ctx context.Context, value any) (any, error) {
	return s.call(ctx, "restore", value)
}

func (s *RemoteSession) call(ctx context.Context, action string, value any) (any, error) {
	var response struct {
		Output any `json:"output"`
	}
	err := s.client.do(ctx, http.MethodPost, "/v1/sessions/"+s.ID+"/"+action, map[string]any{"input": value}, &response)
	if err != nil {
		return nil, err
	}
	return response.Output, nil
}

// Close discards the server-side mapping.
func (s *RemoteSession) Close(ctx context.Context) error {
	return s.client.do(ctx, http.MethodDelete, "/v1/sessions/"+s.ID, nil, nil)
}
