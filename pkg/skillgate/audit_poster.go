package skillgate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPInvocationPoster posts gate.allowed / gate.refused events to the
// aims-core skill-runtime ingestion endpoint. The endpoint forwards into
// the kafscale_stub.publish_event ring buffer (Phase 5 will replace this
// with a real KafScale producer per SPEC-0193).
//
// Cooperative model: PostInvocation MUST NOT block the gate. Any error
// (network down, 5xx, timeout) is returned to the caller but the caller
// is expected to ignore it — see Gate.audit().
type HTTPInvocationPoster struct {
	AuditURL string        // e.g. https://aims-core/api/skills/runtime/invocations
	APIKey   string        // optional bearer token; sent as `Authorization: Bearer <key>`
	Client   *http.Client  // optional; default: 2s-timeout client
	Timeout  time.Duration // optional; default: 2 * time.Second
}

// NewHTTPInvocationPoster constructs a poster with sensible defaults.
func NewHTTPInvocationPoster(url, apiKey string) *HTTPInvocationPoster {
	return &HTTPInvocationPoster{
		AuditURL: url,
		APIKey:   apiKey,
		Client:   &http.Client{Timeout: 2 * time.Second},
		Timeout:  2 * time.Second,
	}
}

// PostInvocation marshals ev to JSON and POSTs it. Returns the first non-2xx
// status as an error; never panics. Callers (Gate.audit) intentionally
// discard the error.
func (p *HTTPInvocationPoster) PostInvocation(ev InvocationEvent) error {
	if p == nil || p.AuditURL == "" {
		return fmt.Errorf("skillgate: HTTPInvocationPoster has no AuditURL")
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("skillgate: marshal invocation event: %w", err)
	}

	timeout := p.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.AuditURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("skillgate: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "m3c-skillgate/1.0")
	if p.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.APIKey)
	}

	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("skillgate: post invocation: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("skillgate: invocation post non-2xx: %d", resp.StatusCode)
	}
	return nil
}

// NopPoster is an InvocationPoster that records calls in memory. Useful in
// tests and as a "do nothing" default for embedding.
type NopPoster struct {
	Events []InvocationEvent
}

// PostInvocation records the event in p.Events.
func (p *NopPoster) PostInvocation(ev InvocationEvent) error {
	p.Events = append(p.Events, ev)
	return nil
}
