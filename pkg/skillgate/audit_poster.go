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
	AuditURL string       // e.g. https://aims-core/api/skills/runtime/invocations
	APIKey   string       // optional API key; sent as `X-API-KEY: <key>` to match the rest of the skill-registry API surface
	UserID   string       // optional user id; sent as `X-User-ID: <id>` (api_auth_required requires both)
	Client   *http.Client // optional; default: 2s-timeout client
	Timeout  time.Duration // optional; default: 2 * time.Second
}

// NewHTTPInvocationPoster constructs a poster with sensible defaults. UserID
// defaults to the gateway host identity ("m3c-skillgate-host"); callers that
// need a different X-User-ID should set the field explicitly after construction
// or use NewHTTPInvocationPosterAs.
func NewHTTPInvocationPoster(url, apiKey string) *HTTPInvocationPoster {
	return &HTTPInvocationPoster{
		AuditURL: url,
		APIKey:   apiKey,
		// SPEC-0202 §17 AC-11: api_auth_required (skill_registry/api.py)
		// rejects requests that lack X-User-ID even when the API key is
		// correct. Without this default the cooperative gate.refused
		// post returned 401 silently and the audit row never landed —
		// the E2E saw count=0 and failed.
		UserID:  "m3c-skillgate-host",
		Client:  &http.Client{Timeout: 2 * time.Second},
		Timeout: 2 * time.Second,
	}
}

// NewHTTPInvocationPosterAs constructs a poster bound to a specific operator
// user_id. Operators that surface as a real human (e.g. CISO Console probes)
// should use this form so the audit row records who took the action.
func NewHTTPInvocationPosterAs(url, apiKey, userID string) *HTTPInvocationPoster {
	p := NewHTTPInvocationPoster(url, apiKey)
	if userID != "" {
		p.UserID = userID
	}
	return p
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
		// Use X-API-KEY to match the rest of the skill-registry API surface
		// (api_auth_required reads request.headers['X-API-KEY']). The previous
		// `Authorization: Bearer …` form was a Phase-4 stub that the runtime
		// invocation endpoint never accepted.
		req.Header.Set("X-API-KEY", p.APIKey)
	}
	if p.UserID != "" {
		// SPEC-0202 §17 AC-11: api_auth_required requires X-User-ID
		// alongside X-API-KEY. Without it the registry returns 401 and
		// the audit row never lands — the cooperative-refusal flow
		// looks like it succeeded (probe still exits 33 from gate.Allow)
		// but the operator has no record of why a refusal occurred.
		req.Header.Set("X-User-ID", p.UserID)
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
