// Package pocket — Pocket Cloud API client (Phase 2 / SPEC-0173).
//
// REST client for https://public.heypocketai.com/api/v1
// Verified 2026-04-27 against the live API (see Pocket-PoC api-probe).
//
// Endpoints honored: list + get + tags + auth probe.
// Endpoints REMOVED (404 on personal pk_ keys): /audio, /recordings/search.
// MCP server: https://public.heypocketai.com/mcp — out of scope here.
package pocket

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const DefaultAPIBaseURL = "https://public.heypocketai.com/api/v1"

// APIClient communicates with the Pocket Cloud API.
type APIClient struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// RateLimit captures the X-RateLimit-* response headers.
type RateLimit struct {
	Limit     int
	Remaining int
	Reset     time.Time
}

// NewAPIClient creates an APIClient from POCKET_API_KEY / POCKET_API_URL env vars.
func NewAPIClient() *APIClient {
	apiKey := os.Getenv("POCKET_API_KEY")
	baseURL := os.Getenv("POCKET_API_URL")
	if baseURL == "" {
		baseURL = DefaultAPIBaseURL
	}
	return &APIClient{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		APIKey:     apiKey,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// IsConfigured returns true if the API key is set.
func (c *APIClient) IsConfigured() bool { return c.APIKey != "" }

// ListRecordings fetches one page (server caps limit at 20).
func (c *APIClient) ListRecordings(page, limit int) ([]APIRecording, *Pagination, error) {
	if limit <= 0 || limit > 20 {
		limit = 20
	}
	if page <= 0 {
		page = 1
	}
	q := url.Values{
		"page":  {strconv.Itoa(page)},
		"limit": {strconv.Itoa(limit)},
	}
	raw, pag, _, err := c.get("/public/recordings", q)
	if err != nil {
		return nil, nil, err
	}
	var recs []APIRecording
	if err := json.Unmarshal(raw, &recs); err != nil {
		return nil, nil, fmt.Errorf("decode list: %w", err)
	}
	return recs, pag, nil
}

// ListRecordingsAll paginates through every recording on the account.
// Filters server-side params are silently ignored by Pocket; do client-side filtering.
func (c *APIClient) ListRecordingsAll() ([]APIRecording, error) {
	var all []APIRecording
	for page := 1; ; page++ {
		recs, pag, err := c.ListRecordings(page, 20)
		if err != nil {
			return nil, err
		}
		all = append(all, recs...)
		if pag == nil || !pag.HasMore {
			break
		}
	}
	return all, nil
}

// GetRecording fetches the full recording detail (transcript + summarizations).
func (c *APIClient) GetRecording(id string) (*APIRecording, error) {
	raw, _, _, err := c.get("/public/recordings/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}
	var r APIRecording
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("decode detail: %w", err)
	}
	return &r, nil
}

// HealthCheck verifies API connectivity by hitting list with limit=1.
func (c *APIClient) HealthCheck() error {
	_, _, _, err := c.get("/public/recordings", url.Values{"limit": {"1"}})
	return err
}

// --- Internal HTTP helpers ---

func (c *APIClient) get(path string, q url.Values) (json.RawMessage, *Pagination, *RateLimit, error) {
	u := c.BaseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("pocket request: %w", err)
	}
	defer resp.Body.Close()

	rl := parseRateLimit(resp.Header)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if err != nil {
		return nil, nil, rl, err
	}

	if resp.StatusCode == 429 {
		return nil, nil, rl, fmt.Errorf("rate limited (429); reset at %s", rl.Reset.Format(time.RFC3339))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := string(body)
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		return nil, nil, rl, fmt.Errorf("HTTP %d %s: %s", resp.StatusCode, path, snippet)
	}

	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, nil, rl, fmt.Errorf("decode envelope: %w", err)
	}
	if !env.Success {
		return nil, nil, rl, fmt.Errorf("api error: %s", env.Error)
	}
	return env.Data, env.Pagination, rl, nil
}

func parseRateLimit(h http.Header) *RateLimit {
	rl := &RateLimit{}
	if v := h.Get("X-RateLimit-Limit"); v != "" {
		rl.Limit, _ = strconv.Atoi(v)
	}
	if v := h.Get("X-RateLimit-Remaining"); v != "" {
		rl.Remaining, _ = strconv.Atoi(v)
	}
	if v := h.Get("X-RateLimit-Reset"); v != "" {
		if epoch, err := strconv.ParseInt(v, 10, 64); err == nil {
			rl.Reset = time.Unix(epoch, 0)
		}
	}
	return rl
}
