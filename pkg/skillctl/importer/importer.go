// Package importer handles communication with the aims-core skill profile API.
// It uploads local skill inventories for server-side profile matching and
// reports back how many skills were imported, already known, or newly discovered.
package importer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

// Client handles communication with the aims-core skill profile API.
type Client struct {
	BaseURL    string
	APIKey     string
	UserID     string // BUG-0084: Required by aims-core auth (X-User-ID header)
	HTTPClient *http.Client
}

// ImportResponse is the JSON body returned by the API.
type ImportResponse struct {
	Imported      int    `json:"imported"`
	NewCandidates int    `json:"new_candidates"`
	AlreadyKnown  int    `json:"already_known"`
	Message       string `json:"message,omitempty"`
}

// NewClient creates a Client with a 30-second timeout.
// It validates that baseURL is a well-formed HTTP(S) URL.
// BUG-0084: userID is required for aims-core auth (X-User-ID header).
func NewClient(baseURL, apiKey, userID string) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("target URL must use http or https scheme, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("target URL must include a host")
	}

	// Normalize: strip trailing slash.
	baseURL = strings.TrimRight(baseURL, "/")

	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		UserID:  userID,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// HealthCheck verifies connectivity by calling GET /health on the target.
func (c *Client) HealthCheck() error {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+"/health", nil) // BUG-0085: was /api/health (404)
	if err != nil {
		return fmt.Errorf("creating health check request: %w", err)
	}
	if c.APIKey != "" {
		req.Header.Set("X-API-KEY", c.APIKey)
	}
	if c.UserID != "" {
		req.Header.Set("X-User-ID", c.UserID) // BUG-0084
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("health check returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return nil
}

// Import sends the inventory's skills to the aims-core skill profile API.
// It POSTs to /api/v2/skills/profile/import with an X-API-KEY header.
func (c *Client) Import(inv *model.Inventory) (*ImportResponse, error) {
	payload := struct {
		Skills []model.SkillDescriptor `json:"skills"`
	}{
		Skills: inv.Skills,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling import payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/api/v2/skills/profile/import", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating import request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("X-API-KEY", c.APIKey)
	}
	if c.UserID != "" {
		req.Header.Set("X-User-ID", c.UserID) // BUG-0084
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("import request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("reading import response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("import returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var result ImportResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing import response: %w", err)
	}

	return &result, nil
}

// DryRun returns a human-readable summary of what would be imported
// without actually sending data to the server.
func (c *Client) DryRun(inv *model.Inventory) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Dry-run import to %s\n", c.BaseURL)
	fmt.Fprintf(&b, "Total skills: %d\n\n", len(inv.Skills))

	// Skills by type.
	byType := make(map[string]int)
	for _, s := range inv.Skills {
		byType[string(s.Type)]++
	}
	if len(byType) > 0 {
		fmt.Fprintln(&b, "By type:")
		for _, kv := range sortedMapEntries(byType) {
			fmt.Fprintf(&b, "  %-25s %d\n", kv.key, kv.count)
		}
		fmt.Fprintln(&b)
	}

	// Skills by project.
	byProject := make(map[string]int)
	for _, s := range inv.Skills {
		proj := s.SourceProject
		if proj == "" {
			proj = "(unknown)"
		}
		byProject[proj]++
	}
	if len(byProject) > 0 {
		fmt.Fprintln(&b, "By project:")
		for _, kv := range sortedMapEntries(byProject) {
			fmt.Fprintf(&b, "  %-25s %d\n", kv.key, kv.count)
		}
		fmt.Fprintln(&b)
	}

	fmt.Fprintf(&b, "Target endpoint: POST %s/api/v2/skills/profile/import\n", c.BaseURL)
	fmt.Fprintln(&b, "No data was sent (--dry-run).")

	return b.String()
}

type mapEntry struct {
	key   string
	count int
}

func sortedMapEntries(m map[string]int) []mapEntry {
	entries := make([]mapEntry, 0, len(m))
	for k, v := range m {
		entries = append(entries, mapEntry{k, v})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count != entries[j].count {
			return entries[i].count > entries[j].count
		}
		return entries[i].key < entries[j].key
	})
	return entries
}
