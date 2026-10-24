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
	"sort"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/httpsafe"
	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

// Client handles communication with the aims-core skill profile API.
type Client struct {
	baseURL    string
	secret     string
	kind       httpsafe.CredentialKind
	userID     string
	HTTPClient *http.Client
}

// ImportResponse is the JSON body returned by the API.
type ImportResponse struct {
	Imported      int    `json:"imported"`
	NewCandidates int    `json:"new_candidates"`
	AlreadyKnown  int    `json:"already_known"`
	Message       string `json:"message,omitempty"`
}

// NewClient validates the independent local operator binding before reading a
// selected secret, then snapshots target, kind and secret for both requests.
// It does not load stores or authenticate issuer/tenant metadata.
func NewClient(baseURL string, allowLoopbackHTTP bool, selected httpsafe.DeferredSecret, userID string) (*Client, error) {
	resolved, err := httpsafe.ResolveCredential(baseURL, allowLoopbackHTTP, selected)
	if err != nil {
		return nil, err
	}
	secret := strings.TrimSpace(string(resolved.Secret))
	if secret == "" || strings.ContainsAny(secret, "\r\n\x00") {
		return nil, fmt.Errorf("invalid import credential format")
	}
	return &Client{
		baseURL: strings.TrimRight(resolved.Base.URL, "/"), secret: secret,
		kind: resolved.Binding.Kind, userID: userID,
		HTTPClient: &http.Client{Timeout: 30 * time.Second, CheckRedirect: httpsafe.NoCredentialRedirect},
	}, nil
}

func (c *Client) applyCredential(req *http.Request) {
	if c.kind == httpsafe.CredentialDeviceBearer {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	} else {
		req.Header.Set("X-API-KEY", c.secret)
	}
	if c.userID != "" {
		req.Header.Set("X-User-ID", c.userID)
	}
}

// HealthCheck verifies connectivity by calling GET /health on the target.
func (c *Client) HealthCheck() error {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+"/health", nil) // BUG-0085: was /api/health (404)
	if err != nil {
		return fmt.Errorf("creating health check request")
	}
	c.applyCredential(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("health check returned HTTP %d", resp.StatusCode)
	}

	return nil
}

// Import sends the inventory's skills to the aims-core skill profile API.
// It POSTs with the credential selected and bound when constructing the client.
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

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/api/v2/skills/profile/import", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating import request")
	}
	req.Header.Set("Content-Type", "application/json")
	c.applyCredential(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("import request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("import returned HTTP %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("reading import response")
	}

	var result ImportResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing import response")
	}

	if strings.Contains(result.Message, c.secret) {
		return nil, fmt.Errorf("import response blocked: selected credential reflected in message")
	}
	return &result, nil
}

// DryRun formats a preview from a validated base and inventory, without a
// credential, store or HTTP client. It does not authorize a later real import.
func DryRun(base httpsafe.APIBase, inv *model.Inventory) string {
	baseURL := strings.TrimRight(base.URL, "/")
	var b strings.Builder

	fmt.Fprintf(&b, "Dry-run import to %s\n", baseURL)
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

	fmt.Fprintf(&b, "Target endpoint: POST %s/api/v2/skills/profile/import\n", baseURL)
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
