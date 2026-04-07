package timetracking

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/auth"
)

// PLMConfig holds connection settings for the PLM API.
type PLMConfig struct {
	BaseURL   string // e.g. "https://onboarding.guide" (ER1 base, no trailing slash)
	APIKey    string // X-API-KEY header
	ContextID string // user context ID
	VerifySSL bool
	Timeout   time.Duration
}

// PLMProject is a project returned by the PLM API.
type PLMProject struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	Client               string   `json:"client"`
	Status               string   `json:"status"`
	Tags                 []string `json:"tags"`
	Description          string   `json:"description"`
	CreatedBy            string   `json:"created_by"`
	CreatedAt            string   `json:"created_at"`
	UpdatedAt            string   `json:"updated_at"`
	QualityScore         float64  `json:"quality_score"`
	CompletionPercentage int      `json:"completion_percentage"`
}

// PLMClient talks to the ER1/PLM API.
type PLMClient struct {
	cfg    PLMConfig
	client *http.Client
}

// NewPLMClient creates a client for the PLM API.
func NewPLMClient(cfg PLMConfig) *PLMClient {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !cfg.VerifySSL,
		},
	}
	return &PLMClient{
		cfg: cfg,
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
	}
}

func (c *PLMClient) doRequest(method, path string, body io.Reader) (*http.Response, error) {
	url := strings.TrimSuffix(c.cfg.BaseURL, "/") + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	auth.ApplyAuth(req, c.cfg.APIKey)
	if c.cfg.ContextID != "" {
		req.Header.Set("X-Context-ID", c.cfg.ContextID)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.client.Do(req)
}

// HealthCheck validates the API key by calling GET /api/plm/projects.
// Returns nil if the key is valid, or an error describing the auth failure.
func (c *PLMClient) HealthCheck() error {
	resp, err := c.doRequest("GET", "/api/plm/projects", nil)
	if err != nil {
		return fmt.Errorf("health check request failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("ER1 API key is invalid or expired (HTTP 401)")
	case http.StatusForbidden:
		return fmt.Errorf("ER1 API key is rejected (HTTP 403)")
	default:
		return fmt.Errorf("ER1 health check returned HTTP %d", resp.StatusCode)
	}
}

// FetchProjects retrieves the project list from GET /api/plm/projects.
// Returns only projects with status "active" or "validating".
func (c *PLMClient) FetchProjects() ([]PLMProject, error) {
	resp, err := c.doRequest("GET", "/api/plm/projects", nil)
	if err != nil {
		return nil, fmt.Errorf("plm projects request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("plm projects HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Projects []PLMProject `json:"projects"`
		Total    int          `json:"total"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse projects: %w", err)
	}

	// Filter to active/validating only.
	var filtered []PLMProject
	for _, p := range result.Projects {
		switch p.Status {
		case "active", "validating":
			filtered = append(filtered, p)
		}
	}

	log.Printf("[plm] fetched %d projects (%d active/validating)", len(result.Projects), len(filtered))
	return filtered, nil
}

// PostTimeEvent sends a context switch event to the PLM API.
func (c *PLMClient) PostTimeEvent(event Event) error {
	payload := map[string]interface{}{
		"event_id":   event.EventID,
		"event_type": event.EventType,
		"timestamp":  event.Timestamp.UTC().Format(time.RFC3339),
		"trigger":    event.Trigger,
	}
	if event.DurationSec != nil {
		payload["duration_sec"] = *event.DurationSec
	}
	if event.ContentRef != "" {
		payload["content_ref"] = event.ContentRef
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	path := fmt.Sprintf("/api/plm/projects/%s/time-events", event.ProjectID)
	resp, err := c.doRequest("POST", path, strings.NewReader(string(data)))
	if err != nil {
		return fmt.Errorf("post time event: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("post time event HTTP %d", resp.StatusCode)
	}

	log.Printf("[plm] synced event %s type=%s project=%s", event.EventID, event.EventType, event.ProjectID)
	return nil
}
