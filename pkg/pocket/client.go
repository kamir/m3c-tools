// client.go — Pocket Cloud API client (Phase 2, SPEC-0119).
//
// REST client for https://public.heypocketai.com/api/v1
// Used in --mode api for cloud transcripts, metadata, and search.
package pocket

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// APIClient communicates with the Pocket Cloud API.
type APIClient struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// APIRecording represents a recording from the Pocket Cloud API.
type APIRecording struct {
	ID              string    `json:"id"`
	Title           string    `json:"title"`
	Duration        float64   `json:"duration"` // seconds
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	TranscriptText  string    `json:"transcript_text"`
	Summary         string    `json:"summary"`
	Tags            []string  `json:"tags"`
	AudioURL        string    `json:"audio_url"` // signed download URL
	Language        string    `json:"language"`
	SpeakerCount    int       `json:"speaker_count"`
	WordCount       int       `json:"word_count"`
}

// APIResponse wraps the standard Pocket API response envelope.
type APIResponse struct {
	Success    bool            `json:"success"`
	Data       json.RawMessage `json:"data"`
	Error      string          `json:"error,omitempty"`
	Pagination *APIPagination  `json:"pagination,omitempty"`
}

// APIPagination holds pagination metadata.
type APIPagination struct {
	Page       int  `json:"page"`
	Limit      int  `json:"limit"`
	Total      int  `json:"total"`
	TotalPages int  `json:"total_pages"`
	HasMore    bool `json:"has_more"`
}

// SearchRequest is the body for POST /public/recordings/search.
type SearchRequest struct {
	Query     string `json:"query"`
	Limit     int    `json:"limit,omitempty"`
	Page      int    `json:"page,omitempty"`
}

// NewAPIClient creates a Pocket API client from config.
func NewAPIClient() *APIClient {
	apiKey := os.Getenv("POCKET_API_KEY")
	baseURL := os.Getenv("POCKET_API_URL")
	if baseURL == "" {
		baseURL = "https://public.heypocketai.com/api/v1"
	}

	return &APIClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// IsConfigured returns true if the API key is set.
func (c *APIClient) IsConfigured() bool {
	return c.APIKey != ""
}

// ListRecordings fetches recordings with optional pagination.
func (c *APIClient) ListRecordings(page, limit int) ([]APIRecording, *APIPagination, error) {
	params := url.Values{}
	if page > 0 {
		params.Set("page", fmt.Sprintf("%d", page))
	}
	if limit > 0 {
		params.Set("limit", fmt.Sprintf("%d", limit))
	}

	body, pagination, err := c.get("/public/recordings", params)
	if err != nil {
		return nil, nil, err
	}

	var recordings []APIRecording
	if err := json.Unmarshal(body, &recordings); err != nil {
		return nil, nil, fmt.Errorf("parse recordings: %w", err)
	}

	return recordings, pagination, nil
}

// GetRecording fetches a single recording by ID.
func (c *APIClient) GetRecording(id string) (*APIRecording, error) {
	body, _, err := c.get("/public/recordings/"+id, nil)
	if err != nil {
		return nil, err
	}

	var rec APIRecording
	if err := json.Unmarshal(body, &rec); err != nil {
		return nil, fmt.Errorf("parse recording: %w", err)
	}

	return &rec, nil
}

// GetAudioURL fetches a signed download URL for a recording's audio.
func (c *APIClient) GetAudioURL(id string) (string, error) {
	body, _, err := c.get("/public/recordings/"+id+"/audio", nil)
	if err != nil {
		return "", err
	}

	var result struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse audio URL: %w", err)
	}

	return result.URL, nil
}

// Search performs semantic search across recordings.
func (c *APIClient) Search(query string, limit int) ([]APIRecording, error) {
	reqBody := SearchRequest{Query: query, Limit: limit}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	respBody, _, err := c.post("/public/recordings/search", data)
	if err != nil {
		return nil, err
	}

	var recordings []APIRecording
	if err := json.Unmarshal(respBody, &recordings); err != nil {
		return nil, fmt.Errorf("parse search results: %w", err)
	}

	return recordings, nil
}

// ListTags fetches all tags.
func (c *APIClient) ListTags() ([]string, error) {
	body, _, err := c.get("/public/tags", nil)
	if err != nil {
		return nil, err
	}

	var tags []string
	if err := json.Unmarshal(body, &tags); err != nil {
		return nil, fmt.Errorf("parse tags: %w", err)
	}

	return tags, nil
}

// HealthCheck verifies API connectivity.
func (c *APIClient) HealthCheck() error {
	_, _, err := c.get("/public/recordings", url.Values{"limit": {"1"}})
	return err
}

// --- HTTP helpers ---

func (c *APIClient) get(path string, params url.Values) (json.RawMessage, *APIPagination, error) {
	u := c.BaseURL + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}
	return c.do(req)
}

func (c *APIClient) post(path string, body []byte) (json.RawMessage, *APIPagination, error) {
	req, err := http.NewRequest("POST", c.BaseURL+path, strings.NewReader(string(body)))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

func (c *APIClient) do(req *http.Request) (json.RawMessage, *APIPagination, error) {
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("pocket API request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB max
	if err != nil {
		return nil, nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == 429 {
		return nil, nil, fmt.Errorf("pocket API rate limited (429)")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("pocket API HTTP %d: %s", resp.StatusCode, string(respBody[:min(200, len(respBody))]))
	}

	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, nil, fmt.Errorf("parse API response: %w", err)
	}

	if !apiResp.Success {
		return nil, nil, fmt.Errorf("pocket API error: %s", apiResp.Error)
	}

	log.Printf("[pocket-api] %s %s → %d", req.Method, req.URL.Path, resp.StatusCode)
	return apiResp.Data, apiResp.Pagination, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
