package plaud

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// Sentinel errors for Plaud API responses.
var (
	ErrUnauthorized = errors.New("plaud: unauthorized (401)")
	ErrNotFound     = errors.New("plaud: not found (404)")
	ErrRateLimited  = errors.New("plaud: rate limited (429)")
)

// Client communicates with the Plaud cloud API.
type Client struct {
	cfg        *Config
	token      string
	httpClient *http.Client
}

// NewClient creates a Plaud API client with the given config and token.
func NewClient(cfg *Config, token string) *Client {
	return &Client{
		cfg:   cfg,
		token: token,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// ListRecordings fetches recordings from the Plaud cloud.
// Uses the /file/simple/web endpoint with pagination.
func (c *Client) ListRecordings() ([]Recording, error) {
	// Fetch up to 100 recordings. is_trash=2 = non-trashed files.
	body, err := c.get("/file/simple/web?skip=0&limit=100&is_trash=2&is_desc=true")
	if err != nil {
		return nil, fmt.Errorf("list recordings: %w", err)
	}

	log.Printf("[plaud] list response: %d bytes", len(body))

	// Parse the Plaud response: {"status":0,"data_file_total":N,"data_file_list":[...]}
	var resp struct {
		Status        int       `json:"status"`
		Msg           string    `json:"msg"`
		DataFileTotal int       `json:"data_file_total"`
		DataFileList  []rawFile `json:"data_file_list"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		snippet := string(body)
		if len(snippet) > 500 {
			snippet = snippet[:500] + "..."
		}
		return nil, fmt.Errorf("list recordings: parse error: %w (body: %s)", err, snippet)
	}

	if resp.Status != 0 {
		return nil, fmt.Errorf("list recordings: API error status=%d msg=%s", resp.Status, resp.Msg)
	}

	var recordings []Recording
	for _, f := range resp.DataFileList {
		recordings = append(recordings, f.toRecording())
	}
	log.Printf("[plaud] found %d recordings (total=%d)", len(recordings), resp.DataFileTotal)
	return recordings, nil
}

// rawFile represents a file object from the Plaud API.
// Field names match the actual /file/simple/web response.
type rawFile struct {
	ID           string `json:"id"`
	FileName     string `json:"filename"`
	FullName     string `json:"fullname"`
	Duration     int64  `json:"duration"`     // milliseconds
	StartTime    int64  `json:"start_time"`   // Unix ms
	EndTime      int64  `json:"end_time"`     // Unix ms
	EditTime     int64  `json:"edit_time"`    // Unix seconds
	EditFrom     string `json:"edit_from"`
	IsTrans      bool   `json:"is_trans"`
	IsSummary    bool   `json:"is_summary"`
	Scene        int    `json:"scene"`
	SerialNumber string `json:"serial_number"`
	FileSize     int64  `json:"filesize"`
	FileMD5      string `json:"file_md5"`
}

func (f rawFile) toRecording() Recording {
	title := f.FileName
	// Duration is in milliseconds — convert to seconds.
	dur := int(f.Duration / 1000)

	var created time.Time
	if f.StartTime > 0 {
		created = time.UnixMilli(f.StartTime)
	}

	status := "new"
	if f.IsTrans {
		status = "transcribed"
	}

	return Recording{
		ID:        f.ID,
		Title:     title,
		Status:    status,
		Duration:  dur,
		CreatedAt: created,
	}
}

// detailContentItem represents an item in the content_list from /file/detail/<id>.
type detailContentItem struct {
	DataID     string `json:"data_id"`
	DataType   string `json:"data_type"`   // "transaction" (transcript) or "outline" (summary)
	TaskStatus int    `json:"task_status"` // 1 = ready
	DataLink   string `json:"data_link"`   // signed S3 URL
}

// detailResponse represents the /file/detail/<id> response.
type detailResponse struct {
	FileID       string              `json:"file_id"`
	FileName     string              `json:"file_name"`
	Duration     int64               `json:"duration"` // ms
	StartTime    int64               `json:"start_time"`
	ContentList  []detailContentItem `json:"content_list"`
	Scene        int                 `json:"scene"`
	SerialNumber string              `json:"serial_number"`
}

// GetRecording fetches a single recording by ID from the detail endpoint.
func (c *Client) GetRecording(id string) (*Recording, error) {
	body, err := c.get("/file/detail/" + id)
	if err != nil {
		return nil, fmt.Errorf("get recording %s: %w", id, err)
	}
	var resp struct {
		Status int            `json:"status"`
		Data   detailResponse `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("get recording %s: parse response: %w", id, err)
	}

	var created time.Time
	if resp.Data.StartTime > 0 {
		created = time.UnixMilli(resp.Data.StartTime)
	}

	hasTrans := false
	for _, item := range resp.Data.ContentList {
		if item.DataType == "transaction" && item.TaskStatus == 1 {
			hasTrans = true
			break
		}
	}
	status := "new"
	if hasTrans {
		status = "transcribed"
	}

	return &Recording{
		ID:        id,
		Title:     resp.Data.FileName,
		Status:    status,
		Duration:  int(resp.Data.Duration / 1000),
		CreatedAt: created,
	}, nil
}

// DownloadAudio downloads the audio bytes for a recording.
// Uses the /file/download/<id> endpoint which returns raw OGG audio.
func (c *Client) DownloadAudio(id string) ([]byte, string, error) {
	body, err := c.get("/file/download/" + id)
	if err != nil {
		return nil, "", fmt.Errorf("download audio %s: %w", id, err)
	}
	log.Printf("[plaud] downloaded %d bytes of audio for %s", len(body), id)
	return body, "ogg", nil
}

// GetTranscript fetches the transcript for a recording from its detail endpoint.
// The transcript is stored as a gzipped JSON file on S3, referenced in content_list.
func (c *Client) GetTranscript(id string) (*Transcript, error) {
	body, err := c.get("/file/detail/" + id)
	if err != nil {
		return nil, fmt.Errorf("get transcript %s: %w", id, err)
	}
	var resp struct {
		Status int            `json:"status"`
		Data   detailResponse `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("get transcript %s: parse response: %w", id, err)
	}

	var transURL, summaryURL string
	for _, item := range resp.Data.ContentList {
		if item.TaskStatus != 1 || item.DataLink == "" {
			continue
		}
		switch item.DataType {
		case "transaction":
			transURL = item.DataLink
		case "outline":
			summaryURL = item.DataLink
		}
	}

	if transURL == "" && summaryURL == "" {
		return nil, fmt.Errorf("no transcript available for %s", id)
	}

	result := &Transcript{}

	// Fetch transcript from S3 (gzipped JSON).
	if transURL != "" {
		transData, fetchErr := c.fetchS3Content(transURL)
		if fetchErr != nil {
			log.Printf("[plaud] warning: fetch transcript content: %v", fetchErr)
		} else {
			result.Text = extractTranscriptText(transData)
		}
	}

	// Fetch summary from S3 (gzipped JSON).
	if summaryURL != "" {
		summData, fetchErr := c.fetchS3Content(summaryURL)
		if fetchErr != nil {
			log.Printf("[plaud] warning: fetch summary content: %v", fetchErr)
		} else {
			result.Summary = extractSummaryText(summData)
		}
	}

	if result.Text == "" && result.Summary == "" {
		return nil, fmt.Errorf("transcript content empty for %s", id)
	}

	return result, nil
}

// fetchS3Content downloads and decompresses a gzipped JSON file from a signed S3 URL.
func (c *Client) fetchS3Content(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	// S3 pre-signed URLs don't need auth headers.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("S3 fetch status %d", resp.StatusCode)
	}

	// Try gzip decompression; if it fails, read raw.
	var reader io.Reader = resp.Body
	if strings.HasSuffix(url, ".gz") || resp.Header.Get("Content-Encoding") == "gzip" {
		gz, gzErr := gzip.NewReader(resp.Body)
		if gzErr != nil {
			return nil, fmt.Errorf("gzip: %w", gzErr)
		}
		defer gz.Close()
		reader = gz
	}

	return io.ReadAll(io.LimitReader(reader, 50<<20)) // 50 MB limit (gzip bomb protection)
}

// extractTranscriptText parses the Plaud transcript JSON and extracts speaker-diarized text.
// Format: [{"start_time":N,"end_time":N,"content":"...","speaker":"Speaker 1"}, ...]
func extractTranscriptText(data []byte) string {
	var segments []struct {
		Content  string `json:"content"`
		Speaker  string `json:"speaker"`
		Text     string `json:"text"` // fallback field name
	}
	if json.Unmarshal(data, &segments) == nil && len(segments) > 0 {
		var parts []string
		prevSpeaker := ""
		for _, s := range segments {
			text := s.Content
			if text == "" {
				text = s.Text
			}
			if text == "" {
				continue
			}
			if s.Speaker != "" && s.Speaker != prevSpeaker {
				parts = append(parts, fmt.Sprintf("\n[%s] %s", s.Speaker, text))
				prevSpeaker = s.Speaker
			} else {
				parts = append(parts, text)
			}
		}
		return strings.TrimSpace(strings.Join(parts, " "))
	}

	// Fallback: single object with "text" field.
	var simple struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(data, &simple) == nil && simple.Text != "" {
		return simple.Text
	}

	return string(data)
}

// extractSummaryText parses the Plaud outline JSON and extracts topic summaries.
// Format: [{"start_time":N,"end_time":N,"topic":"..."}, ...]
func extractSummaryText(data []byte) string {
	var topics []struct {
		Topic   string `json:"topic"`
		Summary string `json:"summary"`
		Text    string `json:"text"`
		Content string `json:"content"`
	}
	if json.Unmarshal(data, &topics) == nil && len(topics) > 0 {
		var parts []string
		for _, t := range topics {
			text := t.Topic
			if text == "" {
				text = t.Summary
			}
			if text == "" {
				text = t.Text
			}
			if text == "" {
				text = t.Content
			}
			if text != "" {
				parts = append(parts, "- "+text)
			}
		}
		return strings.Join(parts, "\n")
	}

	// Fallback: single object.
	var simple struct {
		Text    string `json:"text"`
		Summary string `json:"summary"`
	}
	if json.Unmarshal(data, &simple) == nil {
		if simple.Summary != "" {
			return simple.Summary
		}
		return simple.Text
	}

	return string(data)
}

// get performs an authenticated GET request to the Plaud API.
// Handles region redirects automatically (status -302).
func (c *Client) get(path string) ([]byte, error) {
	body, err := c.doGet(c.cfg.APIURL + path)
	if err != nil {
		return nil, err
	}

	// Check for region redirect: {"status":-302,"data":{"domains":{"api":"https://..."}}}
	var regionResp struct {
		Status int `json:"status"`
		Data   struct {
			Domains struct {
				API string `json:"api"`
			} `json:"domains"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &regionResp) == nil && regionResp.Status == -302 && regionResp.Data.Domains.API != "" {
		newBase := regionResp.Data.Domains.API
		log.Printf("[plaud] region redirect: %s -> %s", c.cfg.APIURL, newBase)
		c.cfg.APIURL = newBase
		return c.doGet(newBase + path)
	}

	return body, nil
}

func (c *Client) doGet(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", c.token)
	req.Header.Set("app-platform", "web")
	req.Header.Set("edit-from", "web")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := checkStatus(resp); err != nil {
		return nil, err
	}

	return io.ReadAll(io.LimitReader(resp.Body, 50<<20)) // 50 MB limit
}

// DebugGet exposes the raw GET method for API exploration.
func (c *Client) DebugGet(path string) ([]byte, error) {
	return c.get(path)
}

// checkStatus maps HTTP error codes to sentinel errors.
func checkStatus(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return nil
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusTooManyRequests:
		return ErrRateLimited
	default:
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
}
