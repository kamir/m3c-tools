package pocket

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/auth"
)

// SyncAPIClient talks to the aims-core pocket-sync API for cross-device dedup.
// Mirrors plaud.SyncAPIClient (SPEC-0117) — same shape, swapped paths/fields.
type SyncAPIClient struct {
	baseURL    string
	apiKey     string
	userID     string
	deviceName string
	client     *http.Client
}

// SyncCheckResult holds the server response for a batch recording check.
type SyncCheckResult struct {
	Synced   map[string]SyncedInfo `json:"synced"`
	Unsynced []string              `json:"unsynced"`
}

// SyncedInfo describes a recording that was already synced on the server.
type SyncedInfo struct {
	ER1DocID   string `json:"er1_doc_id"`
	SyncedAt   string `json:"synced_at"`
	SyncedFrom string `json:"synced_from"`
}

// SyncMapping is the payload sent to register a successful sync on the server.
type SyncMapping struct {
	PocketAccountID   string `json:"pocket_account_id"`
	PocketRecordingID string `json:"pocket_recording_id"`
	ER1DocID          string `json:"er1_doc_id"`
	ER1ContextID      string `json:"er1_context_id"`
	RecordingTitle    string `json:"recording_title,omitempty"`
	RecordingDuration int    `json:"recording_duration,omitempty"`
	AudioFormat       string `json:"audio_format,omitempty"`
	AudioSizeBytes    int    `json:"audio_size_bytes,omitempty"`
	TranscriptLength  int    `json:"transcript_length,omitempty"`
}

// NewSyncAPIClient creates a client from ER1 config values.
// er1APIURL is the full ER1 upload URL (e.g. https://127.0.0.1:8081/upload_2);
// the /upload_2 or /upload suffix is stripped to derive the base URL.
func NewSyncAPIClient(er1APIURL, apiKey, userID string, skipTLSVerify bool) *SyncAPIClient {
	baseURL := deriveBaseURL(er1APIURL)

	transport := &http.Transport{}
	if skipTLSVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	deviceName, _ := os.Hostname()
	if deviceName == "" {
		deviceName = "unknown"
	}

	return &SyncAPIClient{
		baseURL:    baseURL,
		apiKey:     apiKey,
		userID:     userID,
		deviceName: deviceName,
		client: &http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
		},
	}
}

// deriveBaseURL strips /upload_2 or /upload suffix from the ER1 API URL.
func deriveBaseURL(er1APIURL string) string {
	base := er1APIURL
	if idx := strings.LastIndex(base, "/upload"); idx > 0 {
		base = base[:idx]
	}
	return base
}

// CheckRecordings checks which recording IDs are already synced server-side.
// Returns nil, nil if the server is unreachable (graceful degradation).
func (s *SyncAPIClient) CheckRecordings(pocketAccountID string, recordingIDs []string) (*SyncCheckResult, error) {
	if len(recordingIDs) == 0 {
		return &SyncCheckResult{
			Synced:   make(map[string]SyncedInfo),
			Unsynced: []string{},
		}, nil
	}

	u, err := url.Parse(s.baseURL + "/api/pocket-sync/check")
	if err != nil {
		log.Printf("[pocket] sync API: invalid base URL: %v", err)
		return nil, nil
	}
	q := u.Query()
	q.Set("pocket_account_id", pocketAccountID)
	q.Set("recording_ids", strings.Join(recordingIDs, ","))
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		log.Printf("[pocket] sync API: build request failed: %v", err)
		return nil, nil
	}
	s.setHeaders(req)

	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("[pocket] sync API unreachable: %v", err)
		return nil, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		log.Printf("[pocket] sync API auth rejected (HTTP %d)", resp.StatusCode)
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("[pocket] sync API check returned HTTP %d", resp.StatusCode)
		return nil, nil
	}

	var result SyncCheckResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("[pocket] sync API: parse check response: %v", err)
		return nil, nil
	}

	if result.Synced == nil {
		result.Synced = make(map[string]SyncedInfo)
	}
	return &result, nil
}

// RegisterMapping records a successful sync on the server.
func (s *SyncAPIClient) RegisterMapping(mapping SyncMapping) error {
	body, err := json.Marshal(mapping)
	if err != nil {
		return fmt.Errorf("marshal mapping: %w", err)
	}
	req, err := http.NewRequest("POST", s.baseURL+"/api/pocket-sync/map", bytes.NewReader(body))
	if err != nil {
		log.Printf("[pocket] sync API: build mapping request failed: %v", err)
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	s.setHeaders(req)

	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("[pocket] sync API unreachable for mapping: %v", err)
		return fmt.Errorf("sync API unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		log.Printf("[pocket] sync mapping registered: %s -> %s", mapping.PocketRecordingID, mapping.ER1DocID)
		return nil
	}
	log.Printf("[pocket] sync API mapping returned HTTP %d", resp.StatusCode)
	return fmt.Errorf("sync API mapping HTTP %d", resp.StatusCode)
}

// setHeaders applies authentication and identity headers.
// Mirrors plaud.SyncAPIClient.setHeaders — uses the shared auth helper.
func (s *SyncAPIClient) setHeaders(req *http.Request) {
	auth.ApplyAuth(req, s.apiKey)
	if s.userID != "" {
		req.Header.Set("X-User-ID", s.userID)
	}
	if s.deviceName != "" {
		req.Header.Set("X-Device-ID", s.deviceName)
	}
}

// DeriveAccountID creates a stable account identifier from a Pocket API key.
// Uses SHA256 hash of the key, first 16 hex chars, prefixed with "pocket-".
func DeriveAccountID(apiKey string) string {
	hash := sha256.Sum256([]byte(apiKey))
	hexStr := fmt.Sprintf("%x", hash)
	if len(hexStr) > 16 {
		hexStr = hexStr[:16]
	}
	return "pocket-" + hexStr
}

// BaseURL returns the derived base URL for testing/logging.
func (s *SyncAPIClient) BaseURL() string {
	return s.baseURL
}
