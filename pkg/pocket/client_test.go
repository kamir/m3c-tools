package pocket

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// SPEC-0176 §3.4: pin the Pocket Cloud REST contract behaviour.

func newTestAPIClient(srvURL, key string) *APIClient {
	return &APIClient{
		BaseURL:    srvURL,
		APIKey:     key,
		HTTPClient: http.DefaultClient,
	}
}

func TestAPIClient_NewFromEnv(t *testing.T) {
	t.Setenv("POCKET_API_KEY", "pk_test_key")
	t.Setenv("POCKET_API_URL", "https://example.com/api/v1/")
	c := NewAPIClient()
	if c.APIKey != "pk_test_key" {
		t.Errorf("APIKey = %q", c.APIKey)
	}
	if c.BaseURL != "https://example.com/api/v1" {
		t.Errorf("BaseURL = %q (trailing slash should be stripped)", c.BaseURL)
	}
	if !c.IsConfigured() {
		t.Error("IsConfigured should be true with key")
	}
}

func TestAPIClient_NewFromEnvDefaultURL(t *testing.T) {
	t.Setenv("POCKET_API_KEY", "pk_x")
	t.Setenv("POCKET_API_URL", "")
	c := NewAPIClient()
	if c.BaseURL != DefaultAPIBaseURL {
		t.Errorf("BaseURL = %q, want default", c.BaseURL)
	}
}

func TestAPIClient_NotConfigured(t *testing.T) {
	t.Setenv("POCKET_API_KEY", "")
	c := NewAPIClient()
	if c.IsConfigured() {
		t.Error("IsConfigured should be false with empty key")
	}
}

func TestListRecordings_DecodesEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/public/recordings" {
			http.Error(w, "not found", 404)
			return
		}
		if r.Header.Get("Authorization") != "Bearer pk_test" {
			t.Errorf("missing/wrong Authorization header: %q", r.Header.Get("Authorization"))
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 0 {
			page = 1
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": []map[string]any{
				{
					"id":           "9bbc770f-f269-4054-a1d2-4d7770fb4089",
					"title":        "Conversation",
					"duration":     13,
					"state":        "pending",
					"recording_at": "2026-04-27T14:42:49Z",
					"tags":         []string{},
				},
			},
			"pagination": map[string]any{
				"page": page, "limit": 5, "total": 26, "total_pages": 6, "has_more": true,
			},
		})
	}))
	defer srv.Close()

	c := newTestAPIClient(srv.URL, "pk_test")
	recs, pag, err := c.ListRecordings(1, 5)
	if err != nil {
		t.Fatalf("ListRecordings: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("want 1 recording, got %d", len(recs))
	}
	if recs[0].ID != "9bbc770f-f269-4054-a1d2-4d7770fb4089" {
		t.Errorf("ID = %q", recs[0].ID)
	}
	if recs[0].State != "pending" {
		t.Errorf("State = %q", recs[0].State)
	}
	if pag == nil || !pag.HasMore || pag.Total != 26 {
		t.Errorf("pagination wrong: %+v", pag)
	}
}

func TestListRecordings_RespectsLimitClamp(t *testing.T) {
	var gotLimit string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLimit = r.URL.Query().Get("limit")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":[]}`))
	}))
	defer srv.Close()
	c := newTestAPIClient(srv.URL, "pk_x")
	// Request 200; client should clamp to 20 (server-side max).
	if _, _, err := c.ListRecordings(0, 200); err != nil {
		t.Fatal(err)
	}
	if gotLimit != "20" {
		t.Errorf("limit param = %q, want 20", gotLimit)
	}
}

func TestListRecordings_PaginatesAll(t *testing.T) {
	// Mock returns 2 pages: 20 items on page 1, 6 on page 2.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pageStr := r.URL.Query().Get("page")
		page, _ := strconv.Atoi(pageStr)
		var items []map[string]any
		hasMore := false
		switch page {
		case 1:
			items = make([]map[string]any, 20)
			for i := range items {
				items[i] = map[string]any{"id": fmt.Sprintf("p1-%02d", i), "state": "pending", "duration": 1}
			}
			hasMore = true
		case 2:
			items = make([]map[string]any, 6)
			for i := range items {
				items[i] = map[string]any{"id": fmt.Sprintf("p2-%02d", i), "state": "completed", "duration": 60}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success":    true,
			"data":       items,
			"pagination": map[string]any{"page": page, "has_more": hasMore},
		})
	}))
	defer srv.Close()

	c := newTestAPIClient(srv.URL, "pk_x")
	all, err := c.ListRecordingsAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 26 {
		t.Errorf("ListRecordingsAll returned %d, want 26", len(all))
	}
}

func TestGetRecording_DecodesNested(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/public/recordings/abc" {
			http.Error(w, "not found", 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"data": {
				"id": "abc",
				"title": "T",
				"duration": 60,
				"state": "completed",
				"recording_at": "2026-04-27T00:00:00Z",
				"transcript": {"text": "hello"},
				"summarizations": {"u": {"v2": {"summary": {"markdown": "# md"}}}}
			}
		}`))
	}))
	defer srv.Close()
	c := newTestAPIClient(srv.URL, "pk_x")
	rec, err := c.GetRecording("abc")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Transcript.Text != "hello" {
		t.Errorf("Transcript.Text = %q", rec.Transcript.Text)
	}
	if rec.SummaryMarkdown() != "# md" {
		t.Errorf("SummaryMarkdown = %q", rec.SummaryMarkdown())
	}
}

func TestRateLimit_Parsed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "50")
		w.Header().Set("X-RateLimit-Remaining", "47")
		w.Header().Set("X-RateLimit-Reset", "1777305480")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":[]}`))
	}))
	defer srv.Close()
	c := newTestAPIClient(srv.URL, "pk_x")
	// Use the unexported get directly to peek at rate-limit parsing.
	_, _, rl, err := c.get("/public/recordings", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rl == nil {
		t.Fatal("rate-limit not parsed")
	}
	if rl.Limit != 50 || rl.Remaining != 47 {
		t.Errorf("rate-limit numbers wrong: %+v", rl)
	}
	if rl.Reset.Unix() != 1777305480 {
		t.Errorf("reset wrong: %v", rl.Reset)
	}
}

func TestClient_429ReturnsRateLimitedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(60*time.Second).Unix(), 10))
		http.Error(w, "rate limited", 429)
	}))
	defer srv.Close()
	c := newTestAPIClient(srv.URL, "pk_x")
	_, _, err := c.ListRecordings(1, 1)
	if err == nil {
		t.Fatal("expected error on 429")
	}
}

func TestClient_NonSuccessReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":false,"error":"boom"}`))
	}))
	defer srv.Close()
	c := newTestAPIClient(srv.URL, "pk_x")
	_, _, err := c.ListRecordings(1, 1)
	if err == nil || err.Error() == "" {
		t.Errorf("expected api error on success=false, got: %v", err)
	}
}
