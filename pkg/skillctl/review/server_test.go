package review

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/delta"
)

// createTestDelta writes a minimal delta report to a temp file and returns the path.
func createTestDelta(t *testing.T) string {
	t.Helper()
	dr := delta.DeltaReport{
		ComputedAt:   "2026-04-02T10:00:00Z",
		BaselinePath: "baseline.json",
		CurrentPath:  "current.json",
		Entries: []delta.DeltaEntry{
			{
				SkillID:      "proj/alpha",
				SkillName:    "alpha",
				DeltaType:    delta.DeltaAdded,
				CurrentHash:  "abc123",
				CurrentPath:  "/skills/alpha.md",
				ContentDiff:  "new skill content",
				ReviewStatus: delta.ReviewPending,
			},
			{
				SkillID:      "proj/beta",
				SkillName:    "beta",
				DeltaType:    delta.DeltaModified,
				BaselineHash: "old-hash",
				CurrentHash:  "new-hash",
				BaselinePath: "/skills/beta.md",
				CurrentPath:  "/skills/beta.md",
				ContentDiff:  "-old line\n+new line\n context",
				ReviewStatus: delta.ReviewPending,
			},
			{
				SkillID:      "proj/gamma",
				SkillName:    "gamma",
				DeltaType:    delta.DeltaRemoved,
				BaselineHash: "rem-hash",
				BaselinePath: "/skills/gamma.md",
				ReviewStatus: delta.ReviewPending,
			},
		},
		Summary: delta.DeltaSummary{
			Added:    1,
			Modified: 1,
			Removed:  1,
			Total:    3,
		},
	}

	data, err := json.MarshalIndent(dr, "", "  ")
	if err != nil {
		t.Fatalf("marshalling test delta: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "delta.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("writing test delta: %v", err)
	}
	return path
}

func setupServer(t *testing.T) *Server {
	t.Helper()
	deltaPath := createTestDelta(t)
	s := NewServer(":0", deltaPath)
	if err := s.LoadDelta(deltaPath); err != nil {
		t.Fatalf("LoadDelta: %v", err)
	}
	// Use temp dir for seal store.
	store, err := delta.NewSealStoreAt(t.TempDir())
	if err != nil {
		t.Fatalf("NewSealStoreAt: %v", err)
	}
	s.sealStore = store
	return s
}

func TestHealthEndpoint(t *testing.T) {
	s := setupServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	w := httptest.NewRecorder()
	s.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("health status = %d, want 200", w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("health status = %q, want %q", resp["status"], "ok")
	}
}

func TestGetDeltaEndpoint(t *testing.T) {
	s := setupServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/delta", nil)
	w := httptest.NewRecorder()
	s.handleGetDelta(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("delta status = %d, want 200", w.Code)
	}

	var resp deltaJSON
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(resp.Entries) != 3 {
		t.Errorf("entries = %d, want 3", len(resp.Entries))
	}
	if resp.TotalAdded != 1 {
		t.Errorf("total_added = %d, want 1", resp.TotalAdded)
	}
	if resp.TotalModified != 1 {
		t.Errorf("total_modified = %d, want 1", resp.TotalModified)
	}
	// Verify indices are set.
	for i, e := range resp.Entries {
		if e.Index != i {
			t.Errorf("entry[%d].index = %d, want %d", i, e.Index, i)
		}
	}
}

func TestReviewEntryEndpoint(t *testing.T) {
	s := setupServer(t)

	body := strings.NewReader(`{"status":"approved"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/delta/0/review", body)
	w := httptest.NewRecorder()
	s.handleReviewEntry(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("review status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var resp entryJSON
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp.ReviewStatus != delta.ReviewApproved {
		t.Errorf("review_status = %q, want %q", resp.ReviewStatus, delta.ReviewApproved)
	}
	if resp.ReviewedAt == "" {
		t.Error("reviewed_at should be set")
	}
}

func TestReviewEntryInvalidStatus(t *testing.T) {
	s := setupServer(t)

	body := strings.NewReader(`{"status":"invalid"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/delta/0/review", body)
	w := httptest.NewRecorder()
	s.handleReviewEntry(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestReviewEntryOutOfRange(t *testing.T) {
	s := setupServer(t)

	body := strings.NewReader(`{"status":"approved"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/delta/99/review", body)
	w := httptest.NewRecorder()
	s.handleReviewEntry(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestSealRequiresAllReviewed(t *testing.T) {
	s := setupServer(t)

	// Try sealing with pending entries.
	req := httptest.NewRequest(http.MethodPost, "/api/seal", nil)
	w := httptest.NewRecorder()
	s.handleSeal(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("seal status = %d, want 409 (entries still pending)", w.Code)
	}
}

func TestSealAfterFullReview(t *testing.T) {
	s := setupServer(t)

	// Approve all entries.
	for i := 0; i < 3; i++ {
		body := strings.NewReader(`{"status":"approved"}`)
		req := httptest.NewRequest(http.MethodPut, "/api/delta/"+string(rune('0'+i))+"/review", body)
		w := httptest.NewRecorder()
		s.handleReviewEntry(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("review entry %d: status = %d", i, w.Code)
		}
	}

	// Now seal.
	req := httptest.NewRequest(http.MethodPost, "/api/seal", nil)
	w := httptest.NewRecorder()
	s.handleSeal(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("seal status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var resp sealResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp.Approved != 3 {
		t.Errorf("approved = %d, want 3", resp.Approved)
	}
	if resp.SealID == "" {
		t.Error("seal_id should not be empty")
	}
}

func TestListSealsEndpoint(t *testing.T) {
	s := setupServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/seals", nil)
	w := httptest.NewRecorder()
	s.handleListSeals(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("seals status = %d, want 200", w.Code)
	}

	var seals []delta.SealRecord
	if err := json.Unmarshal(w.Body.Bytes(), &seals); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	// Initially empty.
	if len(seals) != 0 {
		t.Errorf("seals = %d, want 0 initially", len(seals))
	}
}

func TestGetDeltaMethodNotAllowed(t *testing.T) {
	s := setupServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/delta", nil)
	w := httptest.NewRecorder()
	s.handleGetDelta(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestUIEndpointServesHTML(t *testing.T) {
	s := setupServer(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	s.handleUI(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("UI status = %d, want 200", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(w.Body.String(), "skillctl") {
		t.Error("UI response should contain 'skillctl'")
	}
}
