package registry

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchRevocationHead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/skills/revocations/head" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"schema_version":"m3c-revocation-head/v1","epoch":7,"issued_at":"2026-07-06T18:00:00Z","emergency":[]}`)
	}))
	defer srv.Close()

	head, err := FetchRevocationHead(srv.URL+"/api/skills", "", 3*time.Second)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if head["schema_version"] != RevocationHeadSchema {
		t.Errorf("schema_version = %v", head["schema_version"])
	}
	if ep, _ := HeadEpoch(head); ep != 7 {
		t.Errorf("epoch = %d, want 7", ep)
	}
}

func TestFetchRevocationHead_Errors(t *testing.T) {
	// empty URL
	if _, err := FetchRevocationHead("", "", time.Second); err == nil {
		t.Error("want error on empty base URL")
	}
	// non-200
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	if _, err := FetchRevocationHead(bad.URL, "", time.Second); err == nil {
		t.Error("want error on HTTP 500")
	}
	// malformed JSON
	junk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "not json")
	}))
	defer junk.Close()
	if _, err := FetchRevocationHead(junk.URL, "", time.Second); err == nil {
		t.Error("want error on malformed JSON")
	}
}
