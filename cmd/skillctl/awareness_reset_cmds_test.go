package main

// Stream S2-M2 tests for `skillctl awareness reset`.
//
// Coverage matrix (from S2-QUESTIONS.md §5.C acceptance plan):
//
//   TestAwarenessReset_RequiresConfirmReset    — flag-parser refusal
//   TestAwarenessReset_DryRunProducesToken      — dry-run prints the token
//   TestAwarenessReset_TokenExpiresAfter5Min   — client-side 5-min TTL
//   TestAwarenessReset_CrossIdentityExits19    — server 403 → exit 19
//
// Pattern: drive `runAwarenessResetWithClient` directly with a test-built
// opts struct and an httptest.Server-backed http.Client, the same shape
// the intent tests use. A few cases drive `runAwarenessReset` via flag-args
// so the flag-validation gates are also exercised.

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAwarenessReset_RequiresConfirmReset(t *testing.T) {
	// Goal: invoking `awareness reset` with neither --dry-run-reset nor
	// --confirm-reset is a usage error (exit 2). Drives the flag-parser
	// path, so this also exercises the precedence rules.
	args := []string{
		"--registry", "http://127.0.0.1:1",
		"--session", "skill-awareness/host/2026-05-06",
	}
	var stdout, stderr bytes.Buffer
	code := runAwarenessReset(args, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d; stderr=%q", code, exitUsage, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--dry-run-reset") {
		t.Errorf("stderr should mention --dry-run-reset; got: %q", stderr.String())
	}
}

func TestAwarenessReset_DryRunProducesToken(t *testing.T) {
	// Goal: --dry-run-reset hits GET ?dry_run=1, and the returned token + TTL
	// land on stdout for the operator to inspect.
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Method != http.MethodGet {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Query().Get("dry_run") != "1" {
			http.Error(w, "missing dry_run flag", http.StatusBadRequest)
			return
		}
		if got := r.URL.Query().Get("session_tag"); got != "skill-awareness/host/2026-05-06" {
			http.Error(w, "wrong session_tag: "+got, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"session_tag":"skill-awareness/host/2026-05-06",
			"affected":[
				{"name":"didactic-session","local_digest":"sha256:aaa"},
				{"name":"fetch-contract","local_digest":"sha256:bbb"}
			],
			"affected_count":2,
			"token":"1746540000.deadbeef",
			"issued_at":"2026-05-06T15:20:00Z",
			"expires_at":"2026-05-06T15:25:00Z"
		}`))
	}))
	defer srv.Close()

	opts := awarenessResetOpts{
		registryURL: srv.URL,
		session:     "skill-awareness/host/2026-05-06",
		dryRun:      true,
		httpClient:  srv.Client(),
	}
	var stdout, stderr bytes.Buffer
	code := runAwarenessResetWithClient(opts, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, want 0; stderr=%q", code, stderr.String())
	}
	if hits != 1 {
		t.Errorf("server hits = %d, want 1", hits)
	}
	out := stdout.String()
	if !strings.Contains(out, "affected: 2") {
		t.Errorf("stdout missing affected count; got: %q", out)
	}
	if !strings.Contains(out, "token: 1746540000.deadbeef") {
		t.Errorf("stdout missing token; got: %q", out)
	}
}

func TestAwarenessReset_TokenExpiresAfter5Min(t *testing.T) {
	// Goal: a confirm-reset with a token older than 5 min is rejected
	// CLIENT-SIDE (exit 1) without hitting the network.
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	defer srv.Close()

	// Token issued 10 minutes ago.
	staleIssued := time.Now().Add(-10 * time.Minute).Unix()
	staleToken := fmt.Sprintf("%d.deadbeef", staleIssued)

	opts := awarenessResetOpts{
		registryURL:  srv.URL,
		session:      "skill-awareness/host/2026-05-06",
		confirmReset: true,
		dryRunToken:  staleToken,
		httpClient:   srv.Client(),
	}
	var stdout, stderr bytes.Buffer
	code := runAwarenessResetWithClient(opts, &stdout, &stderr)
	if code != exitGeneric {
		t.Fatalf("exit = %d, want %d (generic, stale token); stderr=%q", code, exitGeneric, stderr.String())
	}
	if hits != 0 {
		t.Errorf("server hit %d times on stale token, want 0 (client-side gate)", hits)
	}
	if !strings.Contains(stderr.String(), "older than 5 minutes") {
		t.Errorf("stderr should mention 5-min TTL; got: %q", stderr.String())
	}

	// Sanity: a fresh token (issued just now) DOES reach the network.
	hits = 0
	srvOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"session_tag":"skill-awareness/host/2026-05-06","deleted":3}`))
	}))
	defer srvOK.Close()
	freshToken := fmt.Sprintf("%d.deadbeef", time.Now().Unix())
	opts2 := awarenessResetOpts{
		registryURL:  srvOK.URL,
		session:      "skill-awareness/host/2026-05-06",
		confirmReset: true,
		dryRunToken:  freshToken,
		httpClient:   srvOK.Client(),
	}
	var stdout2, stderr2 bytes.Buffer
	code2 := runAwarenessResetWithClient(opts2, &stdout2, &stderr2)
	if code2 != exitOK {
		t.Fatalf("fresh token: exit = %d, want 0; stderr=%q", code2, stderr2.String())
	}
	if hits != 1 {
		t.Errorf("fresh token: server hits = %d, want 1", hits)
	}
	if !strings.Contains(stdout2.String(), "deleted: 3") {
		t.Errorf("fresh token: stdout missing deleted count; got: %q", stdout2.String())
	}
}

func TestAwarenessReset_CrossIdentityExits19(t *testing.T) {
	// Goal: a server 403 with reason=identity_mismatch maps to exit 19.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"reason":"identity_mismatch","detail":"client_identity != admitted_by_identity"}`))
	}))
	defer srv.Close()

	freshToken := fmt.Sprintf("%d.sig", time.Now().Unix())
	opts := awarenessResetOpts{
		registryURL:  srv.URL,
		session:      "skill-awareness/other-host/2026-05-06",
		confirmReset: true,
		dryRunToken:  freshToken,
		httpClient:   srv.Client(),
	}
	var stdout, stderr bytes.Buffer
	code := runAwarenessResetWithClient(opts, &stdout, &stderr)
	if code != 19 {
		t.Fatalf("exit = %d, want 19 (ExitIdentityMismatch); stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "identity") {
		t.Errorf("stderr should mention identity; got: %q", stderr.String())
	}
}
