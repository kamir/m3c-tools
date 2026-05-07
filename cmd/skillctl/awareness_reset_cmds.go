package main

// Stream S2-M2 (Sprint 2 / Stream M2) — `skillctl awareness reset` subcommand.
//
// Pairs with the `DELETE /api/skills/admit-from-scan?session_tag=<tag>`
// endpoint that Stream A builds aims-core-side. SPEC-0195 §4 + §7
// (S2.2 Q-block, locked 2026-05-06):
//
//   - Reset blast radius: ALL docs whose `session_tag == --session`
//     regardless of digest. Other sessions and other clients are out of
//     reach (the destructive scope is intentionally narrow).
//   - Cross-identity safety: server returns 403 if
//     `client_identity != admitted_by_identity`; the CLI surfaces this as
//     exit code 19 (`identity_mismatch`).
//   - G-23 symmetry: `--dry-run` produces an affected-list + a 5-min TTL
//     signature token; `--confirm-reset --dry-run-reset-token <sig>` actually
//     deletes. Both flags are required for the destructive path so a
//     confused operator cannot reset by accident.
//
// File location: this is a NEW file specifically to avoid the merge
// conflict with Stream M1's `awareness_cmds.go` (which owns sync/verify).
// The `awareness` dispatch case in main.go fans out by subcommand —
// `reset` lands here, `sync` and `verify` will land in M1's file.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// awarenessResetMaxTokenAge bounds how long a `--dry-run` signature token
// is valid for. 5 minutes mirrors the G-23 spec text (long enough for the
// operator to inspect the affected list and decide; short enough that a
// stale token in shell history isn't a free destructive primitive).
const awarenessResetMaxTokenAge = 5 * time.Minute

// awarenessResetDryRunResp is the response shape from a `?dry_run=1` GET
// on the reset endpoint. Stream A's handler returns this.
type awarenessResetDryRunResp struct {
	SessionTag    string                   `json:"session_tag"`
	Affected      []map[string]any         `json:"affected"`
	AffectedCount int                      `json:"affected_count"`
	Token         string                   `json:"token"`
	IssuedAt      string                   `json:"issued_at"`
	ExpiresAt     string                   `json:"expires_at"`
}

// awarenessResetConfirmResp is the response shape from a successful DELETE.
type awarenessResetConfirmResp struct {
	SessionTag string `json:"session_tag"`
	Deleted    int    `json:"deleted"`
}

// awarenessResetErr is the error envelope used by the endpoint for
// auth/identity refusals (403) and stale-token / token-mismatch errors
// (409 / 410). Field names mirror the SPEC-0195 §7 admission error shape
// for consistency.
type awarenessResetErr struct {
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// runAwarenessReset is the flag-parser entry point. Network calls happen
// in runAwarenessResetWithClient so tests can inject httptest.Server.
func runAwarenessReset(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("awareness reset", flag.ContinueOnError)
	fs.SetOutput(stderr)

	registryURL := fs.String("registry", "", "Registry base URL.")
	session := fs.String("session", "", "Session tag to reset (required). Only docs whose session_tag matches are affected.")
	dryRun := fs.Bool("dry-run-reset", false, "Preview affected docs and produce a 5-min token; no deletion.")
	dryRunToken := fs.String("dry-run-reset-token", "", "Token from a prior --dry-run-reset; required to confirm the destructive call.")
	confirmReset := fs.Bool("confirm-reset", false, "Required (alongside --dry-run-reset-token) to actually DELETE.")
	timeout := fs.Duration("timeout", registry.DefaultTimeout, "HTTP timeout.")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl awareness reset --session TAG [--dry-run-reset | --confirm-reset --dry-run-reset-token <sig>]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Two-step destructive workflow (SPEC-0195 §4.1 / SPEC-0188 §11b, G-23 symmetry):")
		fmt.Fprintln(stderr, "  1. --dry-run-reset       → list affected docs, print signature token (5-min TTL)")
		fmt.Fprintln(stderr, "  2. --confirm-reset       → DELETE; requires --dry-run-reset-token from step 1")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "The reset is scoped to --session TAG and refuses to cross identities (the")
		fmt.Fprintln(stderr, "registry returns 403 if client_identity != admitted_by_identity).")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Exit codes:")
		fmt.Fprintln(stderr, "   0  ok")
		fmt.Fprintln(stderr, "   1  generic / network / token expired")
		fmt.Fprintln(stderr, "   2  usage / flag error")
		fmt.Fprintln(stderr, "  19  identity mismatch (server refused: client != admitter)")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return exitUsage
	}
	if *session == "" {
		fmt.Fprintln(stderr, "skillctl awareness reset: --session TAG is required.")
		return exitUsage
	}
	if !*dryRun && !*confirmReset {
		fmt.Fprintln(stderr, "skillctl awareness reset: pass --dry-run-reset to preview, then --confirm-reset --dry-run-reset-token <sig> to delete.")
		return exitUsage
	}
	if *dryRun && *confirmReset {
		fmt.Fprintln(stderr, "skillctl awareness reset: --dry-run-reset and --confirm-reset are mutually exclusive.")
		return exitUsage
	}
	if *confirmReset && *dryRunToken == "" {
		fmt.Fprintln(stderr, "skillctl awareness reset: --confirm-reset requires --dry-run-reset-token <sig> from a prior --dry-run-reset.")
		return exitUsage
	}
	if *registryURL == "" {
		fmt.Fprintln(stderr, "skillctl awareness reset: --registry is required.")
		return exitUsage
	}
	if err := validateRegistryURL(*registryURL); err != nil {
		fmt.Fprintf(stderr, "skillctl awareness reset: %v\n", err)
		return exitUsage
	}

	opts := awarenessResetOpts{
		registryURL:  *registryURL,
		session:      *session,
		dryRun:       *dryRun,
		confirmReset: *confirmReset,
		dryRunToken:  *dryRunToken,
		timeout:      *timeout,
	}
	return runAwarenessResetWithClient(opts, stdout, stderr)
}

// awarenessResetOpts is the test-friendly opts struct for
// runAwarenessResetWithClient. All flag-derived values plus optional
// httpClient injection.
type awarenessResetOpts struct {
	registryURL  string
	session      string
	dryRun       bool
	confirmReset bool
	dryRunToken  string
	timeout      time.Duration
	httpClient   *http.Client // injected by tests
	now          func() time.Time
}

// runAwarenessResetWithClient executes the reset workflow against the
// registry. Returns the numeric exit code (0/1/2/19).
func runAwarenessResetWithClient(opts awarenessResetOpts, stdout, stderr io.Writer) int {
	httpClient := opts.httpClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: opts.timeout}
	}
	if opts.now == nil {
		opts.now = time.Now
	}

	endpoint := strings.TrimRight(opts.registryURL, "/") + "/admit-from-scan"

	if opts.dryRun {
		// GET ?session_tag=<tag>&dry_run=1 → returns affected list + token.
		u := endpoint + "?" + url.Values{
			"session_tag": []string{opts.session},
			"dry_run":     []string{"1"},
		}.Encode()
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			fmt.Fprintf(stderr, "skillctl awareness reset: build request: %v\n", err)
			return exitGeneric
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "skillctl/spec-0195-s2-m2")

		resp, err := httpClient.Do(req)
		if err != nil {
			fmt.Fprintf(stderr, "skillctl awareness reset: GET %s: %v\n", u, err)
			return exitGeneric
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))

		if code := classifyResetError(resp.StatusCode, body, stderr); code != 0 {
			return code
		}

		var dr awarenessResetDryRunResp
		if err := json.Unmarshal(body, &dr); err != nil {
			fmt.Fprintf(stderr, "skillctl awareness reset: decode dry-run response: %v\n", err)
			return exitGeneric
		}
		fmt.Fprintf(stdout, "session_tag: %s\n", dr.SessionTag)
		fmt.Fprintf(stdout, "affected: %d\n", dr.AffectedCount)
		for _, a := range dr.Affected {
			out, _ := json.Marshal(a)
			fmt.Fprintf(stdout, "  %s\n", string(out))
		}
		fmt.Fprintf(stdout, "token: %s\n", dr.Token)
		fmt.Fprintf(stdout, "issued_at: %s\n", dr.IssuedAt)
		fmt.Fprintf(stdout, "expires_at: %s\n", dr.ExpiresAt)
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "Re-run with --confirm-reset --dry-run-reset-token <token> within 5 min to delete.")
		return exitOK
	}

	// --confirm-reset path: enforce the 5-min TTL client-side too. The
	// server is the authoritative gate (rejects stale tokens with 410)
	// but checking locally first means we don't burn a network round
	// trip on an obviously-expired token.
	//
	// The token is opaque to the client: format is
	// "<issued_at_unix_seconds>.<hmac_b64url>" (Stream A's choice). We
	// only need to parse the prefix for the staleness check.
	if expired, err := isAwarenessResetTokenExpired(opts.dryRunToken, opts.now()); err != nil {
		fmt.Fprintf(stderr, "skillctl awareness reset: dry-run-reset-token: %v\n", err)
		return exitUsage
	} else if expired {
		fmt.Fprintln(stderr, "skillctl awareness reset: dry-run-reset-token is older than 5 minutes; re-run --dry-run-reset.")
		return exitGeneric
	}

	// DELETE ?session_tag=<tag>&token=<sig>.
	u := endpoint + "?" + url.Values{
		"session_tag": []string{opts.session},
		"token":       []string{opts.dryRunToken},
	}.Encode()
	req, err := http.NewRequest(http.MethodDelete, u, bytes.NewReader(nil))
	if err != nil {
		fmt.Fprintf(stderr, "skillctl awareness reset: build request: %v\n", err)
		return exitGeneric
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "skillctl/spec-0195-s2-m2")

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl awareness reset: DELETE %s: %v\n", u, err)
		return exitGeneric
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))

	if code := classifyResetError(resp.StatusCode, body, stderr); code != 0 {
		return code
	}

	var ok awarenessResetConfirmResp
	if err := json.Unmarshal(body, &ok); err != nil {
		fmt.Fprintf(stderr, "skillctl awareness reset: decode confirm response: %v\n", err)
		return exitGeneric
	}
	fmt.Fprintf(stdout, "session_tag: %s\n", ok.SessionTag)
	fmt.Fprintf(stdout, "deleted: %d\n", ok.Deleted)
	return exitOK
}

// classifyResetError inspects an HTTP response and returns the appropriate
// exit code for a non-2xx outcome. Returns 0 for 2xx (caller continues).
//
// Identity mismatch (403 + reason=identity_mismatch) maps to exit 19 via
// the verify package's sentinel. Other non-2xx → exit 1 (generic) with a
// stderr diagnostic.
func classifyResetError(status int, body []byte, stderr io.Writer) int {
	if status >= 200 && status < 300 {
		return 0
	}
	var e awarenessResetErr
	_ = json.Unmarshal(body, &e)
	switch {
	case status == http.StatusForbidden && e.Reason == "identity_mismatch":
		fmt.Fprintf(stderr, "skillctl awareness reset: refused — client identity does not match the identity that admitted this session.\n")
		if e.Detail != "" {
			fmt.Fprintf(stderr, "detail: %s\n", e.Detail)
		}
		return verify.ExitCode(fmt.Errorf("server: %w", verify.ErrIdentityMismatch))
	case status == http.StatusGone, status == http.StatusConflict:
		// Server rejected the dry-run-token (expired or already used).
		fmt.Fprintf(stderr, "skillctl awareness reset: server rejected the dry-run-token (%s); re-run --dry-run.\n", http.StatusText(status))
		if e.Reason != "" {
			fmt.Fprintf(stderr, "reason: %s\n", e.Reason)
		}
		return exitGeneric
	default:
		fmt.Fprintf(stderr, "skillctl awareness reset: registry returned %d %s\n", status, http.StatusText(status))
		if len(body) > 0 {
			fmt.Fprintf(stderr, "response body: %s\n", string(body))
		}
		return exitGeneric
	}
}

// isAwarenessResetTokenExpired performs a CLIENT-SIDE freshness check on
// the dry-run-token. The server is the authoritative gate; this check
// just spares the network round trip when the token is obviously stale.
//
// Token format (per Stream A's contract): "<issued_unix_seconds>.<sig>".
// Anything not parseable as that shape returns an error so the caller
// surfaces a clear "malformed token" rather than silently passing the
// blob to the server.
func isAwarenessResetTokenExpired(token string, now time.Time) (bool, error) {
	if token == "" {
		return false, errors.New("token is empty")
	}
	dot := strings.IndexByte(token, '.')
	if dot <= 0 {
		return false, fmt.Errorf("token shape: expected <issued>.<sig>, got %q", token)
	}
	prefix := token[:dot]
	var issued int64
	for _, r := range prefix {
		if r < '0' || r > '9' {
			return false, fmt.Errorf("token issued-at prefix %q not numeric", prefix)
		}
		issued = issued*10 + int64(r-'0')
	}
	issuedTime := time.Unix(issued, 0).UTC()
	age := now.UTC().Sub(issuedTime)
	if age < 0 {
		// Clock skew: token claims to be from the future. Treat as
		// fresh — server will reject it if it's actually invalid.
		return false, nil
	}
	return age > awarenessResetMaxTokenAge, nil
}

// _ keeps context imported for future callers; the dispatcher in main.go
// passes args without a ctx today, but follow-on PRs will. Not load-bearing.
var _ = context.Background

// runAwareness is the sub-router for `skillctl awareness <subcommand>`.
//
// Stream ownership (Sprint 2):
//   - reset → Stream M2 (this file).
//   - sync, verify → Stream M1 (cmd/skillctl/awareness_cmds.go, when M1
//     lands; M1 will replace the placeholder cases below with their own
//     `runAwarenessSync` / `runAwarenessVerify` runners).
//
// Until M1 lands, `awareness sync` and `awareness verify` print a clear
// "not yet implemented in this stream" message and exit 2 (usage). This
// shape gives M1 a one-line edit to wire their commands in without
// touching this file or main.go.
// (M1's `runAwareness` + `printAwarenessUsage` in awareness_cmds.go now
// dispatches all three subcommands — sync, verify, reset. The M2 stub
// versions that lived here were removed during the master merge.)
