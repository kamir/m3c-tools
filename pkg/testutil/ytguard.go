// Package testutil provides shared test helpers for m3c-tools.
//
// YT API Rate-Limit Protection
//
// Tests that call the YouTube API (InnerTube transcript fetches, thumbnail
// downloads, etc.) are skipped by default to prevent accidental rate limiting
// during routine development. To run these tests, pass the test flag:
//
//	go test -v ./e2e/ -yt-calls-enforce-all
//
// Or set the environment variable:
//
//	M3C_YT_CALLS_ENFORCE_ALL=1 go test -v ./e2e/
//
// The Makefile targets `test-network` and `e2e` automatically enable YT calls.
package testutil

import (
	"flag"
	"os"
	"sync"
	"testing"
)

// ytCallsEnforceAll is the flag registered by RegisterYTFlag.
// When true, tests that call the YouTube API are allowed to run.
var ytCallsEnforceAll *bool

var registerOnce sync.Once

// RegisterYTFlag registers the -yt-calls-enforce-all test flag.
// It is safe to call multiple times; only the first call registers.
// Must be called before flag.Parse() (typically in TestMain or init).
func RegisterYTFlag() {
	registerOnce.Do(func() {
		ytCallsEnforceAll = flag.Bool(
			"yt-calls-enforce-all",
			false,
			"Enable tests that call the YouTube API (disabled by default to prevent rate limiting)",
		)
	})
}

// YTCallsAllowed reports whether YT API tests are allowed to run.
// Returns true if either:
//   - The -yt-calls-enforce-all flag is set, or
//   - The M3C_YT_CALLS_ENFORCE_ALL environment variable is non-empty.
func YTCallsAllowed() bool {
	// Environment variable override (works without flag registration)
	if os.Getenv("M3C_YT_CALLS_ENFORCE_ALL") != "" {
		return true
	}
	// Flag check (nil-safe — if RegisterYTFlag was never called, flag is not set)
	if ytCallsEnforceAll != nil && *ytCallsEnforceAll {
		return true
	}
	return false
}

// SkipIfNoYTCalls skips the test with a descriptive message if YT API calls
// are not enabled. Use this at the top of any test that hits YouTube.
//
//	func TestTranscriptFetch(t *testing.T) {
//	    testutil.SkipIfNoYTCalls(t)
//	    // ... test code that calls YouTube API ...
//	}
func SkipIfNoYTCalls(t *testing.T) {
	t.Helper()
	if !YTCallsAllowed() {
		t.Skip("Skipping: YouTube API test (pass -yt-calls-enforce-all flag or set M3C_YT_CALLS_ENFORCE_ALL=1 to enable)")
	}
}
