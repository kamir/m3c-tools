// Package testutil provides shared test helpers for m3c-tools.
//
// External-dependency skip helpers (the opt-out trust-test mechanism)
//
// The trust-layer test surface (pkg/skillctl/..., cmd/skillctl/...,
// evaluation/...) runs WHOLE-PACKAGE on the windows-latest CI runner — there
// is no hand-maintained -run allow-list. To make that durable, any test that
// depends on something the Windows CI job (or a routine `go test`) does not
// provide — a live ER1 server, the whisper binary, real network egress, a
// microphone, or the Plaud cloud API — must call one of the Require* helpers
// below at its top. Each helper calls t.Skip(reason) when the dependency is
// absent, on EVERY platform. Because the Windows CI job sets none of the
// gating envs, those tests skip there cleanly with a clear reason and no
// Windows-special-casing; on a developer box or a dedicated integration runner
// the same env opts them back in.
//
// Env / probe convention (reuses the existing M3C_TEST_* scheme):
//
//	M3C_TEST_ER1=1        — a live ER1 server is available (ER1_API_URL points at it)
//	M3C_TEST_NETWORK=1    — outbound network egress is permitted
//	M3C_TEST_WHISPER=1    — the whisper binary is installed (also probed via PATH)
//	M3C_TEST_MIC=1        — a recording microphone + PortAudio are available
//	M3C_TEST_PLAUD=1      — the Plaud cloud API is reachable with a valid token
//
// New trust tests are covered by the windows job automatically. The ONLY tests
// excluded from the Windows run are the ones that self-skip through these
// helpers — never via a CI allow-list. Do not reintroduce an allow-list.
package testutil

import (
	"os"
	"os/exec"
	"testing"
)

// envEnabled reports whether the named env var is set to a truthy value.
// Any non-empty value other than "0"/"false" counts as enabled, matching the
// loose M3C_TEST_PLAUD=1 convention already used in e2e/.
func envEnabled(name string) bool {
	v := os.Getenv(name)
	return v != "" && v != "0" && v != "false"
}

// RequireER1 skips the test unless a live ER1 server is available. Tests that
// exercise an in-process httptest fake do NOT need this — only tests that dial
// a real aims-core / ER1 instance. Enable with M3C_TEST_ER1=1 (and point
// ER1_API_URL at the server).
func RequireER1(t *testing.T) {
	t.Helper()
	if !envEnabled("M3C_TEST_ER1") {
		t.Skip("Skipping: requires a live ER1 server (set M3C_TEST_ER1=1 and ER1_API_URL to enable)")
	}
}

// RequireNetwork skips the test unless outbound network egress is permitted.
// Use for any test that reaches a real remote host (not an httptest server).
// Enable with M3C_TEST_NETWORK=1.
func RequireNetwork(t *testing.T) {
	t.Helper()
	if !envEnabled("M3C_TEST_NETWORK") {
		t.Skip("Skipping: requires network egress (set M3C_TEST_NETWORK=1 to enable)")
	}
}

// RequireWhisper skips the test unless the whisper CLI binary is available.
// It first honours M3C_TEST_WHISPER=1, then falls back to probing PATH so a
// developer with whisper installed gets coverage without setting any env.
func RequireWhisper(t *testing.T) {
	t.Helper()
	if envEnabled("M3C_TEST_WHISPER") {
		return
	}
	for _, bin := range []string{"whisper", "whisper-cpp", "main"} {
		if _, err := exec.LookPath(bin); err == nil {
			return
		}
	}
	t.Skip("Skipping: requires the whisper binary on PATH (or set M3C_TEST_WHISPER=1)")
}

// RequireMic skips the test unless a microphone + PortAudio are available.
// There is no portable host probe for an input device, so this gates purely on
// M3C_TEST_MIC=1 — set it on the (Unix) runner that actually has hardware.
func RequireMic(t *testing.T) {
	t.Helper()
	if !envEnabled("M3C_TEST_MIC") {
		t.Skip("Skipping: requires a microphone + PortAudio (set M3C_TEST_MIC=1 to enable)")
	}
}

// RequirePlaud skips the test unless the Plaud cloud API is reachable with a
// valid token. Enable with M3C_TEST_PLAUD=1 (the token is harvested out of
// band; see the plaud sync flow). Mirrors the existing e2e/plaud gate.
func RequirePlaud(t *testing.T) {
	t.Helper()
	if !envEnabled("M3C_TEST_PLAUD") {
		t.Skip("Skipping: requires the Plaud cloud API (set M3C_TEST_PLAUD=1 to enable)")
	}
}
