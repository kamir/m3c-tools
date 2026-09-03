package main

// Regression tests for WF-001 H-F1 / THREAT-R01 — revocation-SUPPRESSION.
//
// The bug: fetchRevokedOnline "failed OPEN on availability" — on ANY fetch error
// it returned the (possibly EMPTY) cache with online=false and NEVER an error. On
// a fresh machine, or after an attacker clears the cache and blocks the network /
// serves a hostile 5xx / redirects to a dead host, the empty set meant a KNOWN-
// revoked digest was not blocked: revocation was silently suppressed by making the
// fetch fail.
//
// The fix makes the revoked-set consumers fail CLOSED under MANAGED (self-trust-
// root) config while keeping the UNMANAGED/dev path fail-open. These tests pin
// both halves so the fail-open cannot regress.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// THREAT-R01 (consumer / sweep) — the trust-decision caller fails CLOSED.
//
// With a MANAGED host whose revoked-set fetch is unavailable and whose cache is
// empty (sweepRevokedFn returns errRevokedSetUnavailable), the sweep must
// QUARANTINE the managed skill rather than read the empty set as "nothing
// revoked". This is the exact suppression vector the wave-1 challenge gate
// flagged: a KNOWN-revoked digest must NOT be allowed to keep running just
// because the fetch was made to fail.
func TestSweep_RevocationUnavailableUnderManaged_FailsClosed(t *testing.T) {
	home := t.TempDir()
	// A managed, otherwise-fine skill whose digest is NOT in any (empty) local set.
	writeSidecarDigest(t, home, "er1-push", "sha256:beef")

	// Simulate MANAGED + revoked-set fetch unavailable + empty cache.
	orig := sweepRevokedFn
	sweepRevokedFn = func(string) (map[string]struct{}, bool, error) {
		return map[string]struct{}{}, false, errRevokedSetUnavailable
	}
	t.Cleanup(func() { sweepRevokedFn = orig })

	code, out := runSweep(t, home, "--quarantine")
	_ = code
	if q, _ := quarantined(t, home, "er1-push"); !q {
		t.Fatalf("managed skill must FAIL CLOSED (be quarantined) when revocation is unavailable under managed trust roots; not quarantined.\nout=\n%s", out)
	}
}

// THREAT-R01 (report-only) — the fail-closed is advisory without --quarantine, so
// the SessionStart sweep does not destructively move skills, but the state IS
// surfaced (RevocationUnavailable) for observability.
func TestSweep_RevocationUnavailableUnderManaged_ReportOnly(t *testing.T) {
	home := t.TempDir()
	writeSidecarDigest(t, home, "er1-push", "sha256:beef")

	orig := sweepRevokedFn
	sweepRevokedFn = func(string) (map[string]struct{}, bool, error) {
		return map[string]struct{}{}, false, errRevokedSetUnavailable
	}
	t.Cleanup(func() { sweepRevokedFn = orig })

	// No --quarantine → report-only: NOT physically moved, but reported closed.
	_, out := runSweep(t, home) // report-only
	if q, _ := quarantined(t, home, "er1-push"); q {
		t.Fatalf("report-only sweep must NOT physically move the skill; it was quarantined")
	}
	if !containsAll(out, "fail", "revocation") {
		t.Fatalf("report-only sweep must SURFACE the fail-closed state; out=\n%s", out)
	}
}

// THREAT-R01 (negative / no spurious deny) — UNMANAGED / dev must still work.
//
// When the revoked-set fetch returns cleanly with nothing revoked and NO error
// (the unmanaged/dev best-effort path), a managed-looking skill must NOT be
// quarantined. Guards against the fix over-reaching into a hard deny that would
// break first-run / offline dev.
func TestSweep_UnmanagedCleanFetch_NoSpuriousDeny(t *testing.T) {
	home := t.TempDir()
	writeSidecarDigest(t, home, "er1-push", "sha256:beef")

	stubRootsOK(t)
	stubVerify(t, exitOK, "ok", nil)

	orig := sweepRevokedFn
	sweepRevokedFn = func(string) (map[string]struct{}, bool, error) {
		return map[string]struct{}{}, false, nil // unmanaged/clean: nothing revoked, no error
	}
	t.Cleanup(func() { sweepRevokedFn = orig })

	_, out := runSweep(t, home, "--quarantine")
	if q, _ := quarantined(t, home, "er1-push"); q {
		t.Fatalf("clean unmanaged fetch must NOT quarantine (no spurious hard-deny); out=\n%s", out)
	}
}

// fetchRevokedOnline (real function) — UNMANAGED branch stays fail-OPEN.
//
// No self-trust-roots.yaml under $HOME → fetchRevokedOnline must return the cache
// with online=false and NO error, so offline keygen/pack/sign/verify-sig + first
// run keep working.
func TestFetchRevokedOnline_UnmanagedFailOpen(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)  // no ~/.claude/trust-roots.yaml here → unmanaged
	setUserProfile(t, home) // WIN-T8: keep a shipping-style resolve scoped to temp
	_, online, err := fetchRevokedOnline(home)
	if err != nil {
		t.Fatalf("unmanaged fetch must be fail-OPEN (nil error); got %v", err)
	}
	if online {
		t.Fatalf("unmanaged fetch cannot be 'online' with no trust roots")
	}
}

// revokedUnavailableUnderManaged (helper) — the GRACE WINDOW.
//
//   - empty/absent cache → fail-CLOSED (errRevokedSetUnavailable);
//   - fresh cache (within TTL) → fail-OPEN (nil error): last-known-good still
//     bounds staleness;
//   - stale cache (past TTL) → fail-CLOSED again.
func TestRevokedUnavailableUnderManaged_GraceWindow(t *testing.T) {
	t.Run("empty cache -> fail closed", func(t *testing.T) {
		home := t.TempDir()
		_, online, err := revokedUnavailableUnderManaged(home)
		if !errors.Is(err, errRevokedSetUnavailable) {
			t.Fatalf("empty cache must fail closed; got err=%v", err)
		}
		if online {
			t.Fatalf("must not report online on the fail-closed path")
		}
	})

	t.Run("fresh cache -> grace window (fail open)", func(t *testing.T) {
		home := t.TempDir()
		writeRevokedCache(home, map[string]struct{}{"sha256:beef": {}}) // fetched_at = now → fresh
		set, _, err := revokedUnavailableUnderManaged(home)
		if err != nil {
			t.Fatalf("a within-TTL last-known-good cache is the grace window; must not fail closed; got %v", err)
		}
		if _, ok := set["sha256:beef"]; !ok {
			t.Fatalf("grace-window path must return the cached last-known-good set")
		}
	})

	t.Run("stale cache -> fail closed", func(t *testing.T) {
		home := t.TempDir()
		p := revokedCachePath(home)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		// A long-past fetched_at → outside revokedCacheTTL → no grace.
		stale := `{"digests":["sha256:beef"],"fetched_at":"2000-01-01T00:00:00Z"}`
		if err := os.WriteFile(p, []byte(stale), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := revokedUnavailableUnderManaged(home); !errors.Is(err, errRevokedSetUnavailable) {
			t.Fatalf("a stale (past-TTL) cache must fail closed; got err=%v", err)
		}
	})
}

// fetchRevokedOnline (real function) — MANAGED branch, end-to-end.
//
// With a real self-trust-roots.yaml (managed) and a registry that is unreachable,
// the live fetch fails: with an empty cache fetchRevokedOnline must surface
// errRevokedSetUnavailable (fail-closed); with a fresh cache it must ride the
// grace window (nil error, last-known-good returned). This proves the managed-vs-
// unmanaged distinction on the REAL code path, not just the helper.
func TestFetchRevokedOnline_ManagedUnavailable_FailsClosed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setUserProfile(t, home)
	writeSelfTrustRoots(t, home) // → MANAGED

	// A guaranteed-dead registry endpoint (a just-closed httptest port → dial
	// refused, no hang), reached via ER1_TARGET. An API key is present so
	// resolveER1Config succeeds and the failure is at the fetch, not the config.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	dead := srv.URL
	srv.Close()
	t.Setenv("ER1_TARGET", dead)
	t.Setenv("ER1_API_KEY", "test-key")

	t.Run("empty cache -> fail closed", func(t *testing.T) {
		if _, _, err := fetchRevokedOnline(home); !errors.Is(err, errRevokedSetUnavailable) {
			t.Fatalf("managed + unreachable registry + empty cache must fail closed; got err=%v", err)
		}
	})

	t.Run("fresh cache -> grace window", func(t *testing.T) {
		writeRevokedCache(home, map[string]struct{}{"sha256:beef": {}}) // fresh
		set, _, err := fetchRevokedOnline(home)
		if err != nil {
			t.Fatalf("managed + unreachable registry + FRESH cache must ride the grace window (nil err); got %v", err)
		}
		if _, ok := set["sha256:beef"]; !ok {
			t.Fatalf("grace-window path must return the cached last-known-good set")
		}
	})
}

// --- helpers ---

// writeSelfTrustRoots writes a minimal-but-valid ~/.claude/trust-roots.yaml so
// LoadSelfTrustRoots succeeds → the host is treated as MANAGED. Only pubkey_b64
// is required (registry defaults to "self", governance to "green", fingerprint is
// recomputed on load).
func writeSelfTrustRoots(t *testing.T, home string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	yaml := "registry: self\npubkey_b64: " + base64.StdEncoding.EncodeToString(pub) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "trust-roots.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
}

// setUserProfile mirrors HOME into USERPROFILE (WIN-T8) so the temp home is honored
// on every platform's userHome() resolution. Inert on non-Windows.
func setUserProfile(t *testing.T, home string) {
	t.Helper()
	t.Setenv("USERPROFILE", home)
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(strings.ToLower(s), strings.ToLower(sub)) {
			return false
		}
	}
	return true
}
