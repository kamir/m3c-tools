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
// The full closure has four parts, each pinned below and each verified to BITE
// (the test fails when its fix is reverted):
//   R01-A  hot-path (verify-hook) fails closed under managed on a stale/empty cache
//   R01-B  the grace window is AUTHENTICATED (signed HEAD), not a forgeable timestamp
//   R01-C  a present-but-corrupt trust-roots.yaml fails closed (not fail-open)
//   sweep  the sweep consumer fails closed (test-theater fixed to assert exit 22)
//
// while the UNMANAGED/dev path stays fail-open (no spurious hard-deny).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// ---------------------------------------------------------------------------
// sweep consumer (test-theater FIXED)
// ---------------------------------------------------------------------------

// THREAT-R01 (consumer / sweep) — the trust-decision caller fails CLOSED, and the
// assertion now BITES: it requires the quarantine to come from the R01 fail-closed
// branch (exit 22 / reason names the cause), not from the fixture's incidental
// blob-vs-sidecar digest mismatch (exit 10). Both the offline path and the online
// verify are stubbed to PASS, so ONLY the R01 branch can quarantine — reverting it
// makes the skill verify clean and the test FAIL.
func TestSweep_RevocationUnavailableUnderManaged_FailsClosed(t *testing.T) {
	home := t.TempDir()
	writeSidecarDigest(t, home, "er1-push", "sha256:beef")

	stubRootsOK(t)
	stubVerify(t, exitOK, "ok", nil) // sweepVerifyManagedFn → clean
	origOffline := verifyManagedOfflineFn
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) { return exitOK, "verified", true }
	t.Cleanup(func() { verifyManagedOfflineFn = origOffline })

	orig := sweepRevokedFn
	sweepRevokedFn = func(string) (map[string]struct{}, bool, error) {
		return map[string]struct{}{}, false, errRevokedSetUnavailable // managed + unavailable + empty
	}
	t.Cleanup(func() { sweepRevokedFn = orig })

	rep := runSweepReport(t, home, "--quarantine")
	e := findEntry(t, rep, "er1-push")
	if e.State != "quarantined" || e.Exit != exitRevocationStale {
		t.Fatalf("managed skill must FAIL CLOSED via the R01 branch (state=quarantined exit=%d); got state=%q exit=%d reason=%q",
			exitRevocationStale, e.State, e.Exit, e.Reason)
	}
	if !containsAll(e.Reason, "revocation", "WF-001") {
		t.Fatalf("quarantine reason must name the fail-closed cause; got %q", e.Reason)
	}
	if q, _ := quarantined(t, home, "er1-push"); !q {
		t.Fatalf("--quarantine must physically move the skill")
	}
}

// THREAT-R01 (negative / no spurious deny) — UNMANAGED / clean fetch must NOT
// quarantine a managed-looking skill.
func TestSweep_UnmanagedCleanFetch_NoSpuriousDeny(t *testing.T) {
	home := t.TempDir()
	writeSidecarDigest(t, home, "er1-push", "sha256:beef")

	stubRootsOK(t)
	stubVerify(t, exitOK, "ok", nil)

	orig := sweepRevokedFn
	sweepRevokedFn = func(string) (map[string]struct{}, bool, error) {
		return map[string]struct{}{}, false, nil // clean: nothing revoked, no error
	}
	t.Cleanup(func() { sweepRevokedFn = orig })

	_, out := runSweep(t, home, "--quarantine")
	if q, _ := quarantined(t, home, "er1-push"); q {
		t.Fatalf("clean fetch must NOT quarantine (no spurious hard-deny); out=\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// R01-A — verify-hook HOT PATH
// ---------------------------------------------------------------------------

// R01-A (crux) — a KNOWN-revoked managed skill is DENIED per-invocation on a
// stale/empty cache, because the hot path now refreshes the revoked set instead of
// skipping the check between sweeps. BITE: revert the R01-A block → stale cache is
// skipped → the (stubbed-allow) skill is ALLOWED → assertDeny fails.
func TestVerifyHook_HotPath_RevokedOnStaleCache_Denied(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setUserProfile(t, home)
	writeSelfTrustRoots(t, home) // MANAGED → the hot path consults the fetch
	writeSidecarDigest(t, home, "er1-push", "sha256:beef")
	stubHookVerifyAllow(t) // the ONLY possible deny is the revocation check

	// No fresh cache on disk → hot path refreshes; the fetch reports the digest revoked.
	orig := hotPathRevokedFn
	hotPathRevokedFn = func(string) (map[string]struct{}, bool, error) {
		return map[string]struct{}{"sha256:beef": {}}, true, nil
	}
	t.Cleanup(func() { hotPathRevokedFn = orig })

	code, out, _ := feed(t, `{"tool_name":"Skill","tool_input":{"skill":"er1-push"}}`)
	assertDeny(t, code, out, "revoked")
}

// R01-A (fail-closed on unavailable) — a managed host whose hot-path refresh is
// UNAVAILABLE denies rather than runs against an unprovable revocation state.
func TestVerifyHook_HotPath_UnavailableUnderManaged_Denied(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setUserProfile(t, home)
	writeSelfTrustRoots(t, home)
	writeSidecarDigest(t, home, "er1-push", "sha256:beef")
	stubHookVerifyAllow(t)

	orig := hotPathRevokedFn
	hotPathRevokedFn = func(string) (map[string]struct{}, bool, error) {
		return map[string]struct{}{}, false, errRevokedSetUnavailable
	}
	t.Cleanup(func() { hotPathRevokedFn = orig })

	code, out, _ := feed(t, `{"tool_name":"Skill","tool_input":{"skill":"er1-push"}}`)
	assertDeny(t, code, out, "revocation authority unavailable")
}

// R01-A (no spurious deny + latency guard) — a FRESH cache within grace allows and
// the hot path does NOT fetch (zero added latency on the normal path). BITE for the
// latency guard: if the fetch ran on a fresh cache, `called` trips.
func TestVerifyHook_HotPath_FreshCache_NoFetch_Allowed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setUserProfile(t, home)
	writeSelfTrustRoots(t, home)
	writeSidecarDigest(t, home, "er1-push", "sha256:beef")
	stubHookVerifyAllow(t)
	writeRevokedCache(home, map[string]struct{}{"sha256:dead": {}}) // fresh; not our digest

	called := false
	orig := hotPathRevokedFn
	hotPathRevokedFn = func(string) (map[string]struct{}, bool, error) {
		called = true
		return map[string]struct{}{}, false, errRevokedSetUnavailable
	}
	t.Cleanup(func() { hotPathRevokedFn = orig })

	code, out, _ := feed(t, `{"tool_name":"Skill","tool_input":{"skill":"er1-push"}}`)
	assertAllow(t, code, out)
	if called {
		t.Fatalf("hot path fetched despite a FRESH cache — must add no latency to normal invocations")
	}
}

// ---------------------------------------------------------------------------
// R01-B — AUTHENTICATED grace window
// ---------------------------------------------------------------------------

func TestRevokedUnavailableUnderManaged_AuthenticatedGrace(t *testing.T) {
	t.Run("empty cache -> fail closed", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		setUserProfile(t, home)
		if _, online, err := revokedUnavailableUnderManaged(home); !errors.Is(err, errRevokedSetUnavailable) || online {
			t.Fatalf("empty cache must fail closed; got online=%v err=%v", online, err)
		}
	})

	// R01-B BITE — a forged {digests:[],fetched_at:now} (unsigned, same-uid-writable)
	// must NOT open the grace window: without a pinned-key-verified signed HEAD, an
	// attacker could otherwise ride grace forever with an EMPTY set. Reverting R01-B
	// (grace = plain fetched_at freshness) makes this return nil and the test FAIL.
	t.Run("R01-B forged fresh fetched_at, no signed HEAD -> fail closed", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		setUserProfile(t, home)
		writeSelfTrustRoots(t, home)                   // MANAGED, but no signed HEAD persisted
		writeRevokedCache(home, map[string]struct{}{}) // fresh fetched_at, EMPTY set (the forgery)
		if _, _, err := revokedUnavailableUnderManaged(home); !errors.Is(err, errRevokedSetUnavailable) {
			t.Fatalf("forged fresh timestamp without a signed HEAD must NOT open grace; got %v", err)
		}
	})

	// Positive — an AUTHENTICATED basis (verified signed HEAD, recent issued_at,
	// cached set binds to the HEAD's revoked_set_root) DOES open grace.
	t.Run("verified signed HEAD + bound fresh set -> grace open", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		setUserProfile(t, home)
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		writeSelfTrustRootsKey(t, home, pub)
		dg := headTestDigest('a')
		set := map[string]struct{}{dg: {}}
		installSignedHead(t, home, priv, 1, sweepClockFn().UTC(), []string{dg})
		writeRevokedCache(home, set) // fresh + set binds to the HEAD root
		got, _, err := revokedUnavailableUnderManaged(home)
		if err != nil {
			t.Fatalf("authenticated grace must open; got %v", err)
		}
		if _, ok := got[dg]; !ok {
			t.Fatalf("grace path must return the last-known-good set")
		}
	})

	// A verified signed HEAD whose authenticated issued_at is PAST the TTL does not
	// open grace (freshness is judged on the AUTHENTICATED anchor, not fetched_at).
	t.Run("signed HEAD past TTL -> fail closed", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		setUserProfile(t, home)
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		writeSelfTrustRootsKey(t, home, pub)
		dg := headTestDigest('a')
		set := map[string]struct{}{dg: {}}
		old := sweepClockFn().UTC().Add(-2 * revokedCacheTTL)
		installSignedHead(t, home, priv, 1, old, []string{dg})
		writeRevokedCache(home, set) // fetched_at fresh, but the SIGNED anchor is old
		if _, _, err := revokedUnavailableUnderManaged(home); !errors.Is(err, errRevokedSetUnavailable) {
			t.Fatalf("a signed HEAD older than the TTL must NOT open grace; got %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// R01-C — present-but-corrupt trust-roots.yaml
// ---------------------------------------------------------------------------

// R01-C — a PRESENT-but-unparseable trust-roots.yaml is tampering, not "unmanaged":
// it must fail CLOSED, not silently downgrade to fail-open. BITE: reverting R01-C
// (treating any LoadSelfTrustRoots error as unmanaged) returns nil and this FAILS.
func TestFetchRevokedOnline_CorruptTrustRoots_FailsClosed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setUserProfile(t, home)
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "trust-roots.yaml"), []byte("{{{ not: [valid yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fetchRevokedOnline(home); !errors.Is(err, errRevokedSetUnavailable) {
		t.Fatalf("present-but-corrupt trust-roots must fail CLOSED (not fail-open); got %v", err)
	}
}

// The ABSENT case stays fail-OPEN (genuine unmanaged / first-run) — the counterpart
// to R01-C that guards against over-reaching into a hard deny.
func TestFetchRevokedOnline_AbsentTrustRoots_FailOpen(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home) // no ~/.claude/trust-roots.yaml
	setUserProfile(t, home)
	_, online, err := fetchRevokedOnline(home)
	if err != nil {
		t.Fatalf("absent trust-roots (unmanaged) must be fail-OPEN (nil error); got %v", err)
	}
	if online {
		t.Fatalf("unmanaged fetch cannot be 'online' with no trust roots")
	}
}

// ---------------------------------------------------------------------------
// fetchRevokedOnline — MANAGED branch end-to-end (real code path, unreachable reg)
// ---------------------------------------------------------------------------

func TestFetchRevokedOnline_ManagedUnavailable_EndToEnd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setUserProfile(t, home)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	writeSelfTrustRootsKey(t, home, pub) // MANAGED

	// A guaranteed-dead registry endpoint (a just-closed httptest port → dial
	// refused, no hang). An API key is present so resolveER1Config succeeds and the
	// failure is at the fetch, not the config.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	dead := srv.URL
	srv.Close()
	t.Setenv("ER1_TARGET", dead)
	t.Setenv("ER1_API_KEY", "test-key")

	t.Run("empty cache -> fail closed", func(t *testing.T) {
		if _, _, err := fetchRevokedOnline(home); !errors.Is(err, errRevokedSetUnavailable) {
			t.Fatalf("managed + unreachable registry + empty cache must fail closed; got %v", err)
		}
	})

	t.Run("authenticated fresh snapshot -> grace window", func(t *testing.T) {
		dg := headTestDigest('b')
		set := map[string]struct{}{dg: {}}
		installSignedHead(t, home, priv, 2, sweepClockFn().UTC(), []string{dg})
		writeRevokedCache(home, set)
		got, _, err := fetchRevokedOnline(home)
		if err != nil {
			t.Fatalf("managed + unreachable registry + AUTHENTICATED fresh snapshot must ride grace (nil err); got %v", err)
		}
		if _, ok := got[dg]; !ok {
			t.Fatalf("grace path must return the last-known-good set")
		}
	})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// writeSelfTrustRootsKey writes a minimal-but-valid ~/.claude/trust-roots.yaml
// pinning `pub` → the host is treated as MANAGED and `pub` is the verification key.
func writeSelfTrustRootsKey(t *testing.T, home string, pub ed25519.PublicKey) {
	t.Helper()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	yaml := "registry: self\npubkey_b64: " + base64.StdEncoding.EncodeToString(pub) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "trust-roots.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeSelfTrustRoots pins a throwaway key (when the test does not need to sign a HEAD).
func writeSelfTrustRoots(t *testing.T, home string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeSelfTrustRootsKey(t, home, pub)
}

// installSignedHead builds, signs (with priv), and PERSISTS a revocation HEAD to
// ~/.claude/skillctl/revoked-head.signed.json so verifiedAdoptedHead re-verifies it
// against the pinned key. Digests must be full sha256 tokens (validateDigest).
func installSignedHead(t *testing.T, home string, priv ed25519.PrivateKey, epoch int, issuedAt time.Time, digests []string) {
	t.Helper()
	head, err := registry.BuildRevocationHead(registry.RevocationHeadInput{Epoch: epoch, IssuedAt: issuedAt, Digests: digests})
	if err != nil {
		t.Fatalf("build head: %v", err)
	}
	if _, err := registry.SignEnvelopeSignature(priv, head); err != nil {
		t.Fatalf("sign head: %v", err)
	}
	persistSignedHead(home, head)
}

// setUserProfile mirrors HOME into USERPROFILE (WIN-T8) so the temp home is honored
// on every platform's userHome() resolution. Inert on non-Windows.
func setUserProfile(t *testing.T, home string) {
	t.Helper()
	t.Setenv("USERPROFILE", home)
}

// stubHookVerifyAllow makes the managed verify chain PASS so the ONLY possible deny
// in a verify-hook test is the revocation check under test.
func stubHookVerifyAllow(t *testing.T) {
	t.Helper()
	ov, oo := verifyManagedFn, verifyManagedOfflineFn
	verifyManagedFn = func(string, gatePolicy) (int, string) { return exitOK, "ok" }
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) { return exitOK, "ok", true }
	t.Cleanup(func() { verifyManagedFn = ov; verifyManagedOfflineFn = oo })
}

// runSweepReport runs `verify --all --json ...` and returns the parsed report
// (stdout captured separately so the JSON parses cleanly).
func runSweepReport(t *testing.T, home string, args ...string) sweepReport {
	t.Helper()
	t.Setenv("HOME", home)
	var out, errb bytes.Buffer
	_ = runVerify(append([]string{"--all", "--json"}, args...), &out, &errb)
	var rep sweepReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("sweep --json not parseable: %v\nstdout=%s\nstderr=%s", err, out.String(), errb.String())
	}
	return rep
}

func findEntry(t *testing.T, rep sweepReport, name string) sweepEntry {
	t.Helper()
	for _, e := range rep.Entries {
		if e.Skill == name {
			return e
		}
	}
	t.Fatalf("no sweep entry for %q; entries=%+v", name, rep.Entries)
	return sweepEntry{}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(strings.ToLower(s), strings.ToLower(sub)) {
			return false
		}
	}
	return true
}
