package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/pin"
	"github.com/kamir/m3c-tools/pkg/skillctl/statemachine"
)

// testPubkeyB64 is a syntactically valid base64 of 32 zero bytes — enough for
// the trust-roots loader's length + base64 validation (these tests never verify
// a signature).
func testPubkeyB64() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 32))
}

// withSessionBaselineSeams installs test seams and restores them on cleanup.
func withSessionBaselineSeams(t *testing.T, in statemachine.Inputs, pinRes pin.StatusResult) {
	t.Helper()
	origGather := sessionBaselineGather
	origPin := sessionBaselinePinStatus
	origNow := sessionBaselineNow
	sessionBaselineGather = func(home string, forceOnline bool, now time.Time) statemachine.Inputs {
		cp := in
		cp.RegistryReachable = in.RegistryReachable || forceOnline
		cp.Now = now
		return cp
	}
	sessionBaselinePinStatus = func(path string) pin.StatusResult { return pinRes }
	sessionBaselineNow = func() time.Time { return time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() {
		sessionBaselineGather = origGather
		sessionBaselinePinStatus = origPin
		sessionBaselineNow = origNow
	})
}

// TestSessionBaseline_AdvisoryBannerWhenNotPinned is the AC-8 fallback: the RED
// advisory-until-pinned banner must appear when the gate is NOT pinned.
func TestSessionBaseline_AdvisoryBannerWhenNotPinned(t *testing.T) {
	home := t.TempDir()
	in := statemachine.Inputs{RegistryReachable: true, TrustBasisPresent: true}
	withSessionBaselineSeams(t, in, pin.StatusResult{Level: pin.LevelAbsent})

	var out, errb bytes.Buffer
	code := runSessionBaseline([]string{"--home", home}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (informational). stderr=%s", code, errb.String())
	}
	if !strings.Contains(out.String(), advisoryUntilPinnedMsg) {
		t.Fatalf("expected advisory banner %q in output:\n%s", advisoryUntilPinnedMsg, out.String())
	}
	if !strings.Contains(out.String(), "online") {
		t.Fatalf("expected the online state in output:\n%s", out.String())
	}
}

// TestSessionBaseline_NoBannerWhenPinned: a pinned gate must NOT print the
// advisory banner.
func TestSessionBaseline_NoBannerWhenPinned(t *testing.T) {
	home := t.TempDir()
	in := statemachine.Inputs{RegistryReachable: false, TrustBasisPresent: true}
	withSessionBaselineSeams(t, in, pin.StatusResult{Level: pin.LevelPinned, HasSweepHook: true, HasVerifyHook: true})

	var out, errb bytes.Buffer
	if code := runSessionBaseline([]string{"--home", home}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if strings.Contains(out.String(), advisoryUntilPinnedMsg) {
		t.Fatalf("advisory banner must NOT appear when pinned:\n%s", out.String())
	}
	// Disconnected but fresh (no ceilings) → degraded.
	if !strings.Contains(out.String(), "degraded") {
		t.Fatalf("expected degraded state:\n%s", out.String())
	}
}

// TestSessionBaseline_JSON emits the decision + pin fields.
func TestSessionBaseline_JSON(t *testing.T) {
	home := t.TempDir()
	in := statemachine.Inputs{RegistryReachable: true, TrustBasisPresent: true}
	withSessionBaselineSeams(t, in, pin.StatusResult{Level: pin.LevelAbsent})

	var out, errb bytes.Buffer
	if code := runSessionBaseline([]string{"--home", home, "--json"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, want 0. stderr=%s", code, errb.String())
	}
	var doc struct {
		State          string `json:"state"`
		Pinned         bool   `json:"pinned"`
		AdvisoryBanner string `json:"advisory_banner"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}
	if doc.State != "online" {
		t.Errorf("state = %q, want online", doc.State)
	}
	if doc.Pinned {
		t.Errorf("pinned = true, want false (LevelAbsent)")
	}
	if doc.AdvisoryBanner != advisoryUntilPinnedMsg {
		t.Errorf("advisory_banner = %q, want %q", doc.AdvisoryBanner, advisoryUntilPinnedMsg)
	}
}

// TestResolveSessionOfflinePolicy_EnterpriseWins: an enterprise root's policy is
// selected machine-wide, and a non-enterprise/absent config yields the shipped
// default (never locks).
func TestResolveSessionOfflinePolicy(t *testing.T) {
	home := t.TempDir()
	trPath := filepath.Join(home, ".claude", "skill-trust-roots.yaml")
	if err := os.MkdirAll(filepath.Dir(trPath), 0o700); err != nil {
		t.Fatal(err)
	}

	// A valid trust-roots with an enterprise offline_policy on the second root.
	yaml := `trust_roots:
  - registry_url: https://a.example.com/api/skills
    registry_keys:
      - id: k1
        pubkey: ` + testPubkeyB64() + `
    identity_keys_authorized: from-registry
    governance_minimum: green
  - registry_url: https://b.example.com/api/skills
    registry_keys:
      - id: k2
        pubkey: ` + testPubkeyB64() + `
    identity_keys_authorized: from-registry
    governance_minimum: green
    offline_policy:
      enterprise: true
      max_policy_cache_age: 24h
      max_revocation_cache_age: 12h
      require_local_audit: true
`
	if err := os.WriteFile(trPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	pol, note := resolveSessionOfflinePolicy(home, trPath)
	if !pol.Enterprise {
		t.Fatalf("expected enterprise policy selected, note=%q", note)
	}
	if pol.MaxPolicyCacheAge != 24*time.Hour {
		t.Errorf("MaxPolicyCacheAge = %v, want 24h", pol.MaxPolicyCacheAge)
	}
	if pol.MaxRevocationCacheAge != 12*time.Hour {
		t.Errorf("MaxRevocationCacheAge = %v, want 12h", pol.MaxRevocationCacheAge)
	}
	if !pol.RequireLocalAudit {
		t.Errorf("RequireLocalAudit not carried through")
	}

	// Missing file → zero policy (never locks) + a note.
	pol2, note2 := resolveSessionOfflinePolicy(home, filepath.Join(home, "nope.yaml"))
	if pol2.Enterprise {
		t.Errorf("missing trust-roots must yield a non-enterprise default")
	}
	if note2 == "" {
		t.Errorf("expected a note explaining the fallback default")
	}
}

// TestResolveSessionOfflinePolicy_RejectsRequireLocalAuditWithoutEnterprise:
// Load must refuse require_local_audit without enterprise (R-7.3/R-8), so the
// baseline surfaces the fallback note rather than silently honouring it.
func TestResolveSessionOfflinePolicy_RejectsRequireLocalAuditWithoutEnterprise(t *testing.T) {
	home := t.TempDir()
	trPath := filepath.Join(home, "roots.yaml")
	yaml := `trust_roots:
  - registry_url: https://a.example.com/api/skills
    registry_keys:
      - id: k1
        pubkey: ` + testPubkeyB64() + `
    identity_keys_authorized: from-registry
    governance_minimum: green
    offline_policy:
      require_local_audit: true
`
	if err := os.WriteFile(trPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, note := resolveSessionOfflinePolicy(home, trPath)
	if pol.RequireLocalAudit || pol.Enterprise {
		t.Fatalf("require_local_audit without enterprise must be rejected at Load, got pol=%+v", pol)
	}
	if !strings.Contains(note, "unreadable") {
		t.Errorf("expected a fallback note about the unreadable/invalid config, got %q", note)
	}
}
