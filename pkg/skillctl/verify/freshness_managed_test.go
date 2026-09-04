package verify

import (
	"errors"
	"testing"
	"time"
)

// managedRootYAML builds a valid enterprise-MANAGED trust-roots file (offline_policy
// enterprise: true) with a pinned reviewer but NO max_staleness and NO
// require_signed_governance set. The FR-0090 IS-T5 defaulting must fill both in.
func managedRootYAML(t *testing.T) string {
	t.Helper()
	regKey := validPubkeyB64(t)
	revKey := validPubkeyB64(t)
	return `trust_roots:
  - registry_url: https://managed.example.com/api/skills
    registry_keys:
      - id: k1
        pubkey: ` + regKey + `
        issued: 2026-06-24
    identity_keys_authorized: from-registry
    governance_minimum: green
    reviewers:
      - id: id:reviewer@org
        pubkey: ` + revKey + `
    offline_policy:
      enterprise: true
`
}

// TestManagedTrustRootDefaults is the FR-0090 IS-T5 loader half: a managed root with
// unset knobs is stamped with the fail-closed defaults at Load: max_staleness = 48h
// and require_signed_governance ON. Against the old loader both stay unset (0 / false),
// so the freshness contract has "no ceiling" and governance is advisory.
func TestManagedTrustRootDefaults(t *testing.T) {
	tr, err := Load(writeRootsFile(t, managedRootYAML(t)))
	if err != nil {
		t.Fatalf("managed root should load: %v", err)
	}
	root := tr.Roots[0]
	if !root.IsManaged() {
		t.Fatal("root should be managed (offline_policy.enterprise: true)")
	}
	if root.MaxStaleness != "48h" {
		t.Errorf("managed max_staleness default = %q, want 48h", root.MaxStaleness)
	}
	if !root.RequireSignedGovernance {
		t.Error("managed require_signed_governance default = false, want true (fail-closed)")
	}
	fp, err := root.Freshness()
	if err != nil {
		t.Fatalf("Freshness: %v", err)
	}
	if fp.MaxStaleness != 48*time.Hour {
		t.Errorf("resolved MaxStaleness = %v, want 48h", fp.MaxStaleness)
	}
	if !fp.Managed {
		t.Error("resolved policy.Managed = false, want true")
	}
}

// TestManagedRootStaleHighRiskDenied is the FR-0090 IS-T5 enforcement half: a managed
// root, an unreachable feed (so the last snapshot is old), a clock past the 48h
// ceiling, and a HIGH-risk invocation of a since-revoked digest → DENY with
// ErrRevocationStale. Against the old code the managed root had no ceiling, so
// EvaluateFreshness returned Allowed=true ("no_staleness_ceiling") and the stale
// snapshot would have been trusted. The since-revoked digest would run.
func TestManagedRootStaleHighRiskDenied(t *testing.T) {
	tr, err := Load(writeRootsFile(t, managedRootYAML(t)))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	policy, err := tr.Roots[0].Freshness()
	if err != nil {
		t.Fatalf("Freshness: %v", err)
	}
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	issuedAt := now.Add(-72 * time.Hour).Format(time.RFC3339) // last sync 72h ago > 48h ceiling

	dec, err := EvaluateFreshness(7, issuedAt, policy, RiskHigh, now)
	if err == nil || !errors.Is(err, ErrRevocationStale) {
		t.Fatalf("stale managed high-risk must deny with ErrRevocationStale, got err=%v", err)
	}
	if dec.Allowed {
		t.Error("decision must be denied (Allowed=false)")
	}
	if !dec.Stale {
		t.Error("decision must record Stale=true")
	}
	if dec.Reason != "stale_high_risk_fail_closed" {
		t.Errorf("reason = %q, want stale_high_risk_fail_closed", dec.Reason)
	}
}

// TestManagedPolicyNoCeilingIsBeltAndSuspenders proves the freshness.go guard bites
// even on a HAND-CONSTRUCTED managed policy whose MaxStaleness is 0 (bypassing the
// loader): the effective ceiling is forced to 48h so a stale high-risk action is
// denied. The non-managed control with the same 0 ceiling is ALLOWED. "no ceiling"
// applies ONLY to non-managed roots.
func TestManagedPolicyNoCeilingIsBeltAndSuspenders(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	stale := now.Add(-72 * time.Hour).Format(time.RFC3339)

	// Managed, MaxStaleness deliberately 0 (hand-constructed) → 48h fail-closed.
	managed := FreshnessPolicy{Managed: true} // MaxStaleness == 0
	dec, err := EvaluateFreshness(1, stale, managed, RiskHigh, now)
	if err == nil || !errors.Is(err, ErrRevocationStale) || dec.Allowed {
		t.Fatalf("managed policy with MaxStaleness=0 must still fail closed past 48h; err=%v allowed=%v reason=%q", err, dec.Allowed, dec.Reason)
	}

	// Non-managed, MaxStaleness 0 → genuinely no ceiling (pre-SPEC-0279 default).
	unmanaged := FreshnessPolicy{} // Managed == false, MaxStaleness == 0
	dec2, err2 := EvaluateFreshness(1, stale, unmanaged, RiskHigh, now)
	if err2 != nil || !dec2.Allowed || dec2.Reason != "no_staleness_ceiling" {
		t.Fatalf("non-managed no-ceiling must allow; err=%v allowed=%v reason=%q", err2, dec2.Allowed, dec2.Reason)
	}
}
