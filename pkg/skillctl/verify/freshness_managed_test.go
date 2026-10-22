package verify

import (
	"errors"
	"strings"
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
// unset knobs is stamped with the fail-closed defaults at Load: max_staleness = 24h
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
	if root.MaxStaleness != "24h" {
		t.Errorf("managed max_staleness default = %q, want 24h", root.MaxStaleness)
	}
	if !root.RequireSignedGovernance {
		t.Error("managed require_signed_governance default = false, want true (fail-closed)")
	}
	fp, err := root.Freshness()
	if err != nil {
		t.Fatalf("Freshness: %v", err)
	}
	if fp.MaxStaleness != 24*time.Hour {
		t.Errorf("resolved MaxStaleness = %v, want 24h", fp.MaxStaleness)
	}
	if !fp.Managed {
		t.Error("resolved policy.Managed = false, want true")
	}
}

// TestManagedRootStaleHighRiskDenied is the FR-0090 IS-T5 enforcement half: a managed
// root, an unreachable feed (so the last snapshot is old), a clock past the 24h
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
	issuedAt := now.Add(-72 * time.Hour).Format(time.RFC3339) // last sync 72h ago > 24h ceiling

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
// loader): the effective ceiling is forced to 24h so a stale high-risk action is
// denied. The non-managed control with the same 0 ceiling is ALLOWED. "no ceiling"
// applies ONLY to non-managed roots.
func TestManagedPolicyNoCeilingIsBeltAndSuspenders(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	stale := now.Add(-72 * time.Hour).Format(time.RFC3339)

	// Managed, MaxStaleness deliberately 0 (hand-constructed) → 24h fail-closed.
	managed := FreshnessPolicy{Managed: true} // MaxStaleness == 0
	dec, err := EvaluateFreshness(1, stale, managed, RiskHigh, now)
	if err == nil || !errors.Is(err, ErrRevocationStale) || dec.Allowed {
		t.Fatalf("managed policy with MaxStaleness=0 must still fail closed past 24h; err=%v allowed=%v reason=%q", err, dec.Allowed, dec.Reason)
	}

	// Non-managed, MaxStaleness 0 → genuinely no ceiling (pre-SPEC-0279 default).
	unmanaged := FreshnessPolicy{} // Managed == false, MaxStaleness == 0
	dec2, err2 := EvaluateFreshness(1, stale, unmanaged, RiskHigh, now)
	if err2 != nil || !dec2.Allowed || dec2.Reason != "no_staleness_ceiling" {
		t.Fatalf("non-managed no-ceiling must allow; err=%v allowed=%v reason=%q", err2, dec2.Allowed, dec2.Reason)
	}
}

func managedFreshnessTestHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_TOKEN_STORE", "file")
	t.Setenv("M3C_TEST_KEYCHAIN", "0")
}

func TestManagedFreshness24HourConfiguration(t *testing.T) {
	managedFreshnessTestHome(t)
	for _, tc := range []struct {
		value string
		want  time.Duration
		valid bool
	}{
		{"", 24 * time.Hour, true},
		{"0s", 24 * time.Hour, true},
		{"24h", 24 * time.Hour, true},
		{"12h", 12 * time.Hour, true},
		{"24h1s", 0, false},
		{"72h", 0, false},
		{"-1h", 0, false},
		{"invalid", 0, false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			yaml := managedRootYAML(t)
			if tc.value != "" {
				yaml = strings.Replace(yaml, "    governance_minimum: green", "    governance_minimum: green\n    max_staleness: "+tc.value, 1)
			}
			roots, err := ParseTrustRoots([]byte(yaml))
			if !tc.valid {
				if err == nil || roots != nil {
					t.Fatal("invalid managed ceiling loaded")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			root := roots.Roots[0]
			raw, err := time.ParseDuration(root.MaxStaleness)
			if err != nil || raw != tc.want {
				t.Fatalf("raw policy can bypass bound: %s", root.MaxStaleness)
			}
			policy, err := root.Freshness()
			if err != nil || policy.MaxStaleness != tc.want {
				t.Fatalf("resolved policy mismatch: %+v %v", policy, err)
			}
		})
	}
}

func TestManagedFreshness24HourBoundary(t *testing.T) {
	managedFreshnessTestHome(t)
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	for _, ceiling := range []time.Duration{0, 24 * time.Hour, 72 * time.Hour, -time.Hour} {
		for _, tc := range []struct {
			name, issued string
			allowed      bool
		}{
			{"exact", now.Add(-24 * time.Hour).Format(time.RFC3339), true},
			{"older", now.Add(-24*time.Hour - time.Second).Format(time.RFC3339), false},
			{"missing", "", false},
			{"invalid", "not-a-timestamp", false},
			{"future", now.Add(5*time.Minute + time.Second).Format(time.RFC3339), false},
		} {
			t.Run(ceiling.String()+"/"+tc.name, func(t *testing.T) {
				decision, err := EvaluateFreshness(1, tc.issued, FreshnessPolicy{Managed: true, MaxStaleness: ceiling, FailPolicy: FailOpen}, RiskHigh, now)
				if decision.MaxStalenessSeconds != 86400 || decision.Allowed != tc.allowed {
					t.Fatalf("managed ceiling bypass: %+v %v", decision, err)
				}
				if tc.allowed && err != nil {
					t.Fatal(err)
				}
				if !tc.allowed && !errors.Is(err, ErrRevocationStale) {
					t.Fatalf("stale denial cause lost: %v", err)
				}
			})
		}
	}
	// Existing low-risk fail-open is separate from the ceiling and stays explicit.
	decision, err := EvaluateFreshness(1, now.Add(-25*time.Hour).Format(time.RFC3339), FreshnessPolicy{Managed: true, FailPolicy: FailOpen}, RiskLow, now)
	if err != nil || !decision.Stale || !decision.Allowed {
		t.Fatalf("existing low-risk audited disposition changed: %+v %v", decision, err)
	}
	for _, duration := range []time.Duration{0, 72 * time.Hour} {
		root := &TrustRoot{MaxStaleness: duration.String()}
		policy, err := root.Freshness()
		if err != nil || policy.Managed || policy.MaxStaleness != duration {
			t.Fatalf("unmanaged development/offline policy changed: %+v %v", policy, err)
		}
	}
}
