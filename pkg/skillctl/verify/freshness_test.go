package verify

// SPEC-0279 R2 + R3 — freshness policy + staleness fail-policy core tests.
//
// AC1 — a lower-epoch revocation list is refused (rollback test; regression of
//        the R1 floor that this SPEC builds on).
// AC2 — past max_staleness a HIGH-risk action fails closed; a LOW-risk action
//        follows fail_policy (both branches).
// Plus: policy parsing/validation, action-risk classification (incl. the
// red-team "downgrade high→low" guard), and the clock-injection property.

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// --- AC1: rollback (lower epoch refused) — regression of the R1 floor ---

func TestAC1_LowerEpochRevocationListRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := revocationRoot(t, pub)
	// A genuinely-signed list at epoch 3.
	list, err := NewSignedRevocationList(root.RegistryURL, "2026-06-22T10:00:00Z", 3, []string{digestOf("x")}, priv)
	if err != nil {
		t.Fatal(err)
	}
	// Verifier has pinned floor 5 → epoch-3 list refused even though signed.
	if _, err := VerifyRevocationList(list, root, 5); !errors.Is(err, ErrRegistryNotTrusted) {
		t.Fatalf("lower-epoch signed list must be refused (rollback), got: %v", err)
	}
	// At/above the floor it verifies.
	if _, err := VerifyRevocationList(list, root, 3); err != nil {
		t.Fatalf("epoch == floor must verify, got: %v", err)
	}
}

// --- R2: freshness policy parsing + validation ---

func TestFreshnessPolicy_Defaults(t *testing.T) {
	tr := &TrustRoot{} // all freshness fields empty.
	p, err := tr.Freshness()
	if err != nil {
		t.Fatal(err)
	}
	if p.MaxStaleness != 0 {
		t.Errorf("default max_staleness = %v, want 0 (no ceiling)", p.MaxStaleness)
	}
	if p.CacheTTL != defaultCacheTTL {
		t.Errorf("default cache_ttl = %v, want %v", p.CacheTTL, defaultCacheTTL)
	}
	if p.FailPolicy != FailClosed {
		t.Errorf("default fail_policy = %q, want closed", p.FailPolicy)
	}
}

func TestFreshnessPolicy_Parses(t *testing.T) {
	tr := &TrustRoot{
		MaxStaleness:     "24h",
		CacheTTL:         "6h",
		FailPolicy:       "open",
		FailPolicyByRisk: map[string]string{"low": "open", "high": "closed"},
	}
	p, err := tr.Freshness()
	if err != nil {
		t.Fatal(err)
	}
	if p.MaxStaleness != 24*time.Hour {
		t.Errorf("max_staleness = %v, want 24h", p.MaxStaleness)
	}
	if p.CacheTTL != 6*time.Hour {
		t.Errorf("cache_ttl = %v, want 6h", p.CacheTTL)
	}
	if p.PolicyFor(RiskLow) != FailOpen {
		t.Errorf("low-risk policy = %q, want open", p.PolicyFor(RiskLow))
	}
	// High-risk is floored to closed even with explicit override.
	if p.PolicyFor(RiskHigh) != FailClosed {
		t.Errorf("high-risk policy = %q, want closed (floored)", p.PolicyFor(RiskHigh))
	}
}

func TestFreshnessPolicy_RejectsBadValues(t *testing.T) {
	cases := []TrustRoot{
		{MaxStaleness: "-1h"},                                    // negative
		{MaxStaleness: "notaduration"},                           // unparseable
		{FailPolicy: "halfopen"},                                 // unknown policy
		{FailPolicyByRisk: map[string]string{"high": "open"}},    // R3 floor violation
		{FailPolicyByRisk: map[string]string{"bogus": "closed"}}, // unknown risk key
	}
	for i, tr := range cases {
		trc := tr
		if _, err := trc.Freshness(); err == nil {
			t.Errorf("case %d: expected validation error, got nil (%+v)", i, tr)
		}
	}
}

// --- R3: staleness → fail-policy decision (AC2) ---

func freshPolicy(t *testing.T, maxStale string, fail string, byRisk map[string]string) FreshnessPolicy {
	t.Helper()
	tr := &TrustRoot{MaxStaleness: maxStale, FailPolicy: fail, FailPolicyByRisk: byRisk}
	p, err := tr.Freshness()
	if err != nil {
		t.Fatalf("policy build: %v", err)
	}
	return p
}

func TestAC2_StaleHighRiskFailsClosed(t *testing.T) {
	p := freshPolicy(t, "24h", "open", nil) // even fail_policy=open...
	issued := "2026-06-20T00:00:00Z"
	now := mustTime(t, "2026-06-22T00:00:00Z") // 48h old > 24h ceiling
	dec, err := EvaluateFreshness(7, issued, p, RiskHigh, now)
	if !errors.Is(err, ErrRevocationStale) {
		t.Fatalf("stale high-risk must fail closed (ErrRevocationStale), got: %v", err)
	}
	if dec.Allowed {
		t.Error("decision.Allowed = true, want false for stale high-risk")
	}
	if ExitCode(err) != ExitRevocationStale {
		t.Errorf("exit code = %d, want %d", ExitCode(err), ExitRevocationStale)
	}
	if !dec.Stale || dec.Risk != RiskHigh || dec.FailPolicy != FailClosed {
		t.Errorf("audit record wrong: %+v", dec)
	}
}

func TestAC2_StaleLowRiskFollowsFailPolicy(t *testing.T) {
	issued := "2026-06-20T00:00:00Z"
	now := mustTime(t, "2026-06-22T00:00:00Z") // 48h old > 24h ceiling

	// Branch A: fail_policy=closed → low-risk is DENIED.
	closedP := freshPolicy(t, "24h", "closed", nil)
	decC, errC := EvaluateFreshness(7, issued, closedP, RiskLow, now)
	if !errors.Is(errC, ErrRevocationStale) {
		t.Fatalf("stale low-risk + closed must deny, got: %v", errC)
	}
	if decC.Allowed {
		t.Error("closed branch: Allowed=true, want false")
	}

	// Branch B: fail_policy=open → low-risk is ALLOWED (but audited).
	openP := freshPolicy(t, "24h", "open", nil)
	decO, errO := EvaluateFreshness(7, issued, openP, RiskLow, now)
	if errO != nil {
		t.Fatalf("stale low-risk + open must allow (no error), got: %v", errO)
	}
	if !decO.Allowed {
		t.Error("open branch: Allowed=false, want true")
	}
	if decO.Reason != "stale_low_risk_fail_open" || !decO.Stale {
		t.Errorf("open branch audit record wrong: %+v", decO)
	}
}

func TestFreshness_WithinCeilingAlwaysAllows(t *testing.T) {
	p := freshPolicy(t, "24h", "closed", nil)
	issued := "2026-06-22T00:00:00Z"
	now := mustTime(t, "2026-06-22T06:00:00Z") // 6h old < 24h
	for _, risk := range []ActionRisk{RiskHigh, RiskLow} {
		dec, err := EvaluateFreshness(9, issued, p, risk, now)
		if err != nil {
			t.Fatalf("fresh snapshot must allow risk=%s, got: %v", risk, err)
		}
		if !dec.Allowed || dec.Stale {
			t.Errorf("risk=%s: fresh record wrong: %+v", risk, dec)
		}
	}
}

func TestFreshness_NoCeilingNeverDenies(t *testing.T) {
	p := freshPolicy(t, "", "closed", nil) // no max_staleness
	issued := "2000-01-01T00:00:00Z"       // ancient
	now := mustTime(t, "2026-06-22T00:00:00Z")
	dec, err := EvaluateFreshness(1, issued, p, RiskHigh, now)
	if err != nil || !dec.Allowed {
		t.Fatalf("no ceiling must never deny even ancient+high-risk, got err=%v dec=%+v", err, dec)
	}
}

// Adversary: a list with no parseable issued_at must be treated as infinitely
// stale once a ceiling is set (it cannot dodge the contract by omitting time).
func TestFreshness_UnparseableIssuedAtIsStale(t *testing.T) {
	p := freshPolicy(t, "24h", "open", nil)
	now := mustTime(t, "2026-06-22T00:00:00Z")
	dec, err := EvaluateFreshness(3, "", p, RiskHigh, now)
	if !errors.Is(err, ErrRevocationStale) {
		t.Fatalf("missing issued_at + high-risk must fail closed, got: %v", err)
	}
	if !dec.Stale {
		t.Error("missing issued_at must be marked stale")
	}
}

// --- R3: action-risk classification (red-team: cannot downgrade high→low) ---

func TestClassifyActionRisk(t *testing.T) {
	cases := []struct {
		name  string
		se    []string
		destr bool
		extra []string
		want  ActionRisk
	}{
		{"read-only", []string{"fs:read", "git:read"}, false, nil, RiskLow},
		{"empty", nil, false, nil, RiskLow},
		{"llm-call low", []string{"llm:call", "secrets:read"}, false, nil, RiskLow},
		{"fs:write high", []string{"fs:write"}, false, nil, RiskHigh},
		{"fs:delete high", []string{"fs:delete"}, false, nil, RiskHigh},
		{"network:outbound high", []string{"network:outbound"}, false, nil, RiskHigh},
		{"subprocess high", []string{"subprocess"}, false, nil, RiskHigh},
		{"destructive flag high", []string{"fs:read"}, true, nil, RiskHigh},
		{"spend signal high", nil, false, []string{"spend"}, RiskHigh},
		{"prod signal high", []string{"fs:read"}, false, []string{"prod"}, RiskHigh},
		// Red-team: a write side-effect cannot be hidden by also listing reads.
		{"mixed read+write still high", []string{"fs:read", "git:read", "fs:write"}, false, nil, RiskHigh},
	}
	for _, c := range cases {
		if got := ClassifyActionRisk(c.se, c.destr, c.extra...); got != c.want {
			t.Errorf("%s: ClassifyActionRisk = %q, want %q", c.name, got, c.want)
		}
	}
}

// Clock-injection property: the SAME list is fresh at one `now` and stale at a
// later `now`. Proves staleness is measured against the injected clock, not the
// list's self-asserted freshness — an adversary replaying a stale list cannot
// present it as fresh.
func TestFreshness_ClockInjectionDrivesVerdict(t *testing.T) {
	p := freshPolicy(t, "1h", "closed", nil)
	issued := "2026-06-22T00:00:00Z"

	early := mustTime(t, "2026-06-22T00:30:00Z") // 30m — fresh
	if dec, err := EvaluateFreshness(1, issued, p, RiskHigh, early); err != nil || !dec.Allowed {
		t.Fatalf("at +30m must be fresh, got err=%v dec=%+v", err, dec)
	}
	late := mustTime(t, "2026-06-22T02:00:00Z") // 2h — stale
	if _, err := EvaluateFreshness(1, issued, p, RiskHigh, late); !errors.Is(err, ErrRevocationStale) {
		t.Fatalf("at +2h must be stale-denied, got: %v", err)
	}
}

func mustTime(t *testing.T, rfc string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, rfc)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}
