package statemachine

import (
	"testing"
	"time"
)

// A fixed injected clock; the state machine must never reach for time.Now().
var testNow = time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)

// enterprisePol is a representative enterprise profile with 24h ceilings.
func enterprisePol() OfflinePolicy {
	return OfflinePolicy{
		Enterprise:            true,
		MaxPolicyCacheAge:     24 * time.Hour,
		MaxRevocationCacheAge: 24 * time.Hour,
	}
}

// TestCompute_TableStates exercises the four states across the input matrix.
func TestCompute_TableStates(t *testing.T) {
	fresh := 1 * time.Hour
	stale := 48 * time.Hour

	cases := []struct {
		name string
		in   Inputs
		pol  OfflinePolicy
		want State
	}{
		{
			name: "reachable + fresh + basis → online",
			in:   Inputs{RegistryReachable: true, PolicyAge: fresh, RevocationAge: fresh, TrustAge: fresh, TrustBasisPresent: true, Now: testNow},
			pol:  enterprisePol(),
			want: StateOnline,
		},
		{
			name: "reachable but stale caches → still online (can refresh)",
			in:   Inputs{RegistryReachable: true, PolicyAge: stale, RevocationAge: stale, TrustAge: stale, TrustBasisPresent: true, Now: testNow},
			pol:  enterprisePol(),
			want: StateOnline,
		},
		{
			name: "disconnected + fresh → degraded",
			in:   Inputs{RegistryReachable: false, PolicyAge: fresh, RevocationAge: fresh, TrustAge: fresh, TrustBasisPresent: true, Now: testNow},
			pol:  enterprisePol(),
			want: StateDegraded,
		},
		{
			name: "disconnected + stale policy → offline",
			in:   Inputs{RegistryReachable: false, PolicyAge: stale, RevocationAge: fresh, TrustAge: fresh, TrustBasisPresent: true, Now: testNow},
			pol:  enterprisePol(),
			want: StateOffline,
		},
		{
			name: "disconnected + stale revocation → offline",
			in:   Inputs{RegistryReachable: false, PolicyAge: fresh, RevocationAge: stale, TrustAge: fresh, TrustBasisPresent: true, Now: testNow},
			pol:  enterprisePol(),
			want: StateOffline,
		},
		{
			name: "disconnected + stale trust → offline",
			in:   Inputs{RegistryReachable: false, PolicyAge: fresh, RevocationAge: fresh, TrustAge: stale, TrustBasisPresent: true, Now: testNow},
			pol:  enterprisePol(),
			want: StateOffline,
		},
		{
			name: "enterprise + no trust basis at all → locked",
			in:   Inputs{RegistryReachable: false, TrustBasisPresent: false, AnchorPresent: false, Now: testNow},
			pol:  enterprisePol(),
			want: StateLocked,
		},
		{
			name: "enterprise + no basis but reachable → still locked (no basis to verify)",
			in:   Inputs{RegistryReachable: true, TrustBasisPresent: false, AnchorPresent: false, Now: testNow},
			pol:  enterprisePol(),
			want: StateLocked,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Compute(c.in, c.pol); got != c.want {
				t.Fatalf("Compute = %s, want %s", got, c.want)
			}
		})
	}
}

// TestCompute_NeverBrick_SelfER1SidecarOnly is the load-bearing R-7.1/7.2 case:
// a self/ER1 host that has NO SPEC-0188 skill-trust-roots.yaml but DOES have a
// .m3c-provenance sidecar (folded into TrustBasisPresent) must compute
// online/degraded and NEVER locked — even under an enterprise profile.
func TestCompute_NeverBrick_SelfER1SidecarOnly(t *testing.T) {
	sidecarOnly := Inputs{
		RegistryReachable: false,
		PolicyAge:         1 * time.Hour,
		RevocationAge:     1 * time.Hour,
		TrustAge:          1 * time.Hour,
		TrustBasisPresent: true, // the .m3c-provenance sidecar is a trust basis
		AnchorPresent:     false,
		Now:               testNow,
	}

	// Even under an enterprise profile, sidecar-present ⇒ not locked.
	if got := Compute(sidecarOnly, enterprisePol()); got == StateLocked {
		t.Fatalf("sidecar-only host locked under enterprise profile — day-one brick trap (R-7.2)")
	}
	if got := Compute(sidecarOnly, enterprisePol()); got != StateDegraded {
		t.Fatalf("disconnected sidecar-only host = %s, want degraded", got)
	}

	// Reachable ⇒ online.
	reach := sidecarOnly
	reach.RegistryReachable = true
	if got := Compute(reach, enterprisePol()); got != StateOnline {
		t.Fatalf("reachable sidecar-only host = %s, want online", got)
	}
}

// TestCompute_NeverBrick_UnmanagedHostNeverLocks: a fresh / unmanaged /
// air-gapped machine WITHOUT an enterprise profile, and with NO trust basis at
// all, must NEVER enter locked (R-7.2: locked is enterprise opt-in only). The
// shipped unmanaged=allow default must not be flipped.
func TestCompute_NeverBrick_UnmanagedHostNeverLocks(t *testing.T) {
	airgapped := Inputs{
		RegistryReachable: false,
		TrustBasisPresent: false,
		AnchorPresent:     false,
		Now:               testNow,
	}
	// Zero-value policy = the shipped default (not enterprise, no ceilings).
	if got := Compute(airgapped, OfflinePolicy{}); got == StateLocked {
		t.Fatalf("unmanaged air-gapped host locked WITHOUT an enterprise profile — the shipped default must never lock (R-7.2)")
	}
	// With no ceilings, disconnected-with-no-basis is degraded (caches trivially
	// "fresh" because there is no ceiling), never locked.
	if got := Compute(airgapped, OfflinePolicy{}); got != StateDegraded {
		t.Fatalf("unmanaged disconnected host = %s, want degraded (no enterprise, no ceilings)", got)
	}
	// And DenyAllManaged must be false for whatever state it lands in.
	if DenyAllManaged(Compute(airgapped, OfflinePolicy{})) {
		t.Fatalf("unmanaged host must not deny all managed skills")
	}
}

// TestCompute_AnchorAloneIsTrustBasis: a translog anchor alone counts as a trust
// basis for the locked guard (even under enterprise), so an anchored host never
// locks.
func TestCompute_AnchorAloneIsTrustBasis(t *testing.T) {
	anchored := Inputs{
		RegistryReachable: false,
		PolicyAge:         1 * time.Hour,
		RevocationAge:     1 * time.Hour,
		TrustAge:          1 * time.Hour,
		TrustBasisPresent: false,
		AnchorPresent:     true,
		Now:               testNow,
	}
	if got := Compute(anchored, enterprisePol()); got == StateLocked {
		t.Fatalf("anchored host locked — a translog anchor is a trust basis (R-7.1)")
	}
}

// TestEmergencyActive_ExemptFromStateAndExpiry is the AC-7 emergency case: an
// old-but-valid emergency deny-list still denies in EVERY state, including
// locked and fully-expired offline. The emergency channel is exempt from cache
// expiry and from the state machine — EmergencyActive does not even accept the
// age/ceiling, and ignores the state.
func TestEmergencyActive_ExemptFromStateAndExpiry(t *testing.T) {
	for _, s := range []State{StateOnline, StateDegraded, StateOffline, StateLocked} {
		if !EmergencyActive(true, s) {
			t.Fatalf("emergency deny-list suppressed in state %s — the compromise channel must be exempt from every state (AC-7)", s)
		}
		if EmergencyActive(false, s) {
			t.Fatalf("EmergencyActive(false, %s) = true; must be a pure passthrough", s)
		}
	}

	// Concretely: a host whose caches are ALL expired (offline) still honours the
	// emergency list — expiry of the ordinary revocation cache does not expire the
	// emergency channel.
	expired := Inputs{RegistryReachable: false, PolicyAge: 999 * time.Hour, RevocationAge: 999 * time.Hour, TrustAge: 999 * time.Hour, TrustBasisPresent: true, Now: testNow}
	st := Compute(expired, enterprisePol())
	if st != StateOffline {
		t.Fatalf("all-expired disconnected host = %s, want offline", st)
	}
	if !EmergencyActive(true, st) {
		t.Fatalf("emergency list not active in fully-expired offline state (AC-7)")
	}
}

// TestPredicates pins the posture predicates that gate the R-1.4 fallback and
// name the fail-closed / deny-all postures.
func TestPredicates(t *testing.T) {
	// Online is the ONLY state that permits the online fallback.
	for _, s := range []State{StateOnline, StateDegraded, StateOffline, StateLocked} {
		want := s == StateOnline
		if got := AllowOnlineFallback(s); got != want {
			t.Errorf("AllowOnlineFallback(%s) = %v, want %v", s, got, want)
		}
	}
	// High-risk fails closed everywhere except online/degraded.
	if HighRiskFailsClosed(StateOnline) || HighRiskFailsClosed(StateDegraded) {
		t.Errorf("high-risk must not fail closed in online/degraded")
	}
	if !HighRiskFailsClosed(StateOffline) || !HighRiskFailsClosed(StateLocked) {
		t.Errorf("high-risk must fail closed in offline/locked")
	}
	// Deny-all is locked only.
	if DenyAllManaged(StateOnline) || DenyAllManaged(StateDegraded) || DenyAllManaged(StateOffline) {
		t.Errorf("only locked may deny all managed skills")
	}
	if !DenyAllManaged(StateLocked) {
		t.Errorf("locked must deny all managed skills")
	}
}

// TestAgeFresh_FutureDatedIsStale: a cache dated in the FUTURE beyond the skew
// tolerance is treated as STALE (fail-safe), so it cannot "look fresh forever"
// and dodge the offline demotion.
func TestAgeFresh_FutureDated(t *testing.T) {
	ceiling := 24 * time.Hour
	// Small future skew (2m) is tolerated → fresh.
	if !ageFresh(-2*time.Minute, ceiling) {
		t.Errorf("small future skew should be tolerated as fresh")
	}
	// Large future skew (1h) → stale.
	if ageFresh(-1*time.Hour, ceiling) {
		t.Errorf("large future-dated cache must be treated as stale (fail-safe)")
	}
	// No ceiling → always fresh regardless of age.
	if !ageFresh(999*time.Hour, 0) {
		t.Errorf("zero ceiling means no ceiling → always fresh")
	}

	// A disconnected host with a wildly future-dated policy cache under an
	// enterprise ceiling must be offline, not degraded.
	in := Inputs{RegistryReachable: false, PolicyAge: -10 * time.Hour, RevocationAge: time.Hour, TrustAge: time.Hour, TrustBasisPresent: true, Now: testNow}
	if got := Compute(in, enterprisePol()); got != StateOffline {
		t.Fatalf("future-dated policy cache = %s, want offline (fail-safe)", got)
	}
}

// TestDecide_AuditRecord: Decide.State must equal Compute, and the record must
// materialise the posture predicates + the injected clock.
func TestDecide_AuditRecord(t *testing.T) {
	in := Inputs{RegistryReachable: false, PolicyAge: 2 * time.Hour, RevocationAge: 90 * time.Minute, TrustAge: time.Hour, TrustBasisPresent: true, Now: testNow}
	pol := enterprisePol()

	dec := Decide(in, pol)
	if dec.State != Compute(in, pol) {
		t.Fatalf("Decide.State %s != Compute %s", dec.State, Compute(in, pol))
	}
	if dec.State != StateDegraded {
		t.Fatalf("Decide.State = %s, want degraded", dec.State)
	}
	if dec.AllowOnlineFallback {
		t.Errorf("degraded must not allow the online fallback")
	}
	if dec.PolicyAgeSeconds != int64((2 * time.Hour).Seconds()) {
		t.Errorf("PolicyAgeSeconds = %d, want %d", dec.PolicyAgeSeconds, int64((2 * time.Hour).Seconds()))
	}
	if dec.ComputedAt != testNow.Format(time.RFC3339) {
		t.Errorf("ComputedAt = %q, want %q", dec.ComputedAt, testNow.Format(time.RFC3339))
	}
	if dec.Enterprise != true {
		t.Errorf("Enterprise not echoed")
	}

	// Negative (future) age clamps to 0 in the record.
	in2 := in
	in2.PolicyAge = -time.Hour
	if got := Decide(in2, pol).PolicyAgeSeconds; got != 0 {
		t.Errorf("future PolicyAge should clamp to 0 in record, got %d", got)
	}
}

// TestState_String pins the stable labels.
func TestState_String(t *testing.T) {
	cases := map[State]string{
		StateOnline:   "online",
		StateDegraded: "degraded",
		StateOffline:  "offline",
		StateLocked:   "locked",
		State(99):     "unknown",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("State(%d).String() = %q, want %q", int(s), got, want)
		}
	}
}
