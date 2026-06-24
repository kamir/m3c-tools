package evaluation

// E5 — Agent-grant AUTHORIZATION overhead (SPEC-0280 §2; SPEC-0247 + SPEC-0277).
//
// Method: measure the added cost of the per-invocation authorization gate vs a
// no-gate baseline. The gate has two shipped parts:
//
//  1. agentid.Verify(mandate) — the full OFFLINE cryptographic verification of
//     the agent's signed mandate against PINNED keys (owner signature, validity
//     window, revocation set). A relying party that re-verifies the mandate each
//     invocation pays this.
//  2. Grant.AuthorizeSkill(skill, intents) — the per-call membership predicate
//     (skill in grant AND every required intent in grant). A relying party that
//     caches the verified mandate pays ONLY this per invocation.
//
// We report BOTH so the paper can state the honest figure for either deployment:
//   - "full gate" = Verify + AuthorizeSkill (re-verify every call),
//   - "cached gate" = AuthorizeSkill only (mandate verified once, then cached).
//
// Baseline = an empty invocation stub (the work the gate is added ON TOP of),
// measured the same way so the DELTA is the gate's added ms/invocation.

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/evaluation/internal/synth"
	"github.com/kamir/m3c-tools/pkg/skillctl/agentid"
)

const e5Seed = 0x52470277

// e5Pins is a minimal PinnedKeys backed by a single owner key.
type e5Pins struct {
	ownerID  string
	ownerPub ed25519.PublicKey
}

func (p e5Pins) FindOwner(id string) *agentid.PinnedKey {
	if agentid.NormalizeID(id) == agentid.NormalizeID(p.ownerID) {
		return &agentid.PinnedKey{ID: p.ownerID, Pubkey: p.ownerPub}
	}
	return nil
}
func (p e5Pins) FindApprover(string) *agentid.PinnedKey { return nil }

// e5Mandate builds a signed, pinned, valid AgentID granting one skill + intent,
// plus the matching pins. Deterministic from e5Seed.
func e5Mandate(t testing.TB) (*agentid.AgentID, agentid.VerifyOpts, string, []string) {
	t.Helper()
	ownerPub, ownerPriv := synth.LogKeypair(e5Seed) // any deterministic keypair
	ownerID := "id:owner@eval"
	p := agentid.Payload{
		ID:          "agent:eval-0001",
		Owner:       ownerID,
		DisplayName: "EvalAgent",
		CreatedAt:   "2026-06-01T00:00:00Z",
		NotAfter:    "2027-06-01T00:00:00Z",
		TrustRoot:   synth.RegistryURL,
		Grant: agentid.Grant{
			Skills:  []string{"eval-skill@>=1.0.0", "fetch-contract"},
			Intents: []string{"network:read", "fs:read"},
		},
	}
	sig, err := agentid.Sign(p, agentid.RoleOwner, ownerID, ownerPriv)
	if err != nil {
		t.Fatalf("sign mandate: %v", err)
	}
	a := &agentid.AgentID{Payload: p, Signatures: []agentid.Signature{sig}}
	opts := agentid.VerifyOpts{
		Pins: e5Pins{ownerID: ownerID, ownerPub: ownerPub},
		Now:  time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC),
	}
	// Sanity: it must verify and authorize before we benchmark it.
	res, err := agentid.Verify(a, opts)
	if err != nil {
		t.Fatalf("mandate must verify: %v", err)
	}
	if _, ok := res.Grant.AuthorizeSkill("eval-skill", []string{"network:read"}); !ok {
		t.Fatalf("mandate must authorize the eval skill")
	}
	return a, opts, "eval-skill", []string{"network:read"}
}

// baselineInvocation is the no-gate stub: the minimal work an invocation does
// without the authorization gate. Kept non-trivial-but-tiny so the subtraction
// is the gate cost, not measurement noise. Marked go:noinline so the compiler
// can't fold it away under the benchmark loop.
//
//go:noinline
func baselineInvocation(skill string) int { return len(skill) }

// BenchmarkE5BaselineInvocation measures the no-gate baseline.
func BenchmarkE5BaselineInvocation(b *testing.B) {
	sink := 0
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sink += baselineInvocation("eval-skill")
	}
	_ = sink
}

// BenchmarkE5AuthorizeOnly measures the cached-mandate gate: AuthorizeSkill only.
func BenchmarkE5AuthorizeOnly(b *testing.B) {
	a, _, skill, intents := e5Mandate(b)
	g := a.Payload.Grant
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := g.AuthorizeSkill(skill, intents); !ok {
			b.Fatal("authorize should pass")
		}
	}
}

// BenchmarkE5FullGate measures the full per-invocation gate: Verify + Authorize.
func BenchmarkE5FullGate(b *testing.B) {
	a, opts, skill, intents := e5Mandate(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := agentid.Verify(a, opts)
		if err != nil {
			b.Fatalf("verify: %v", err)
		}
		if _, ok := res.Grant.AuthorizeSkill(skill, intents); !ok {
			b.Fatal("authorize should pass")
		}
	}
}

// TestE5AuthzOverhead measures baseline / authorize-only / full-gate wall-clock
// per invocation and records the ADDED ms/invocation for both gate forms.
func TestE5AuthzOverhead(t *testing.T) {
	requireEval(t)
	a, opts, skill, intents := e5Mandate(t)
	g := a.Payload.Grant

	const iters = 200000

	base := timeLoop(iters, func() { _ = baselineInvocation(skill) })
	authz := timeLoop(iters, func() {
		if _, ok := g.AuthorizeSkill(skill, intents); !ok {
			t.Fatal("authorize should pass")
		}
	})
	full := timeLoop(iters, func() {
		res, err := agentid.Verify(a, opts)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if _, ok := res.Grant.AuthorizeSkill(skill, intents); !ok {
			t.Fatal("authorize should pass")
		}
	})

	baseMs := perOpMs(base, iters)
	authzMs := perOpMs(authz, iters)
	fullMs := perOpMs(full, iters)

	addedAuthz := authzMs - baseMs
	addedFull := fullMs - baseMs
	if addedAuthz < 0 {
		addedAuthz = 0
	}

	t.Logf("E5 baseline=%.6fms authorize-only=%.6fms full-gate=%.6fms", baseMs, authzMs, fullMs)
	record(t, "E5", "authorize-only", "added_ms_per_invocation", round6(addedAuthz),
		"cached-mandate gate (Grant.AuthorizeSkill), %d iters, delta over no-gate baseline", iters)
	record(t, "E5", "full-gate", "added_ms_per_invocation", round6(addedFull),
		"re-verify-each-call gate (agentid.Verify + AuthorizeSkill), %d iters, delta over no-gate baseline", iters)
}

// timeLoop runs fn iters times and returns the total wall-clock.
func timeLoop(iters int, fn func()) time.Duration {
	start := time.Now()
	for i := 0; i < iters; i++ {
		fn()
	}
	return time.Since(start)
}

func perOpMs(total time.Duration, iters int) float64 {
	return float64(total.Nanoseconds()) / float64(iters) / 1e6
}
