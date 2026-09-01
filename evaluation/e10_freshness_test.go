package evaluation

// E10 — Revocation FRESHNESS correctness (SPEC-0280 §2; SPEC-0279 + SPEC-0278).
//
// This is a CORRECTNESS matrix, not a latency curve: for each adversarial case
// the harness drives the SHIPPED logic and asserts it produces the SAFE verdict.
// We report a pass/fail per case (and an aggregate pass-rate). The cases:
//
//   rollback      — an attacker substitutes an OLDER signed revocation list (lower
//                   epoch) to drop a revocation. Driven through the real
//                   verify.VerifyRevocationList with a pinned epoch floor; the
//                   stale-epoch list MUST be refused (ErrRegistryNotTrusted).
//   stale-high    — a synced snapshot is older than max_staleness and the action
//                   is HIGH-risk. EvaluateFreshness MUST deny (fail-closed) with
//                   ErrRevocationStale, regardless of fail_policy.
//   stale-low-open- a stale snapshot + LOW-risk action + fail_policy=open MUST be
//                   ALLOWED but produce an auditable record (never silent).
//   fresh         — a within-ceiling snapshot MUST be allowed.
//   future-dated  — a forged future issued_at MUST be treated as infinitely stale
//                   (fail-safe), so a high-risk action is denied.
//   split-view    — the log shows two STHs at the same tree_size with different
//                   roots. DetectSplitView MUST flag it (ErrSplitView).
//   consistency   — a genuine append between two sizes MUST verify
//                   (VerifyConsistency ok); a rewritten history MUST fail.
//
// Each case is also a standalone Test* so `go test ./evaluation/` (no RUN_EVAL)
// exercises the correctness logic and fails CI if a safety property regresses.

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/evaluation/internal/synth"
	"github.com/kamir/m3c-tools/pkg/skillctl/translog"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

const e10Seed = 0x52790279

var e10Now = time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)

// e10Root returns a trust root whose registry key signs revocation lists, so
// VerifyRevocationList accepts a list signed with synth.RegistryPriv(e10Seed).
func e10Root() *verify.TrustRoot {
	regPriv := synth.RegistryPriv(e10Seed)
	regPub := regPriv.Public().(ed25519.PublicKey)
	return &verify.TrustRoot{
		RegistryURL: synth.RegistryURL,
		RegistryKeys: []verify.RegistryKey{{
			ID:        "eval-registry-2026",
			Pubkey:    []byte(regPub),
			PubkeyB64: "", // not needed; Pubkey is hydrated
			Issued:    "2026-06-22",
		}},
		IdentityKeysAuthorized: "pinned",
		GovernanceMinimum:      "green",
	}
}

// caseRollback: an older-epoch signed list must be refused against a pinned floor.
func caseRollback(t *testing.T) bool {
	t.Helper()
	root := e10Root()
	regPriv := synth.RegistryPriv(e10Seed)
	digests := synth.SyntheticDigests(3, e10Seed)

	// The verifier has already seen epoch 5 (pinned floor). An attacker presents
	// a genuinely-signed but OLDER epoch-2 list that omits a revocation.
	old, err := verify.NewSignedRevocationList(synth.RegistryURL, "2026-06-01T00:00:00Z", 2, digests, regPriv)
	if err != nil {
		t.Fatalf("sign old list: %v", err)
	}
	_, vErr := verify.VerifyRevocationList(old, root, 5) // minEpoch=5
	// Safe verdict: refused (rollback caught).
	if vErr == nil {
		t.Logf("E10 rollback: FAIL — stale-epoch list was accepted")
		return false
	}
	if !errors.Is(vErr, verify.ErrRegistryNotTrusted) {
		t.Logf("E10 rollback: FAIL — wrong error: %v", vErr)
		return false
	}
	// And the SAME list at/above the floor must be accepted (no false positive).
	current, err := verify.NewSignedRevocationList(synth.RegistryURL, "2026-06-24T00:00:00Z", 5, digests, regPriv)
	if err != nil {
		t.Fatalf("sign current list: %v", err)
	}
	if _, err := verify.VerifyRevocationList(current, root, 5); err != nil {
		t.Logf("E10 rollback: FAIL — at-floor list wrongly refused: %v", err)
		return false
	}
	return true
}

// caseStaleHighRisk: a stale snapshot + high-risk action must be denied.
func caseStaleHighRisk(t *testing.T) bool {
	t.Helper()
	policy := verify.FreshnessPolicy{MaxStaleness: 24 * time.Hour, FailPolicy: verify.FailOpen}
	// 100h old, HIGH-risk: fail-closed regardless of FailOpen.
	issued := e10Now.Add(-100 * time.Hour).Format(time.RFC3339)
	dec, err := verify.EvaluateFreshness(5, issued, policy, verify.RiskHigh, e10Now)
	if err == nil || dec.Allowed {
		t.Logf("E10 stale-high: FAIL — stale high-risk action was allowed (dec=%+v err=%v)", dec, err)
		return false
	}
	if !errors.Is(err, verify.ErrRevocationStale) {
		t.Logf("E10 stale-high: FAIL — wrong error: %v", err)
		return false
	}
	return true
}

// caseStaleLowOpen: stale + low-risk + fail-open must allow WITH an audit record.
func caseStaleLowOpen(t *testing.T) bool {
	t.Helper()
	policy := verify.FreshnessPolicy{MaxStaleness: 24 * time.Hour, FailPolicy: verify.FailOpen}
	issued := e10Now.Add(-100 * time.Hour).Format(time.RFC3339)
	risk := verify.ClassifyActionRisk([]string{"fs:read"}, false) // proven low
	if risk != verify.RiskLow {
		t.Logf("E10 stale-low-open: FAIL — fs:read should classify low, got %s", risk)
		return false
	}
	dec, err := verify.EvaluateFreshness(5, issued, policy, risk, e10Now)
	if err != nil || !dec.Allowed {
		t.Logf("E10 stale-low-open: FAIL — stale low-risk fail-open was denied (dec=%+v err=%v)", dec, err)
		return false
	}
	if !dec.Stale || dec.Reason != "stale_low_risk_fail_open" {
		t.Logf("E10 stale-low-open: FAIL — missing audit record (dec=%+v)", dec)
		return false
	}
	return true
}

// caseFresh: a within-ceiling snapshot must be allowed.
func caseFresh(t *testing.T) bool {
	t.Helper()
	policy := verify.FreshnessPolicy{MaxStaleness: 24 * time.Hour, FailPolicy: verify.FailClosed}
	issued := e10Now.Add(-1 * time.Hour).Format(time.RFC3339)
	dec, err := verify.EvaluateFreshness(5, issued, policy, verify.RiskHigh, e10Now)
	if err != nil || !dec.Allowed || dec.Stale {
		t.Logf("E10 fresh: FAIL — fresh snapshot wrongly denied (dec=%+v err=%v)", dec, err)
		return false
	}
	return true
}

// caseFutureDated: a forged future issued_at must be treated as infinitely stale.
func caseFutureDated(t *testing.T) bool {
	t.Helper()
	policy := verify.FreshnessPolicy{MaxStaleness: 24 * time.Hour, FailPolicy: verify.FailClosed}
	// 1000h in the FUTURE — would "look fresh forever" if not fail-safed.
	issued := e10Now.Add(1000 * time.Hour).Format(time.RFC3339)
	dec, err := verify.EvaluateFreshness(5, issued, policy, verify.RiskHigh, e10Now)
	if err == nil || dec.Allowed || !dec.Stale {
		t.Logf("E10 future-dated: FAIL — future-dated snapshot looked fresh (dec=%+v err=%v)", dec, err)
		return false
	}
	return true
}

// caseSplitView: two STHs at the same size with different roots must be flagged.
func caseSplitView(t *testing.T) bool {
	t.Helper()
	logPub, logPriv := synth.LogKeypair(e10Seed)

	// History A and a FORKED history B of the same size → same tree_size,
	// different root. Build each via a real log so the STH/root is genuine.
	dirA := t.TempDir()
	lA := buildLog(t, dirA, 8)
	sthA, err := lA.SignHead(logPriv, e10Now)
	if err != nil {
		t.Fatalf("sign A: %v", err)
	}

	dirB := t.TempDir()
	lB, err := translog.OpenLog(dirB+"/b.jsonl", "eval-log")
	if err != nil {
		t.Fatalf("open B: %v", err)
	}
	for i := 0; i < 8; i++ {
		// Fork the middle entry so B's root differs at the same size.
		seed := e7Seed + i
		if i == 4 {
			seed = 999999
		}
		e := translog.LogEntry{
			Type:      translog.EventAdmit,
			Digest:    synth.SyntheticDigests(1, uint64(seed))[0],
			Timestamp: "2026-06-24T12:00:00Z",
			Subject:   "eval-subject",
		}
		if _, err := lB.Append(e); err != nil {
			t.Fatalf("append B[%d]: %v", i, err)
		}
	}
	sthB, err := lB.SignHead(logPriv, e10Now.Add(time.Minute))
	if err != nil {
		t.Fatalf("sign B: %v", err)
	}

	pins := e10PinnedLog{id: "eval-log", pub: logPub}
	conflict, err := translog.DetectSplitView(pins, []translog.STH{sthA, sthB})
	if err == nil || conflict == nil {
		t.Logf("E10 split-view: FAIL — equivocation not detected (conflict=%v err=%v)", conflict, err)
		return false
	}
	if !errors.Is(err, translog.ErrSplitView) {
		t.Logf("E10 split-view: FAIL — wrong error: %v", err)
		return false
	}
	return true
}

// caseConsistency: a genuine append must verify; a rewrite must fail.
func caseConsistency(t *testing.T) bool {
	t.Helper()
	dir := t.TempDir()
	l := buildLog(t, dir, 8)
	firstRoot, err := func() ([translog.HashSize]byte, error) {
		// Root at size 5 via a fresh log replaying the first 5 entries.
		d2 := t.TempDir()
		l2 := buildLog(t, d2, 5)
		return l2.Root()
	}()
	if err != nil {
		t.Fatalf("first root: %v", err)
	}
	secondRoot, err := l.Root()
	if err != nil {
		t.Fatalf("second root: %v", err)
	}
	proof, second, err := l.ProveConsistency(5)
	if err != nil {
		t.Fatalf("prove consistency: %v", err)
	}
	if err := translog.VerifyConsistency(5, second, firstRoot, secondRoot, proof); err != nil {
		t.Logf("E10 consistency: FAIL — genuine append wrongly rejected: %v", err)
		return false
	}
	// A rewritten history: corrupt the firstRoot so the proof can't reconstruct it.
	bad := firstRoot
	bad[0] ^= 0xFF
	if err := translog.VerifyConsistency(5, second, bad, secondRoot, proof); err == nil {
		t.Logf("E10 consistency: FAIL — rewritten history wrongly accepted")
		return false
	}
	return true
}

// e10PinnedLog implements translog.PinnedLogKey for split-view detection.
type e10PinnedLog struct {
	id  string
	pub ed25519.PublicKey
}

func (p e10PinnedLog) PublicKeyFor(logID string) ([]byte, error) {
	if logID != p.id {
		return nil, errors.New("no pinned key for log " + logID)
	}
	return p.pub, nil
}

// TestE10FreshnessMatrix drives every adversarial case and records the pass/fail
// matrix + aggregate pass-rate. The individual cases are also asserted (a FAIL
// here is a real safety regression, so the test fails CI even without RUN_EVAL).
func TestE10FreshnessMatrix(t *testing.T) {
	cases := []struct {
		name string
		fn   func(*testing.T) bool
	}{
		{"rollback", caseRollback},
		{"stale-high-risk", caseStaleHighRisk},
		{"stale-low-fail-open", caseStaleLowOpen},
		{"fresh", caseFresh},
		{"future-dated", caseFutureDated},
		{"split-view", caseSplitView},
		{"consistency", caseConsistency},
	}

	passed := 0
	for _, c := range cases {
		ok := c.fn(t)
		if ok {
			passed++
		} else {
			t.Errorf("E10 case %q did not produce the safe verdict", c.name)
		}
		verdict := "PASS"
		if !ok {
			verdict = "FAIL"
		}
		// Record per-case only in a measured run to avoid polluting the sink in CI.
		if eval() {
			recordPop(t, "E10", "freshness-"+c.name, "verdict", verdict, "synthetic",
				"SPEC-0279/0278 adversarial case driven through the shipped logic")
		}
	}

	t.Logf("E10 freshness matrix: %d/%d cases passed the safe-verdict check", passed, len(cases))
	if eval() {
		recordPop(t, "E10", "freshness-matrix", "pass_rate", round0(100*float64(passed)/float64(len(cases))),
			"synthetic", "%d/%d adversarial cases produced the safe verdict (rollback/stale/split-view/consistency)", passed, len(cases))
	}
}

// eval reports whether the measured harness is active (RUN_EVAL set).
func eval() bool { return testingRunEval }
