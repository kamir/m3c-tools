package verify

// SPEC-0279 R2 + R3 — the offline-revocation FRESHNESS contract.
//
// SPEC-0276 (R1, shipped) gave the signed RevocationList a monotonic `epoch`
// and the rollback floor. But a verifier that has not synced cannot see a
// revocation it never received: "signed revocation propagates" is only honest
// with a DEFINED freshness contract + a fail-policy. This file is that contract:
//
//   - FreshnessPolicy — the relying-party knobs (max_staleness / cache_ttl /
//     fail_policy / per-risk override), parsed from the trust-root (R2).
//   - ActionRisk      — the high-risk vs low-risk classification, derived from
//     the SPEC-0196 intent/datascope side-effect vocabulary (R3).
//   - EvaluateFreshness — the decision: given a snapshot's issued_at, `now`
//     (INJECTABLE — never time.Now() in the core), and the action's risk, decide
//     allow vs deny and PRODUCE AN AUDITABLE RECORD (R6).
//
// The load-bearing rule (SPEC-0279 R3 + Modes §4): past max_staleness, a
// HIGH-RISK action ALWAYS fails closed (deny) regardless of fail_policy; a
// LOW-RISK / read-only action follows fail_policy (closed default, open
// configurable). The clock is a parameter so an adversary cannot replay a stale
// list past max_staleness for a high-risk action — the verifier computes
// staleness against the caller's `now`, not the list's self-asserted freshness.

import (
	"fmt"
	"strings"
	"time"
)

// defaultCacheTTL is the shipped sweep cadence used when cache_ttl is unset.
const defaultCacheTTL = 12 * time.Hour

// maxFutureClockSkew is how far a snapshot's issued_at may sit in the FUTURE
// (relative to the verifier's clock) before it is treated as DISHONEST. A small
// skew (NTP jitter, sub-second rounding) is tolerated; anything beyond it is a
// forged/future-dated timestamp that would otherwise "look fresh forever" — so
// past this bound we treat the snapshot as INFINITELY STALE (fail-safe), exactly
// like a missing/unparseable issued_at (SPEC-0279 P4 review finding #4).
const maxFutureClockSkew = 5 * time.Minute

// FailPolicy is the disposition past max_staleness. Closed (deny) is the
// SPEC-0279 default; Open (allow, audited) is configurable for low-risk actions.
type FailPolicy string

const (
	// FailClosed denies the action when the snapshot is stale. The default.
	FailClosed FailPolicy = "closed"
	// FailOpen allows the action when the snapshot is stale — ONLY honored for a
	// low-risk action, and only ever with an audited record (never silent).
	FailOpen FailPolicy = "open"
)

// ActionRisk is the freshness-relevant risk class of the action being gated.
// HIGH-risk actions fail closed past max_staleness unconditionally (R3); LOW-risk
// actions follow fail_policy.
type ActionRisk string

const (
	// RiskHigh — a state-mutating / consequential action: fs:write, fs:delete,
	// git:write, network:outbound, subprocess, a destructive intent, a spend, or a
	// prod target. Classified via the SPEC-0196 side-effect vocabulary.
	RiskHigh ActionRisk = "high"
	// RiskLow — a read-only / low-consequence action: fs:read, git:read,
	// secrets:read, llm:call, or no declared side-effects. Follows fail_policy.
	RiskLow ActionRisk = "low"
)

// FreshnessPolicy is the resolved (parsed + defaulted) relying-party freshness
// policy for one trust root. Built by TrustRoot.Freshness(); never constructed
// by hand outside tests. All durations are real time.Duration here (the YAML
// strings are parsed once at Load).
type FreshnessPolicy struct {
	// MaxStaleness is the staleness ceiling. Zero means "no ceiling" — the
	// pre-SPEC-0279 behaviour (a synced snapshot is trusted at any age). When
	// non-zero, a snapshot older than this triggers the fail-policy.
	MaxStaleness time.Duration

	// CacheTTL is the local revocation-cache lifetime (default 12h).
	CacheTTL time.Duration

	// FailPolicy is the default disposition past MaxStaleness for actions with no
	// per-risk override. Defaults to FailClosed.
	FailPolicy FailPolicy

	// byRisk is the per-risk override map (already validated: high⇒closed only).
	byRisk map[ActionRisk]FailPolicy
}

// PolicyFor returns the effective fail-policy for a risk class: the per-risk
// override when present, else the default FailPolicy. A HIGH-risk action is
// floored to FailClosed regardless of any configuration — the R3 invariant lives
// HERE as well as in validation, so even a hand-constructed policy cannot make a
// high-risk action fail open.
func (p FreshnessPolicy) PolicyFor(risk ActionRisk) FailPolicy {
	if risk == RiskHigh {
		return FailClosed // R3: high-risk is ALWAYS fail-closed past max_staleness.
	}
	if p.byRisk != nil {
		if fp, ok := p.byRisk[risk]; ok {
			return fp
		}
	}
	if p.FailPolicy == "" {
		return FailClosed
	}
	return p.FailPolicy
}

// Freshness parses and validates this trust root's SPEC-0279 R2 freshness fields
// into a resolved FreshnessPolicy. Called by validate() (so a bad value is
// refused at Load) AND by the consumers (so they read the same resolved policy).
//
// Defaults: max_staleness empty → 0 (no ceiling); cache_ttl empty → 12h;
// fail_policy empty → closed. A negative duration, an unparseable duration, an
// unknown fail_policy, or a per-risk override that tries to make HIGH-risk fail
// OPEN is rejected.
func (t *TrustRoot) Freshness() (FreshnessPolicy, error) {
	if t == nil {
		return FreshnessPolicy{}, fmt.Errorf("freshness: nil trust root")
	}
	var p FreshnessPolicy

	maxStale, err := parseFreshnessDuration("max_staleness", t.MaxStaleness, 0)
	if err != nil {
		return FreshnessPolicy{}, err
	}
	p.MaxStaleness = maxStale

	cacheTTL, err := parseFreshnessDuration("cache_ttl", t.CacheTTL, defaultCacheTTL)
	if err != nil {
		return FreshnessPolicy{}, err
	}
	p.CacheTTL = cacheTTL

	fp, err := parseFailPolicy("fail_policy", t.FailPolicy, FailClosed)
	if err != nil {
		return FreshnessPolicy{}, err
	}
	p.FailPolicy = fp

	if len(t.FailPolicyByRisk) > 0 {
		p.byRisk = make(map[ActionRisk]FailPolicy, len(t.FailPolicyByRisk))
		for rawRisk, rawPol := range t.FailPolicyByRisk {
			risk := ActionRisk(strings.ToLower(strings.TrimSpace(rawRisk)))
			if risk != RiskHigh && risk != RiskLow {
				return FreshnessPolicy{}, fmt.Errorf("fail_policy_by_risk: key %q is not one of [high, low]", rawRisk)
			}
			pol, perr := parseFailPolicy("fail_policy_by_risk["+string(risk)+"]", rawPol, "")
			if perr != nil {
				return FreshnessPolicy{}, perr
			}
			// R3 floor: a HIGH-risk action may not be configured to fail OPEN.
			if risk == RiskHigh && pol == FailOpen {
				return FreshnessPolicy{}, fmt.Errorf("fail_policy_by_risk: high-risk actions cannot be configured fail_policy=open (SPEC-0279 R3 requires fail-closed for high-risk past max_staleness)")
			}
			p.byRisk[risk] = pol
		}
	}
	return p, nil
}

// parseFreshnessDuration parses a Go duration string, applying def when empty and
// rejecting a negative value. The label is used in the error so the operator can
// find the offending field.
func parseFreshnessDuration(label, raw string, def time.Duration) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s %q is not a valid duration (e.g. 24h): %w", label, raw, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("%s %q must not be negative", label, raw)
	}
	return d, nil
}

// parseFailPolicy parses a fail-policy token, applying def when empty. An empty
// def with an empty raw is an error (the caller wanted an explicit value).
func parseFailPolicy(label, raw string, def FailPolicy) (FailPolicy, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		if def == "" {
			return "", fmt.Errorf("%s is required (closed | open)", label)
		}
		return def, nil
	}
	switch FailPolicy(raw) {
	case FailClosed, FailOpen:
		return FailPolicy(raw), nil
	default:
		return "", fmt.Errorf("%s %q is not one of [closed, open]", label, raw)
	}
}

// The AUTHORITATIVE risk classifier is allowlist-known-low (knownLowRiskTokens):
// anything NOT PROVEN low is HIGH. The unambiguously-high SPEC-0196 §5 tokens
// (fs:write, fs:delete, git:write, network:outbound, subprocess) are simply NOT
// on the allowlist, so they classify HIGH by exclusion — there is no separate
// high-list to keep in sync (a denylist-known-high model was the review's
// finding #2 fail-safe gap).
//
// knownLowRiskTokens is the CLOSED ALLOWLIST of tokens that are PROVEN low-risk
// for freshness purposes — read-only / non-egress / non-mutating. The fail-safe
// inverts the old denylist-known-high model (SPEC-0279 P4 review finding #2):
// a token must be on THIS list to be treated as low. An unknown / mis-typed /
// future token, or the SPEC-0196 §7 "UNKNOWN" awareness sentinel, is therefore
// HIGH — so a red-team cannot DOWNGRADE a high-risk action to low simply by
// using a token the classifier does not recognise.
//
// It spans BOTH the SPEC-0196 §5 side-effect vocabulary (fs:read, git:read,
// network:inbound, secrets:read, llm:call) AND the read-style grant-intent forms
// the AgentID mandate uses (network:read, fs:read, git:read), so the one
// classifier is correct whether it is fed datascope side-effects or grant intents.
var knownLowRiskTokens = map[string]struct{}{
	// SPEC-0196 §5 side-effect reads (datascope surface).
	"fs:read":         {},
	"git:read":        {},
	"network:inbound": {},
	"secrets:read":    {},
	"llm:call":        {},
	// AgentID grant-intent read forms (mandate surface).
	"network:read": {},
}

// ClassifyActionRisk maps a set of declared side-effects + intent flags to a
// freshness ActionRisk. The classification is FAIL-SAFE toward HIGH via an
// ALLOWLIST-KNOWN-LOW rule (SPEC-0279 P4 review finding #2):
//
//   - an EMPTY surface (no side-effects, no extra signals, not destructive) is
//     HIGH — we cannot PROVE it read-only, so we must not assume it (matching
//     bundleActionRisk, whose empty-scopes case is already HIGH);
//
//   - a `destructive` flag, OR any extra "spend"/"prod"/write/egress signal, is
//     HIGH (the SPEC-0279 R3 spend/prod cases that are not side-effects);
//
//   - any side-effect / signal token NOT in knownLowRiskTokens is HIGH (an
//     unknown/mis-typed/future token cannot dodge fail-closed);
//
//   - only when EVERY supplied token is in the known-low allowlist (and nothing
//     is destructive) is the action LOW.
//
//   - sideEffects — the SPEC-0196 §5 side_effects tokens (fs:write, …).
//
//   - destructive — the intent.destructive flag.
//
//   - extraSignals — free-form action tags ("spend", "prod", "destructive",
//     grant-intent tokens, …) the caller wants to fold in.
//
// The function never DOWNGRADES: once any signal says high, the result is high.
func ClassifyActionRisk(sideEffects []string, destructive bool, extraSignals ...string) ActionRisk {
	if destructive {
		return RiskHigh
	}
	// Empty surface → cannot prove read-only → fail-safe HIGH (matches
	// bundleActionRisk's no-declared-scopes case).
	if len(sideEffects) == 0 && len(extraSignals) == 0 {
		return RiskHigh
	}
	// Every supplied token must be on the known-low allowlist; the first token NOT
	// on it (unknown/mis-typed/future/UNKNOWN-sentinel, or an explicit high token)
	// forces HIGH.
	for _, se := range sideEffects {
		if _, low := knownLowRiskTokens[strings.ToLower(strings.TrimSpace(se))]; !low {
			return RiskHigh
		}
	}
	for _, sig := range extraSignals {
		if _, low := knownLowRiskTokens[strings.ToLower(strings.TrimSpace(sig))]; !low {
			return RiskHigh
		}
	}
	return RiskLow
}

// FreshnessDecision is the auditable record of one freshness evaluation
// (SPEC-0279 R6). Every field the operator needs to reconstruct the verdict is
// here: the epoch seen, the measured staleness, the action's risk, the
// fail-policy applied, and the open/closed outcome. The consumers emit this to
// the audit trail; never fail open without producing one.
type FreshnessDecision struct {
	// Epoch is the snapshot's signed epoch (rollback floor already enforced).
	Epoch int `json:"epoch"`
	// IssuedAt is the snapshot's issued_at (RFC3339), echoed for the record.
	IssuedAt string `json:"issued_at,omitempty"`
	// StalenessSeconds is now - issued_at, in seconds (negative clamped to 0).
	StalenessSeconds int64 `json:"staleness_seconds"`
	// MaxStalenessSeconds is the configured ceiling in seconds (0 = no ceiling).
	MaxStalenessSeconds int64 `json:"max_staleness_seconds"`
	// Stale is true when StalenessSeconds > MaxStalenessSeconds (ceiling set).
	Stale bool `json:"stale"`
	// Risk is the action's freshness risk class ("high" | "low").
	Risk ActionRisk `json:"risk"`
	// FailPolicy is the disposition applied for this risk ("closed" | "open").
	FailPolicy FailPolicy `json:"fail_policy"`
	// Allowed is the outcome: true = the freshness check did NOT deny.
	Allowed bool `json:"allowed"`
	// Reason is a short human/stable token for the verdict.
	Reason string `json:"reason"`
	// CheckpointReset, when true, records that a valid signed freshness
	// checkpoint (R4) reset the staleness clock for this decision.
	CheckpointReset bool `json:"checkpoint_reset,omitempty"`
}

// EvaluateFreshness is the SPEC-0279 R3 decision core. Given a snapshot's epoch +
// issued_at, the resolved policy, the action risk, and an INJECTABLE `now`, it
// computes staleness and decides allow vs deny, returning a fully-populated
// auditable FreshnessDecision and (when denied) ErrRevocationStale.
//
// Algorithm:
//  1. staleness = now - issued_at (clamped ≥ 0; an unparseable/empty issued_at
//     with a ceiling set is treated as INFINITELY stale → the ceiling fires,
//     fail-safe — a list with no honest timestamp cannot dodge the contract).
//  2. if no ceiling (MaxStaleness == 0) OR staleness ≤ ceiling → allowed (fresh).
//  3. stale + HIGH-risk → DENY (fail-closed), ErrRevocationStale, always.
//  4. stale + LOW-risk  → follow PolicyFor(low): closed → DENY; open → ALLOW
//     (audited, never silent).
//
// The clock is a parameter, NOT time.Now(): the caller injects it so a replayed
// stale list cannot present itself as fresh — staleness is measured against the
// verifier's clock, and a high-risk action past the ceiling is denied no matter
// what the list claims.
func EvaluateFreshness(epoch int, issuedAt string, policy FreshnessPolicy, risk ActionRisk, now time.Time) (FreshnessDecision, error) {
	dec := FreshnessDecision{
		Epoch:               epoch,
		IssuedAt:            strings.TrimSpace(issuedAt),
		Risk:                risk,
		MaxStalenessSeconds: int64(policy.MaxStaleness / time.Second),
	}

	staleness, parsedOK := snapshotStaleness(issuedAt, now)
	// A FUTURE issued_at (negative staleness) more than maxFutureClockSkew ahead of
	// the verifier's clock is a dishonest/forged timestamp — it would otherwise
	// clamp to staleness 0 and "look fresh forever". Treat it as unparseable →
	// infinitely stale (fail-safe), so the ceiling fires (SPEC-0279 P4 finding #4).
	if parsedOK && staleness < -maxFutureClockSkew {
		parsedOK = false
	}
	if staleness < 0 {
		staleness = 0
	}
	dec.StalenessSeconds = int64(staleness / time.Second)

	// No ceiling configured → freshness is not enforced (pre-SPEC-0279 default).
	if policy.MaxStaleness == 0 {
		dec.FailPolicy = policy.PolicyFor(risk)
		dec.Allowed = true
		dec.Reason = "no_staleness_ceiling"
		return dec, nil
	}

	// A list whose issued_at is missing/unparseable is treated as infinitely
	// stale once a ceiling is set — it cannot prove freshness, so it must not
	// dodge the contract (fail-safe).
	if !parsedOK {
		dec.Stale = true
		dec.StalenessSeconds = -1 // sentinel: "unknown/unparseable age"
	} else {
		dec.Stale = staleness > policy.MaxStaleness
	}

	if !dec.Stale {
		dec.FailPolicy = policy.PolicyFor(risk)
		dec.Allowed = true
		dec.Reason = "within_max_staleness"
		return dec, nil
	}

	// Stale. Resolve the fail-policy for this risk (high is floored to closed).
	fp := policy.PolicyFor(risk)
	dec.FailPolicy = fp

	if risk == RiskHigh || fp == FailClosed {
		dec.Allowed = false
		if risk == RiskHigh {
			dec.Reason = "stale_high_risk_fail_closed"
		} else {
			dec.Reason = "stale_low_risk_fail_closed"
		}
		return dec, fmt.Errorf("revocation snapshot is stale (epoch %d, %s old > max_staleness; risk=%s policy=%s): %w",
			epoch, humanizeStaleness(dec.StalenessSeconds), risk, fp, ErrRevocationStale)
	}

	// Stale + low-risk + fail-open → allow, but AUDIT (the caller emits dec).
	dec.Allowed = true
	dec.Reason = "stale_low_risk_fail_open"
	return dec, nil
}

// snapshotStaleness computes now - issued_at. The second return reports whether
// issued_at parsed as RFC3339 — an empty/garbage timestamp returns (0, false) so
// the caller can apply the fail-safe "treat as stale" rule.
func snapshotStaleness(issuedAt string, now time.Time) (time.Duration, bool) {
	issuedAt = strings.TrimSpace(issuedAt)
	if issuedAt == "" {
		return 0, false
	}
	t, err := time.Parse(time.RFC3339, issuedAt)
	if err != nil {
		return 0, false
	}
	return now.UTC().Sub(t.UTC()), true
}

// humanizeStaleness renders a staleness-in-seconds for an error message. The -1
// sentinel (unknown age) is rendered explicitly.
func humanizeStaleness(secs int64) string {
	if secs < 0 {
		return "unknown-age (no parseable issued_at)"
	}
	return (time.Duration(secs) * time.Second).String()
}
