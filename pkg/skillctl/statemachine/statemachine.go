// Package statemachine implements SPEC-0317 R-7: the named offline state
// machine that makes skillctl's fail-open/fail-closed posture EXPLICIT.
//
// It is a pure, stdlib-only leaf: Compute maps
//
//	(connectivity × cache ages × anchor presence × trust-basis presence)
//
// to one of four named states — online / degraded / offline / locked — via an
// INJECTABLE clock. It holds NO state, touches NO filesystem, and reaches NO
// network; the caller gathers the Inputs (cache issued-at → ages against the
// injected clock, reachability probe, trust-basis file sweep) and this package
// decides.
//
// What this package IS (R-7.4): the state machine introduces NO second decision
// ladder. It only supplies the `online` flag that gates the R-1.3 online
// fallback (AllowOnlineFallback) plus two advisory predicates
// (HighRiskFailsClosed, DenyAllManaged) that MIRROR — never replace — the
// authoritative freshness.go R3 floor and the SPEC-0247 unmanaged=allow default.
// The precedence remains the one R-1.3 ladder: emergency deny-list > allowlist >
// revoked/revocation staleness > verdict cache > unmanaged policy > state
// default.
//
// Three load-bearing invariants (the day-one brick traps this file must NOT
// fall into):
//
//   - NEVER-BRICK (R-7.1/7.2): a healthy self/ER1 sidecar-only host with fresh
//     caches computes online (or degraded when disconnected), NEVER locked.
//     `trust basis present` INCLUDES the SPEC-0225 self/ER1 roots and the
//     `.m3c-provenance` sidecar — not only the SPEC-0188 skill-trust-roots.yaml
//     (legitimately absent on self hosts). The caller folds all of those into
//     Inputs.TrustBasisPresent.
//
//   - LOCKED IS OPT-IN (R-7.2, AC-7): `locked = deny all managed skills` is
//     enterprise policy ONLY. A fresh / unmanaged / air-gapped machine WITHOUT
//     an enterprise profile (OfflinePolicy.Enterprise == false) NEVER enters
//     locked — the shipped unmanaged=allow default is untouched.
//
//   - EMERGENCY IS EXEMPT (R-7.3, AC-7): the emergency deny-list is exempt from
//     cache expiry and from the state machine. EmergencyActive is a pure
//     passthrough that deliberately does NOT take the state as an input, so no
//     state (not even locked/offline with everything expired) can suppress the
//     compromise channel.
package statemachine

import (
	"encoding/json"
	"time"
)

// State is the named offline posture (SPEC-0317 R-7.1). Compute is TOTAL: it
// always returns exactly one of these four, so the zero value is never produced
// by omission. The ordering is a severity ladder (online → locked) but carries
// no arithmetic meaning; branch on the named constants, never on the int.
type State int

const (
	// StateOnline — the registry is reachable, so the online verify fallback is
	// available. The fully healthy posture. This is the ONLY state in which the
	// R-1.4 online fallback may run.
	StateOnline State = iota

	// StateDegraded — the registry is unreachable BUT the policy / trust /
	// revocation caches are all fresh within the configured max_*_age ceilings.
	// The hot path is strictly local; local decisions are trustworthy because
	// the caches are current.
	StateDegraded

	// StateOffline — caches are present but AGING past their ceilings. The hot
	// path is strictly local and high-risk actions fail closed per SPEC-0279
	// (enforced by freshness.go — this state only NAMES the posture).
	StateOffline

	// StateLocked — there is NO trust basis at all AND an enterprise profile has
	// opted in. Deny all managed skills (exit 28 `offline_locked`). NEVER reached
	// without OfflinePolicy.Enterprise, so it can never brick a self / unmanaged /
	// air-gapped host (R-7.2).
	StateLocked
)

// MarshalJSON emits the human label ("online", …) rather than the int, so a
// StateDecision and any downstream console read a stable token (mirrors
// pin.Level.MarshalJSON).
func (s State) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// String returns the stable lower-case label used in `session-baseline` output,
// audit records, and any downstream console. Keep these tokens stable — they are
// an additive contract.
func (s State) String() string {
	switch s {
	case StateOnline:
		return "online"
	case StateDegraded:
		return "degraded"
	case StateOffline:
		return "offline"
	case StateLocked:
		return "locked"
	default:
		return "unknown"
	}
}

// OfflinePolicy is the RESOLVED (parsed + defaulted) offline policy that gates
// the state machine. It is the stdlib-only counterpart of the YAML
// `offline_policy` block on verify.TrustRoot (R-7.3); verify parses its
// duration strings once at Load and hands this over. Constructed by
// verify.TrustRoot.ResolvedOfflinePolicy(); never assembled by hand outside
// tests.
//
// The zero value is the SHIPPED DEFAULT: not enterprise, no cache ceilings
// (0 == "no ceiling" → caches never expire the posture), unmanaged=allow. A host
// with no offline_policy block therefore computes online/degraded and NEVER
// locked — exactly the day-one plugin-compat behaviour.
type OfflinePolicy struct {
	// AllowCachedTrustedSkills allows a cached, trust-verified skill to run while
	// disconnected (degraded/offline). Advisory to the decision ladder; the state
	// machine does not itself gate on it.
	AllowCachedTrustedSkills bool

	// DenyUnknownSkills denies a skill with no cached trust basis while
	// disconnected. It flips the unmanaged=allow default for UNKNOWN skills only;
	// it does NOT by itself produce the `locked` state (that needs Enterprise +
	// no-trust-basis). Advisory to the decision ladder.
	DenyUnknownSkills bool

	// MaxPolicyCacheAge bounds the policy cache AND the trust cache freshness.
	// Zero == no ceiling (never stale). A snapshot older than this pushes the
	// disconnected posture from degraded to offline.
	MaxPolicyCacheAge time.Duration

	// MaxRevocationCacheAge bounds the revocation cache freshness. Zero == no
	// ceiling. NOTE: this bounds the ORDINARY revocation cache only — the
	// emergency deny-list is EXEMPT (see EmergencyActive).
	MaxRevocationCacheAge time.Duration

	// RequireLocalAudit is the SPEC-0317 R-8 inversion of the SPEC-0255
	// decision-invariance contract. It is ENTERPRISE-ONLY (verify.Load rejects it
	// without Enterprise) and is consumed by the enforce path, not by Compute.
	// Carried here so the resolved policy is one surface.
	RequireLocalAudit bool

	// Enterprise gates the two consequential knobs: it is the opt-in that enables
	// the `locked` state and permits RequireLocalAudit. Without it the host can
	// NEVER lock — the never-brick guard lives HERE and in Compute.
	Enterprise bool
}

// Inputs is the pure snapshot Compute maps to a State. The caller gathers it
// against a single INJECTED clock (Now): the cache *Age fields are that clock
// minus each cache's issued_at, and Now is retained so Decide can stamp an
// auditable record with the exact clock the posture was computed at (SPEC-0279
// R6 "every state decision is audited").
type Inputs struct {
	// RegistryReachable is the result of the caller's reachability probe. It is
	// THE discriminator between online and the disconnected ladder: reachable →
	// online (the fallback is available); unreachable → degraded/offline/locked.
	RegistryReachable bool

	// PolicyAge is now - policy_cache.issued_at. Negative (future-dated) values
	// are treated fail-safe as stale (see ageFresh).
	PolicyAge time.Duration

	// RevocationAge is now - revocation_cache.issued_at (ordinary list; the
	// emergency channel is exempt).
	RevocationAge time.Duration

	// TrustAge is now - trust_cache.issued_at. Bounded by MaxPolicyCacheAge.
	TrustAge time.Duration

	// AnchorPresent reports whether a translog anchor (STH) is present. It counts
	// toward "some trust basis exists" for the locked guard, but note (per the
	// SPEC threat model) a purely-local anchor is only tamper-EVIDENT once
	// witnessed off-box; it is not itself a freshness signal here.
	AnchorPresent bool

	// TrustBasisPresent is the folded-in "is ANY trust basis present" flag. The
	// caller sets it true if ANY of: SPEC-0188 skill-trust-roots.yaml, the
	// SPEC-0225 self/ER1 trust-roots, OR a .m3c-provenance sidecar is present.
	// This breadth is what stops a self/ER1 sidecar-only host from bricking.
	TrustBasisPresent bool

	// Now is the injected clock at which the snapshot was taken. Used for the
	// audit record (Decide); the age comparisons use the *Age fields, which the
	// caller derived from this same clock.
	Now time.Time
}

// Compute is the pure state function (SPEC-0317 R-7.1). It is TOTAL and has no
// side effects.
//
// Precedence (this is a VIEW of the R-1.3 ladder's state-default rung, not a new
// ladder — R-7.4):
//
//  1. locked  — ENTERPRISE opt-in AND no trust basis at all. Checked first
//     because "no policy basis" is the most severe posture. The Enterprise gate
//     is the never-brick guard: a non-enterprise host can never reach this rung.
//  2. online  — the registry is reachable, so the online fallback is available.
//     Reachability is the discriminator; a reachable host can always refresh, so
//     it is online regardless of current cache age.
//  3. degraded — disconnected but every cache is fresh within its ceiling.
//  4. offline — disconnected and at least one cache is aging past its ceiling
//     (high-risk fails closed per SPEC-0279, enforced downstream).
func Compute(in Inputs, pol OfflinePolicy) State {
	// (1) locked — enterprise opt-in ONLY, and only with NO trust basis at all.
	// `trust basis present` is broad (SPEC-0188 roots OR self/ER1 roots OR the
	// .m3c-provenance sidecar OR a translog anchor), folded by the caller into
	// TrustBasisPresent / AnchorPresent. A self / unmanaged / air-gapped host —
	// or ANY non-enterprise host — therefore never locks.
	if pol.Enterprise && !hasTrustBasis(in) {
		return StateLocked
	}

	// (2) online — the registry is reachable: the R-1.4 online fallback is
	// available. A reachable host can always re-sync, so cache age does not
	// demote it below online.
	if in.RegistryReachable {
		return StateOnline
	}

	// (3) degraded — disconnected but caches fresh within the configured ceilings.
	if cachesFresh(in, pol) {
		return StateDegraded
	}

	// (4) offline — disconnected and caches aging past a ceiling.
	return StateOffline
}

// hasTrustBasis reports whether ANY trust basis is present. Deliberately broad
// (R-7.1): a translog anchor OR any of the folded-in root/sidecar sources counts.
func hasTrustBasis(in Inputs) bool {
	return in.TrustBasisPresent || in.AnchorPresent
}

// cachesFresh reports whether the policy, trust, and (ordinary) revocation
// caches are all within their configured ceilings. A zero ceiling means "no
// ceiling" → that cache never counts as stale. The trust cache is bounded by the
// policy ceiling (R-7.3 documents only max_policy_cache_age / max_revocation_
// cache_age; trust roots ride the policy ceiling).
func cachesFresh(in Inputs, pol OfflinePolicy) bool {
	if !ageFresh(in.PolicyAge, pol.MaxPolicyCacheAge) {
		return false
	}
	if !ageFresh(in.TrustAge, pol.MaxPolicyCacheAge) {
		return false
	}
	if !ageFresh(in.RevocationAge, pol.MaxRevocationCacheAge) {
		return false
	}
	return true
}

// maxFutureSkew is how far a cache's issued_at may sit in the FUTURE relative to
// the injected clock (a negative age) before it is treated as dishonest. A small
// skew (NTP jitter, sub-second rounding) is tolerated; beyond it the cache is
// treated as stale (fail-safe), mirroring freshness.go's maxFutureClockSkew — a
// future-dated cache must not "look fresh forever".
const maxFutureSkew = 5 * time.Minute

// ageFresh reports whether an age is within a ceiling. Zero (or negative)
// ceiling means "no ceiling" → always fresh. A future-dated cache (age below
// -maxFutureSkew) is treated as STALE (fail-safe toward the more restrictive
// offline posture), never as freshest-possible.
func ageFresh(age, ceiling time.Duration) bool {
	if ceiling <= 0 {
		return true // no ceiling configured
	}
	if age < -maxFutureSkew {
		return false // dishonest future-dated cache → treat as stale
	}
	if age < 0 {
		age = 0 // tolerate small clock skew
	}
	return age <= ceiling
}

// AllowOnlineFallback reports whether the R-1.3 online fallback may run in the
// given state (SPEC-0317 R-1.4 P2, opt-in). ONLY `online` permits it; in
// degraded / offline / locked the hot path is strictly local. This is the single
// flag the state machine feeds the ladder — it does NOT reorder the ladder.
func AllowOnlineFallback(s State) bool { return s == StateOnline }

// DenyAllManaged reports whether the state denies ALL managed skills. ONLY
// `locked` does (enterprise opt-in, exit 28 `offline_locked`). It NEVER affects
// unmanaged skills — the shipped unmanaged=allow default is untouched (R-7.2).
// Because Compute only returns locked under Enterprise, this can never brick a
// non-enterprise host.
func DenyAllManaged(s State) bool { return s == StateLocked }

// HighRiskFailsClosed reports whether high-risk actions fail closed in the given
// state. True for offline and locked; false for online and degraded (degraded
// caches are fresh, so cached trust decisions stand). This MIRRORS the
// authoritative SPEC-0279 freshness.go R3 floor for display/gating; it is NOT the
// enforcer — freshness.go remains the one place high-risk fail-closed is applied
// (R-7.4). A defensive default: any unrecognised (never-produced) state also
// fails closed.
func HighRiskFailsClosed(s State) bool {
	return s != StateOnline && s != StateDegraded
}

// EmergencyActive reports whether the emergency deny-list is in force. It is a
// PURE PASSTHROUGH of emergencyPresent — the state is intentionally the blank
// parameter so this signature documents, at the type level, that NO state may
// suppress the compromise channel (R-7.3, AC-7). The emergency deny-list is
// EXEMPT from cache expiry: an old-but-valid emergency list still denies in
// EVERY state, including locked and fully-expired offline. The decision ladder
// evaluates emergency FIRST (R-7.4), before this package's state is even
// consulted.
func EmergencyActive(emergencyPresent bool, _ State) bool { return emergencyPresent }

// StateDecision is the auditable record of one Compute evaluation (SPEC-0279 R6
// pattern: every state decision is audited). The session-baseline verb and the
// gate emit it; it is a projection, never a trust input.
type StateDecision struct {
	// State is the computed posture.
	State State `json:"state"`
	// RegistryReachable echoes the connectivity input.
	RegistryReachable bool `json:"registry_reachable"`
	// TrustBasisPresent echoes the folded trust-basis input.
	TrustBasisPresent bool `json:"trust_basis_present"`
	// AnchorPresent echoes the translog-anchor input.
	AnchorPresent bool `json:"anchor_present"`
	// Enterprise echoes whether the enterprise profile is engaged.
	Enterprise bool `json:"enterprise"`
	// PolicyAgeSeconds / RevocationAgeSeconds / TrustAgeSeconds are the measured
	// cache ages (seconds; negative clamped to 0) at the injected clock.
	PolicyAgeSeconds     int64 `json:"policy_age_seconds"`
	RevocationAgeSeconds int64 `json:"revocation_age_seconds"`
	TrustAgeSeconds      int64 `json:"trust_age_seconds"`
	// AllowOnlineFallback / HighRiskFailsClosed / DenyAllManaged are the resolved
	// posture predicates, materialised so a console need not re-derive them.
	AllowOnlineFallback bool `json:"allow_online_fallback"`
	HighRiskFailsClosed bool `json:"high_risk_fails_closed"`
	DenyAllManaged      bool `json:"deny_all_managed"`
	// ComputedAt is the injected clock (RFC3339 UTC) the posture was computed at.
	ComputedAt string `json:"computed_at"`
}

// Decide computes the State and returns it alongside a fully-populated auditable
// StateDecision. It is the same pure function as Compute (Decide.State ==
// Compute(in, pol)); the record is a convenience for the audited callers.
func Decide(in Inputs, pol OfflinePolicy) StateDecision {
	s := Compute(in, pol)
	computedAt := ""
	if !in.Now.IsZero() {
		computedAt = in.Now.UTC().Format(time.RFC3339)
	}
	return StateDecision{
		State:                s,
		RegistryReachable:    in.RegistryReachable,
		TrustBasisPresent:    in.TrustBasisPresent,
		AnchorPresent:        in.AnchorPresent,
		Enterprise:           pol.Enterprise,
		PolicyAgeSeconds:     clampSeconds(in.PolicyAge),
		RevocationAgeSeconds: clampSeconds(in.RevocationAge),
		TrustAgeSeconds:      clampSeconds(in.TrustAge),
		AllowOnlineFallback:  AllowOnlineFallback(s),
		HighRiskFailsClosed:  HighRiskFailsClosed(s),
		DenyAllManaged:       DenyAllManaged(s),
		ComputedAt:           computedAt,
	}
}

// clampSeconds renders a duration as whole seconds, clamping a negative
// (future-dated) age to 0 for the record.
func clampSeconds(d time.Duration) int64 {
	if d < 0 {
		return 0
	}
	return int64(d / time.Second)
}
