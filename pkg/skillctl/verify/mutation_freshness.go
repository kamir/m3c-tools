package verify

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// MutationAction identifies a new installation or approval. It does not classify
// execution of an already installed skill.
type MutationAction string

const (
	MutationInstall MutationAction = "install"
	MutationAdmit   MutationAction = "admit"
	MutationAttest  MutationAction = "attest"
)

// MutationClockState supplies the caller's current clock and reliably loaded
// previous observation. Neither value is authenticated or persisted by this API.
// Missing history is denied; enrollment/bootstrap is a separate responsibility.
type MutationClockState struct {
	Now            time.Time
	LastObservedAt time.Time
}

// MutationFreshnessOpts supplies a caller-selected trusted pinned root, clock
// state and previously adopted epoch floor. Their provenance is the caller's
// responsibility. The evaluator authenticates only Revocations against Root's
// active keys. It performs no fetching, enrollment, state writes or installation.
type MutationFreshnessOpts struct {
	Action           MutationAction
	ExpectedRegistry string
	SubjectDigest    string
	Root             *TrustRoot
	Revocations      *RevocationList
	MinimumEpoch     int
	Clock            MutationClockState
}

// MutationFreshnessDecision reports freshness and non-revocation for one subject
// at EvaluatedAt, not permission to complete an installation or approval. Age is
// meaningful only when AgeKnown is true. EvidenceSource is populated only after
// registry binding and signature verification, including on subsequent denials.
// Callers must durably preserve their clock/epoch floors and recheck before a
// mutation; this pure evaluator cannot prove persistence or prevent state replay.
type MutationFreshnessDecision struct {
	Allowed        bool
	Action         MutationAction
	Registry       string
	SubjectDigest  string
	EvidenceSource string
	Epoch          int
	IssuedAt       time.Time
	EvaluatedAt    time.Time
	MaxAge         time.Duration
	Age            time.Duration
	AgeKnown       bool
	Reason         string
}

// EvaluateMutationFreshness authenticates a complete revocation list, binds its
// registry and subject, and enforces a maximum age of 24h (or a shorter root
// policy). Checkpoints, execution risk and fail-open profiles cannot relax this
// check. A future issuance, clock rollback or absent history denies the action.
// Existing EvaluateFreshness execution semantics are unchanged. No production
// caller is enrolled or wired by adding this standalone API.
func EvaluateMutationFreshness(opts MutationFreshnessOpts) (MutationFreshnessDecision, error) {
	dec := MutationFreshnessDecision{Action: opts.Action, MaxAge: 24 * time.Hour}
	deny := func(reason string, cause error) (MutationFreshnessDecision, error) {
		dec.Reason = reason
		return dec, fmt.Errorf("mutation freshness: %s: %w", reason, cause)
	}
	switch opts.Action {
	case MutationInstall, MutationAdmit, MutationAttest:
	default:
		return deny("invalid_action", errors.New("unsupported mutation action"))
	}
	digest := strings.ToLower(strings.TrimSpace(opts.SubjectDigest))
	if _, err := decodeShaHexDigest(digest); err != nil {
		return deny("invalid_subject_digest", errors.New("invalid subject digest"))
	}
	if opts.Root == nil || opts.Revocations == nil {
		return deny("missing_authority", ErrRegistryNotTrusted)
	}
	registry := strings.TrimRight(strings.TrimSpace(opts.ExpectedRegistry), "/")
	if registry == "" || registry != strings.TrimRight(strings.TrimSpace(opts.Root.RegistryURL), "/") ||
		registry != strings.TrimRight(strings.TrimSpace(opts.Revocations.RegistryURL), "/") {
		return deny("registry_mismatch", ErrRegistryNotTrusted)
	}
	if opts.MinimumEpoch < 0 || opts.Root.MinRevocationEpoch < 0 || opts.Revocations.Epoch <= 0 {
		return deny("invalid_or_unversioned_epoch", ErrRegistryNotTrusted)
	}
	floor := max(opts.MinimumEpoch, opts.Root.MinRevocationEpoch)
	set, err := VerifyRevocationList(opts.Revocations, opts.Root, floor)
	if err != nil {
		// The underlying verifier can include untrusted fields in its diagnostic.
		// Keep the public cause classification without reflecting those fields.
		return deny("untrusted_revocation_list", ErrRegistryNotTrusted)
	}
	dec.Registry = registry
	dec.SubjectDigest = digest
	dec.EvidenceSource = "signed_revocation_list"
	dec.Epoch = opts.Revocations.Epoch
	if _, revoked := set[digest]; revoked {
		return deny("subject_revoked", ErrBlobMissing)
	}
	policy, err := opts.Root.Freshness()
	if err != nil {
		return deny("invalid_root_freshness_policy", ErrRevocationStale)
	}
	if policy.MaxStaleness > 0 && policy.MaxStaleness < dec.MaxAge {
		dec.MaxAge = policy.MaxStaleness
	}
	if opts.Clock.Now.IsZero() || opts.Clock.LastObservedAt.IsZero() {
		return deny("missing_clock_history", ErrRevocationStale)
	}
	dec.EvaluatedAt = opts.Clock.Now.UTC()
	if dec.EvaluatedAt.Before(opts.Clock.LastObservedAt.UTC()) {
		return deny("clock_rollback", ErrRevocationStale)
	}
	issued, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(opts.Revocations.IssuedAt))
	if err != nil || issued.IsZero() {
		return deny("invalid_issued_at", ErrRevocationStale)
	}
	dec.IssuedAt = issued.UTC()
	dec.Age = dec.EvaluatedAt.Sub(dec.IssuedAt)
	dec.AgeKnown = true
	if dec.IssuedAt.After(dec.EvaluatedAt) {
		return deny("future_issued_at", ErrRevocationStale)
	}
	if dec.Age > dec.MaxAge {
		return deny("revocation_list_stale", ErrRevocationStale)
	}
	dec.Allowed = true
	dec.Reason = "fresh_subject_not_revoked"
	return dec, nil
}
