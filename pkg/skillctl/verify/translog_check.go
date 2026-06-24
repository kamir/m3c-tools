package verify

// SPEC-0278 L1 transparency-log integration for the verifier.
//
// This composes the translog primitives into the §7 verifier surface:
// after the signature/governance chain passes, the verifier can ALSO
// confirm that the event (identified by its digest) is INCLUDED under a
// Signed Tree Head the machine trusts — entirely offline, against the STH
// pinned in ~/.claude/skill-trust-roots.yaml. No network call to any single
// company's server is made; that is the Round-A offline property preserved
// across the cross-org boundary.
//
// Honesty: a passing inclusion check proves the event is COMMITTED to a log
// whose head you trust. It makes a log that later tries to withhold or
// equivocate about this event DETECTABLE (the head you pinned, plus a
// cross-witnessed head, would diverge). It does NOT prove the log operator
// is honest in general — only L2 (the deferred BFT consortium ledger) could
// prevent a single operator from equivocating.

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/kamir/m3c-tools/pkg/skillctl/translog"
)

// ErrLogInclusionMissing and ExitLogInclusionMissing (23) are the canonical
// SPEC-0278 L1 sentinel/exit-code pair; they are declared in errors.go
// alongside the rest of the §7 verifier exit codes (20=ExitSelfAttested,
// 21=agentid-expired, 22=ExitRevocationStale are taken — log inclusion is 23)
// and wired into ExitCode(). This file consumes them.

// LogInclusionInput is the material a caller hands the inclusion check: the
// event's leaf (its LogEntry), the index it claims in the log, and the
// inclusion proof. These come from the local log (translog.Log.ProveInclusion)
// or are shipped alongside the bundle as a "log receipt."
type LogInclusionInput struct {
	// Entry is the logged event (its canonical leaf is recomputed here —
	// we never trust a caller-supplied leaf hash).
	Entry translog.LogEntry

	// Index is the leaf position the proof claims.
	Index int

	// TreeSize is the tree size the proof was produced against. Must match
	// (or be covered by) a pinned STH's tree_size.
	TreeSize int

	// Proof is the RFC-6962 inclusion (audit) path.
	Proof [][translog.HashSize]byte

	// LogID names which pinned log this receipt belongs to.
	LogID string
}

// LogInclusionResult reports the outcome of the offline inclusion check.
type LogInclusionResult struct {
	// Included is true iff the event's leaf verified under a pinned,
	// signature-valid STH.
	Included bool

	// STHTreeSize / STHRoot identify the pinned head the proof verified
	// against (forensic breadcrumb).
	STHTreeSize int
	STHRoot     string

	// Advisory carries a human-readable note when the check did not pass
	// but the policy is advisory (so the caller can warn, not block).
	Advisory string
}

// CheckLogInclusion verifies, OFFLINE, that the event in `in` is included
// under a pinned STH for its log. It:
//
//  1. resolves the pinned LogTrust for in.LogID (must exist);
//  2. recomputes the event's leaf hash from its canonical bytes (never
//     trusting a supplied hash);
//  3. finds a pinned STH whose tree_size == in.TreeSize and whose signature
//     verifies under the pinned log key;
//  4. verifies the inclusion proof against that STH's root.
//
// The boolean policy `requireInclusion` decides the FAILURE behaviour:
//   - requireInclusion == true  → any failure returns a wrapped
//     ErrLogInclusionMissing (fail-closed; the CLI maps this to exit 23).
//   - requireInclusion == false → a failure returns (result, nil) with
//     result.Included=false and an Advisory message (warn, don't block).
//
// A SUCCESSFUL check always returns (result{Included:true}, nil) regardless
// of policy.
func CheckLogInclusion(tr *TrustRoots, in LogInclusionInput, requireInclusion bool) (*LogInclusionResult, error) {
	fail := func(reason string) (*LogInclusionResult, error) {
		if requireInclusion {
			return nil, fmt.Errorf("%w: %s", ErrLogInclusionMissing, reason)
		}
		return &LogInclusionResult{Included: false, Advisory: reason}, nil
	}

	if tr == nil {
		return fail("no trust-roots loaded")
	}
	lt := tr.FindLog(in.LogID)
	if lt == nil {
		return fail(fmt.Sprintf("no pinned log %q in trust-roots", in.LogID))
	}
	if len(lt.PinnedSTHs) == 0 {
		return fail(fmt.Sprintf("log %q has no pinned STH", in.LogID))
	}

	// (2) Recompute the leaf hash from the event itself. A caller cannot
	// substitute a leaf hash for an event that was never logged.
	leaf, err := in.Entry.LeafHash()
	if err != nil {
		return fail(fmt.Sprintf("event leaf is invalid: %v", err))
	}

	// (3) Find a pinned STH at exactly in.TreeSize whose signature verifies.
	logPub := ed25519.PublicKey(lt.LogKey)
	for _, ps := range lt.PinnedSTHs {
		if ps.TreeSize != in.TreeSize {
			continue
		}
		sth := translog.STH{
			TreeSize:  ps.TreeSize,
			RootHash:  ps.RootHash,
			Timestamp: ps.Timestamp,
			LogID:     ps.LogID,
			Signature: ps.Signature,
		}
		if err := translog.VerifySTH(logPub, sth); err != nil {
			// A pinned STH that doesn't verify under the pinned key is
			// itself a red flag, but we keep scanning in case another
			// pinned head at the same size is valid.
			continue
		}
		root, err := sth.RootBytes()
		if err != nil {
			continue
		}
		// (4) Offline inclusion verification against the trusted root.
		if err := translog.VerifyInclusion(leaf, in.Index, in.TreeSize, in.Proof, root); err != nil {
			return fail(fmt.Sprintf("inclusion proof did not verify under pinned STH (size %d): %v", ps.TreeSize, err))
		}
		return &LogInclusionResult{
			Included:    true,
			STHTreeSize: ps.TreeSize,
			STHRoot:     hex.EncodeToString(root[:]),
		}, nil
	}

	return fail(fmt.Sprintf("no signature-valid pinned STH at tree_size %d for log %q", in.TreeSize, in.LogID))
}

// PinnedLogKeyResolver adapts the trust-roots `logs` block to the
// translog.PinnedLogKey interface so split-view detection
// (translog.DetectSplitView) can verify each witnessed STH against the
// correct pinned key.
type PinnedLogKeyResolver struct {
	tr *TrustRoots
}

// LogKeys returns a resolver over the trust-roots' pinned logs.
func (t *TrustRoots) LogKeys() PinnedLogKeyResolver {
	return PinnedLogKeyResolver{tr: t}
}

// PublicKeyFor implements translog.PinnedLogKey. Returns the pinned raw
// ed25519 public key for logID, or an error if the log is not pinned.
func (r PinnedLogKeyResolver) PublicKeyFor(logID string) ([]byte, error) {
	lt := r.tr.FindLog(logID)
	if lt == nil {
		return nil, fmt.Errorf("no pinned key for log %q", logID)
	}
	return lt.LogKey, nil
}

// ExitCodeForLog maps a transparency-log error to its process exit code,
// layered on top of the §7 ExitCode. Returns 0 for nil, 23 for a missing/
// invalid inclusion proof under require_log_inclusion, and falls through to
// ExitCode for everything else. (ExitCode itself now also maps
// ErrLogInclusionMissing → 23, so this layering is belt-and-braces.)
func ExitCodeForLog(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, ErrLogInclusionMissing) {
		return ExitLogInclusionMissing
	}
	return ExitCode(err)
}
