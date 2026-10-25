package mutationstate

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// MaxSessionSubjects includes the original subject. Additional subjects must
// belong to this session's pinned authority; cross-authority locking is separate.
const MaxSessionSubjects = 256

// Recheck authenticates retained evidence again under the still-held OS lock.
// It always includes Begin's original subject and action. The caller must first
// recheck runtime and installed content, then call this immediately before its
// first target mutation. It does not freeze the clock after returning.
//
// A validated monotonic clock observation is persisted even on a stale or revoked
// denial. Invalid evidence, a clock rollback or malformed inputs cannot advance
// the floor. Persistence uncertainty invalidates the session until Close.
func (s *Session) Recheck(ctx context.Context, digests ...string) (verify.MutationFreshnessDecision, error) {
	if s == nil {
		return verify.MutationFreshnessDecision{Reason: "session_unavailable"}, ErrInvalidState
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	deny := func(reason string, err error) (verify.MutationFreshnessDecision, error) {
		s.decision = verify.MutationFreshnessDecision{Action: s.action, SubjectDigest: s.digest, Reason: reason}
		return s.decision, err
	}
	if s.closed || s.file == nil || s.store == nil {
		return deny("session_unavailable", ErrInvalidState)
	}
	if s.poisoned {
		return deny("session_persistence_uncertain", ErrPersistence)
	}
	if err := ctx.Err(); err != nil {
		return deny("session_context_canceled", err)
	}
	// Check caps and canonical spellings before copying, decoding or allocating
	// the subject set. A caller cannot replace the original with this list.
	if len(digests) >= MaxSessionSubjects {
		return deny("session_subject_limit", ErrInvalidState)
	}
	for _, digest := range digests {
		if !sessionDigest(digest) {
			return deny("session_invalid_subject", ErrInvalidState)
		}
	}
	r, list, err := s.store.load()
	if err != nil {
		return deny("session_history_invalid", err)
	}
	// No cooperating writer may update this record while our lock is held.
	// Refuse unexpected replacement rather than silently adopting new history.
	if r.Epoch != s.history.Epoch || !r.IssuedAt.Equal(s.history.IssuedAt) ||
		r.EvidenceFingerprint != s.history.EvidenceFingerprint || !r.LastSeen.Equal(s.history.LastSeen) {
		return deny("session_history_changed", ErrInvalidState)
	}
	now := s.store.now().UTC()
	if now.IsZero() || now.Before(r.LastSeen) {
		return deny("clock_rollback", verify.ErrRevocationStale)
	}
	subjects := make([]string, 1, len(digests)+1)
	subjects[0] = s.digest
	subjects = append(subjects, digests...)
	var original, failure verify.MutationFreshnessDecision
	var evaluationErr error
	seen := make(map[string]bool, len(subjects))
	for _, digest := range subjects {
		if seen[digest] {
			continue
		}
		seen[digest] = true
		decision, err := verify.EvaluateMutationFreshness(verify.MutationFreshnessOpts{
			Action: s.action, ExpectedRegistry: s.store.registry, SubjectDigest: digest,
			Root: s.store.root, Revocations: list, MinimumEpoch: r.Epoch,
			Clock: verify.MutationClockState{Now: now, LastObservedAt: r.LastSeen},
		})
		if digest == s.digest {
			original = decision
		}
		if err != nil {
			failure = decision
			if decision.Reason == "subject_revoked" {
				err = fmt.Errorf("mutation subject is revoked: %w", verify.ErrIdentityRevoked)
			}
			evaluationErr = err
			break
		}
	}
	// The evaluator can reject a revoked subject before assigning EvaluatedAt.
	// Only our independently checked monotonic observation advances LastSeen.
	r.LastSeen = now
	if err := s.store.publish(ctx, r); err != nil {
		s.poisoned = true
		return deny("session_persistence_uncertain", errors.Join(evaluationErr, ErrPersistence, err))
	}
	s.history = r
	if evaluationErr != nil {
		failure.Allowed = false
		s.decision = failure
		return failure, evaluationErr
	}
	if err := ctx.Err(); err != nil {
		return deny("session_context_canceled", err)
	}
	s.decision = original
	return original, nil
}

func sessionDigest(digest string) bool {
	if len(digest) != 71 || !strings.HasPrefix(digest, "sha256:") || digest != strings.ToLower(digest) {
		return false
	}
	_, err := hex.DecodeString(digest[7:])
	return err == nil
}
