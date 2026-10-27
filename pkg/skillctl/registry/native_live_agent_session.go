package registry

import (
	"context"
	"errors"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

// NativeLiveAgentSession retains one untrusted carrier snapshot and the held
// native journal until checked Close. Plan authenticates the same bytes through
// the existing native preparation and consent pipeline.
type NativeLiveAgentSession struct {
	session   *NativeInstallSession
	candidate *NativeLiveAgentCandidate
	prepared  *preparedAgent
	workBytes int64
}

// NewNativeLiveAgentSession checks existing history and holds its lease before
// the source can read the selected external credential or make a request.
func NewNativeLiveAgentSession(ctx context.Context, journal *NativeJournal, source *NativeLiveAgentSource, digest string) (*NativeLiveAgentSession, error) {
	if source == nil {
		return nil, nativeSessionDiagnostic(ErrNativeEvidenceInvalid)
	}
	session, err := journal.BeginOfflineInstall(ctx, digest)
	if err != nil {
		return nil, err
	}
	candidate, err := source.Fetch(ctx, session)
	if err != nil {
		return nil, errors.Join(err, session.Close())
	}
	session.mu.Lock()
	live, err := retainNativeAgentCandidateLocked(session, candidate, source.bindingID())
	session.mu.Unlock()
	if err != nil {
		return nil, errors.Join(nativeSessionDiagnostic(err), session.Close())
	}
	return live, nil
}

// retainNativeAgentCandidateLocked freezes untrusted source bytes. The caller
// holds session.mu and supplies the binding of the actual acquired snapshot.
func retainNativeAgentCandidateLocked(session *NativeInstallSession, candidate *NativeLiveAgentCandidate, binding string) (*NativeLiveAgentSession, error) {
	if candidate == nil || candidate.Bundle == nil || len(candidate.Archive) == 0 || len(candidate.Archive) > 16<<20 || candidate.Bundle.StagedSkbPath != "" || candidate.Bundle.ProvenancePath != "" || !nativeSHA(binding) {
		return nil, ErrNativeEvidenceInvalid
	}
	work := candidate.workBytes
	if !nativeLiveReserve(&work, int64(len(candidate.Archive))+4*maxAgentContext+(128<<10)) {
		return nil, ErrNativeEvidenceInvalid
	}
	bundle, _, err := session.snapshotInput([]*StagedBundle{candidate.Bundle})
	if err != nil {
		return nil, err
	}
	candidate = &NativeLiveAgentCandidate{Archive: append([]byte(nil), candidate.Archive...), Bundle: bundle}
	session.liveSourceBinding = binding
	live := &NativeLiveAgentSession{session: session, candidate: candidate, workBytes: work}
	session.liveWork = &live.workBytes
	return live, nil
}

// Plan returns copied display rows and one session-local single-use token.
func (s *NativeLiveAgentSession) Plan(ctx context.Context) (plan *NativeInstallPlan, resultErr error) {
	if s == nil || s.session == nil {
		return nil, nativeSessionDiagnostic(ErrNativeSessionUnavailable)
	}
	inner := s.session
	inner.mu.Lock()
	defer inner.mu.Unlock()
	inner.plan = nil
	defer func() {
		resultErr = nativeSessionDiagnostic(resultErr)
		if resultErr != nil {
			plan = nil
		}
	}()
	if err := inner.usable(ctx); err != nil {
		return nil, err
	}
	if s.candidate == nil || s.candidate.Bundle == nil {
		return nil, ErrNativeEvidenceInvalid
	}
	// Replanning reuses the retained prepared archive. Source work and each
	// repeated context/hash phase remain charged without refunds.
	reserve := int64(8*maxAgentContext + (128 << 10))
	if s.prepared == nil {
		reserve += int64(4*len(s.candidate.Archive)) + skillbundle.DefaultMaxExtractedBytes + nativeLiveInflatedReservation() + int64(skillbundle.DefaultMaxExtractedFiles)*(2*4096+256)
	}
	if !nativeLiveReserve(&s.workBytes, reserve) {
		inner.terminal = true
		return nil, ErrNativeEvidenceInvalid
	}
	input, inputHash, err := inner.snapshotInput([]*StagedBundle{s.candidate.Bundle})
	if err != nil {
		return nil, err
	}
	if err = inner.lease.recheck(ctx, inner.rootDigest); err != nil {
		inner.poisoned = true
		return nil, err
	}
	if len(s.candidate.Archive) == 0 || len(s.candidate.Archive) > 16<<20 {
		return nil, ErrNativeEvidenceInvalid
	}
	if s.prepared == nil {
		s.prepared, err = prepareNativeAgentEvidence(input, s.candidate.Archive, inner.installOpts(ctx))
		if err != nil {
			inner.terminal = true
			return nil, err
		}
	}
	return inner.planPreparedLocked(ctx, input, inputHash, s.prepared)
}

// Confirm consumes exactly the retained plan; it does not reopen a staged path
// or fetch a newer unreviewed carrier snapshot.
func (s *NativeLiveAgentSession) Confirm(ctx context.Context, token string) ([]*InstallResult, error) {
	if s == nil || s.session == nil || s.candidate == nil {
		return nil, nativeSessionDiagnostic(ErrNativeSessionUnavailable)
	}
	inner := s.session
	inner.mu.Lock()
	if err := inner.usable(ctx); err != nil {
		inner.mu.Unlock()
		return nil, nativeSessionDiagnostic(err)
	}
	bodyBytes := 0
	if s.prepared != nil {
		bodyBytes = len(s.prepared.body)
	}
	if !nativeLiveReserve(&s.workBytes, int64(16*maxAgentContext+32*len(s.candidate.Archive)+2*bodyBytes)) {
		inner.terminal = true
		inner.plan = nil
		inner.mu.Unlock()
		return nil, nativeSessionDiagnostic(ErrNativeEvidenceInvalid)
	}
	inner.mu.Unlock()
	return inner.ConfirmInstall(ctx, []*StagedBundle{s.candidate.Bundle}, token)
}

// Close releases the native journal and preserves possible-publication errors.
func (s *NativeLiveAgentSession) Close() error {
	if s == nil || s.session == nil {
		return nil
	}
	return s.session.Close()
}

// The fixed archive reservation includes hidden tar/PAX bytes, every possible
// entry/path slot before unpack, payload allocation, and repeated copy/hash work.
// This is a conservative cumulative work limit, not an allocator/OS sandbox.
func nativeLiveInflatedReservation() int64 {
	return skillbundle.DefaultMaxExtractedBytes + int64(skillbundle.DefaultMaxExtractedFiles)*1024 + (1 << 20)
}
func nativeLiveReserve(used *int64, amount int64) bool {
	if used == nil || *used < 0 || amount < 0 || *used > nativeLiveWorkMax || amount > nativeLiveWorkMax-*used {
		return false
	}
	*used += amount
	return true
}
