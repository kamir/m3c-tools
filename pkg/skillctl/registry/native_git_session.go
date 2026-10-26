package registry

import (
	"context"
	"errors"
)

// NewNativeGitAgentSession acquires existing native history before the selected
// Git source can read credentials or contact its fixed API. The returned session
// retains the acquired bytes and full source-proof binding through consent.
func NewNativeGitAgentSession(ctx context.Context, journal *NativeJournal, source *NativeGitSource, digest string) (out *NativeLiveAgentSession, resultErr error) {
	if ctx == nil || journal == nil || source == nil {
		return nil, nativeSessionDiagnostic(ErrNativeSessionUnavailable)
	}
	if !nativeSubject(digest) {
		return nil, nativeSessionDiagnostic(ErrNativeEvidenceInvalid)
	}
	s, err := journal.BeginOfflineInstall(ctx, digest)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(nativeSessionDiagnostic(resultErr), s.Close())
			out = nil
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	// The acquisition is consumed under the actual kind-specific mutex. The
	// private source checks this held journal lease, without recursive locking.
	s.terminal = true
	c, err := source.fetchCandidate(ctx, journal, s.lease, digest, "agent")
	if err != nil {
		s.poisoned = true
		return nil, err
	}
	if c == nil {
		s.poisoned = true
		return nil, ErrNativeEvidenceInvalid
	}
	live, err := retainNativeAgentCandidateLocked(s, &NativeLiveAgentCandidate{Archive: c.Archive, Bundle: c.Bundle, workBytes: c.workBytes}, c.bindingID)
	if err != nil {
		s.poisoned = true
		return nil, err
	}
	s.terminal = false
	return live, nil
}

// NewNativeGitSkillSession uses the SKILL publisher and its separate plan type.
// It never casts SKILL evidence into an agent session or adopts journal history.
func NewNativeGitSkillSession(ctx context.Context, journal *NativeJournal, source *NativeGitSource, digest string) (out *NativeLiveSkillSession, resultErr error) {
	if ctx == nil || journal == nil || source == nil {
		return nil, nativeSessionDiagnostic(ErrNativeSessionUnavailable)
	}
	if !nativeSubject(digest) {
		return nil, nativeSessionDiagnostic(ErrNativeEvidenceInvalid)
	}
	lease, err := journal.acquire(ctx)
	if err != nil {
		return nil, nativeSessionDiagnostic(err)
	}
	s := &NativeLiveSkillSession{journal: journal, lease: lease, rootDigest: digest}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(nativeSessionDiagnostic(resultErr), s.Close())
			out = nil
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sourceFetched = true
	s.terminal = true
	c, err := source.fetchCandidate(ctx, journal, lease, digest, "skill")
	if err != nil {
		s.poisoned = true
		return nil, err
	}
	if c == nil {
		s.poisoned = true
		return nil, ErrNativeEvidenceInvalid
	}
	if err = s.retainCandidateLocked(&NativeLiveSkillCandidate{Archive: c.Archive, Bundle: c.Bundle, workBytes: c.workBytes}, c.bindingID); err != nil {
		s.poisoned = true
		return nil, err
	}
	s.terminal = false
	return s, nil
}
