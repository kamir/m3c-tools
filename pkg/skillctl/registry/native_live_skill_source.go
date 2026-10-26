package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

// NativeLiveSkillSourceOptions selects the same explicit owned ER1 transport as
// the agent source. It supplies neither credential values nor authority callbacks.
type NativeLiveSkillSourceOptions = NativeLiveAgentSourceOptions

// NativeLiveSkillSource retains immutable endpoint, TLS and auth metadata.
// Its reader is private; no ambient client or transport can be injected by callers.
type NativeLiveSkillSource struct {
	reader  *NativeLiveAgentSource
	binding string
}

// NativeLiveSkillCandidate is owned untrusted input, not publication authority.
type NativeLiveSkillCandidate struct {
	Archive   []byte
	Bundle    *StagedBundle
	workBytes int64
	bindingID string
}

// NewNativeLiveSkillSource validates configuration without credentials or I/O.
func NewNativeLiveSkillSource(opts NativeLiveSkillSourceOptions) (*NativeLiveSkillSource, error) {
	reader, err := NewNativeLiveAgentSource(opts)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte("m3c.native-live-skill-source/v1\n" + reader.bindingID()))
	return &NativeLiveSkillSource{reader: reader, binding: hex.EncodeToString(sum[:])}, nil
}

func (s *NativeLiveSkillSource) bindingID() string {
	if s == nil {
		return ""
	}
	return s.binding
}

// Fetch requires this concrete session's held journal before looking up even a
// selected external credential. An acquired session is terminal after failure.
func (s *NativeLiveSkillSource) Fetch(ctx context.Context, session *NativeLiveSkillSession) (candidate *NativeLiveSkillCandidate, resultErr error) {
	if s == nil || s.reader == nil || s.reader.endpoint == "" || session == nil || ctx == nil {
		return nil, ErrNativeSessionUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if !session.mu.TryLock() {
		return nil, ErrNativeSessionUnavailable
	}
	defer session.mu.Unlock()
	if err := session.usable(ctx); err != nil {
		return nil, nativeSessionDiagnostic(err)
	}
	defer func() {
		if resultErr != nil {
			session.poisoned = true
			candidate = nil
		}
	}()
	if session.sourceFetched {
		return nil, ErrNativeSessionUnavailable
	}
	session.sourceFetched = true
	if session.journal == nil || session.lease == nil || !nativeSubject(session.rootDigest) {
		return nil, ErrNativeSessionUnavailable
	}
	if err := session.lease.recheck(ctx, session.rootDigest); err != nil {
		return nil, nativeSessionDiagnostic(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, nativeLiveIO(err)
	}
	wire, err := s.reader.fetchCandidate(ctx, session.journal, session.rootDigest, skillbundle.KindSkill)
	if err != nil {
		return nil, err
	}
	if wire == nil || wire.Bundle == nil {
		return nil, ErrNativeEvidenceInvalid
	}
	return &NativeLiveSkillCandidate{Archive: wire.Archive, Bundle: wire.Bundle, workBytes: wire.workBytes, bindingID: s.bindingID()}, nil
}
