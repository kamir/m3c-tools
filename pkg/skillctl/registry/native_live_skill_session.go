package registry

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// NativeSkillInstallPlan is copied display data for exactly one held SKILL
// session. BackupPath is part of consent, not a post-publication warning.
type NativeSkillInstallPlan struct {
	Rows      []NativeSkillInstallPlanRow
	Token     string
	ExpiresAt time.Time
}
type NativeSkillInstallPlanRow struct {
	Name, Version, Kind, Digest, Target, Operation, OldDigest, BackupPath string
}
type nativeSkillPlan struct {
	row    NativeSkillInstallPlanRow
	target *nativeSkillTree
	hash   string
	nonce  [32]byte
	issued time.Time
}

// NativeLiveSkillSession holds the native journal before carrier acquisition,
// through explicit consent and checked release. A zero value grants nothing.
type NativeLiveSkillSession struct {
	mu                                                   sync.Mutex
	journal                                              *NativeJournal
	lease                                                *nativeJournalLease
	rootDigest                                           string
	closed, poisoned, terminal, published, sourceFetched bool
	candidate                                            *NativeLiveSkillCandidate
	prepared                                             *preparedNativeSkill
	sourceBinding                                        string
	workBytes                                            int64
	contextBytes                                         int
	plan                                                 *nativeSkillPlan
	active                                               *nativeSkillPlan
	fs                                                   *nativeSkillFS
	workspace                                            *nativeSkillWorkspace
	skillOps                                             *nativeSkillFileOps
	phase                                                func(string) // observation only; every mutation still rechecks authority
	closeErr                                             error
	failureErr                                           error
}

// NewNativeLiveSkillSession never enrolls/adopts history or looks up credentials
// before acquiring and checking the explicit journal's existing lease.
func NewNativeLiveSkillSession(ctx context.Context, journal *NativeJournal, source *NativeLiveSkillSource, digest string) (out *NativeLiveSkillSession, resultErr error) {
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
	if err = lease.recheck(ctx, digest); err != nil {
		return nil, err
	}
	c, err := source.Fetch(ctx, s)
	if err != nil {
		return nil, err
	}
	if c == nil || c.bindingID != source.bindingID() || c.Bundle == nil || len(c.Archive) == 0 || len(c.Archive) > 16<<20 {
		return nil, ErrNativeEvidenceInvalid
	}
	s.workBytes = c.workBytes
	if !nativeLiveReserve(&s.workBytes, int64(len(c.Archive))+4*maxAgentContext+(128<<10)) {
		return nil, ErrNativeEvidenceInvalid
	}
	b := c.Bundle
	if !validAgentName(b.Name) || !nativeSkillVersionValid(b.Version) || b.Kind != "skill" || b.Digest != digest || b.StagedSkbPath != "" || b.ProvenancePath != "" {
		return nil, ErrNativeEvidenceInvalid
	}
	for _, v := range []string{b.Name, b.Version, b.Digest, b.Kind, b.Governance, b.PackedOnHost, b.AdmittedAt, b.SourceDocID, b.AuthorIdentity} {
		if !agentText(v, 8192) && v != "" {
			return nil, ErrNativeEvidenceInvalid
		}
	}
	contextCopy, contextRaw, err := snapshotAgentContext(b.Attestation)
	if err != nil {
		return nil, err
	}
	copyBundle := *b
	copyBundle.Attestation = contextCopy
	s.candidate = &NativeLiveSkillCandidate{Bundle: &copyBundle, Archive: append([]byte(nil), c.Archive...)}
	s.sourceBinding = source.bindingID()
	s.contextBytes = len(contextRaw)
	return s, nil
}

func (s *NativeLiveSkillSession) usable(ctx context.Context) error {
	if s != nil && s.failureErr != nil {
		return errors.Join(ErrNativeSessionUnavailable, s.failureErr)
	}
	if s != nil && s.fs != nil && s.fs.ioErr != nil {
		s.poisoned = true
		return errors.Join(ErrNativeSessionUnavailable, s.fs.ioErr)
	}
	if s == nil || ctx == nil || s.closed || s.poisoned || s.terminal || s.journal == nil || s.lease == nil {
		return ErrNativeSessionUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.journal.selection.validate()
}
func (s *NativeLiveSkillSession) observe(phase string) {
	if s.phase != nil {
		s.phase(phase)
	}
}
func (s *NativeLiveSkillSession) options(ctx context.Context) InstallOpts {
	p := s.journal.selection
	return InstallOpts{Ctx: ctx, NativeTrustRoots: p.artifactRoots, RegistrySpec: p.authority.registry, SkillsDir: filepath.Join(p.home, ".claude", "skills"), TrustRootsFingerprint: selfFingerprint(p.artifactRoots.pub), agentNow: func() time.Time { return s.journal.now().UTC() }}
}

// Plan invalidates an earlier nonce even if the new observation fails. It never
// refetches the carrier or reloads mutable policy paths.
func (s *NativeLiveSkillSession) Plan(ctx context.Context) (out *NativeSkillInstallPlan, resultErr error) {
	if s == nil {
		return nil, nativeSessionDiagnostic(ErrNativeSessionUnavailable)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.plan = nil
	defer func() {
		resultErr = s.diagnostic(resultErr)
		if resultErr != nil {
			out = nil
		}
	}()
	if err := s.usable(ctx); err != nil {
		return nil, err
	}
	if s.candidate == nil || s.candidate.Bundle == nil {
		return nil, ErrNativeEvidenceInvalid
	}
	reserve := int64(8*maxAgentContext + 128<<10)
	if s.prepared == nil {
		reserve += int64(4*len(s.candidate.Archive)) + 100<<20 + nativeLiveInflatedReservation() + 10000*(2*4096+256)
		reserve += int64(12*s.contextBytes) * int64(len(s.journal.selection.artifactRoots.Signers)+1)
	}
	if !nativeLiveReserve(&s.workBytes, reserve) {
		s.terminal = true
		return nil, ErrNativeEvidenceInvalid
	}
	if s.prepared == nil {
		p, err := prepareNativeSkillEvidence(s.candidate.Bundle, s.candidate.Archive, s.options(ctx))
		if err != nil {
			s.terminal = true
			return nil, err
		}
		s.prepared = p
	}
	if err := s.recheckLocked(ctx); err != nil {
		return nil, err
	}
	if s.fs == nil {
		// Reserve cleanup before exposing a plan. Its separate prepaid allowance
		// is consumed, never refunded, so a failed later phase cannot spend it.
		cleanup := int64(2<<20) + int64(3*(len(s.prepared.archive)+len(s.prepared.contextRaw)))
		for _, entry := range s.prepared.entries {
			cleanup += int64(3*len(entry.Content) + 20*(4096+256))
		}
		if !nativeLiveReserve(&s.workBytes, cleanup) {
			s.terminal = true
			return nil, ErrNativeEvidenceInvalid
		}
		ops := defaultNativeSkillFileOps()
		if s.skillOps != nil {
			ops = *s.skillOps
		}
		f, err := openNativeSkillFS(s.journal.selection, &s.workBytes, ops)
		if err != nil {
			return nil, errors.Join(ErrNativePersistence, err)
		}
		s.fs = f
		s.fs.cleanupLeft = cleanup
	}
	if s.workspace == nil {
		w, err := s.reserveWorkspace(ctx)
		s.workspace = w
		if err != nil {
			s.poisoned = true
			return nil, err
		}
		if err = s.stage(ctx); err != nil {
			s.poisoned = true
			return nil, err
		}
	}
	s.observe("before-target-recheck")
	target, err := s.fs.tree(ctx, s.prepared.bundle.Name, true, s.prepared.bundle.Name)
	if err != nil {
		return nil, err
	}
	if target.exists {
		older, e := nativeSkillVersionOlder(s.prepared.bundle.Version, target.version)
		if e != nil {
			return nil, e
		}
		if older {
			return nil, errAgentDowngrade(s.prepared.bundle.Name, target.version, s.prepared.bundle.Version)
		}
	}
	b := s.prepared.bundle
	row := NativeSkillInstallPlanRow{Name: b.Name, Version: b.Version, Kind: "skill", Digest: s.rootDigest, Target: filepath.Join(s.journal.selection.home, ".claude", "skills", b.Name), Operation: "create"}
	if target.exists {
		row.Operation = "overwrite"
		row.OldDigest = target.oldDigest
		row.BackupPath = filepath.Join(s.journal.selection.home, ".claude", "skills", s.workspace.backup)
	}
	h, err := s.consentHash(row, target)
	if err != nil {
		return nil, err
	}
	now := s.journal.now().UTC()
	p := &nativeSkillPlan{row: row, target: target, hash: h, issued: now}
	if _, err = rand.Read(p.nonce[:]); err != nil {
		return nil, err
	}
	if err = s.recheckLocked(ctx); err != nil {
		return nil, err
	}
	s.plan = p
	return &NativeSkillInstallPlan{Rows: []NativeSkillInstallPlanRow{row}, Token: base64.RawURLEncoding.EncodeToString(p.nonce[:]), ExpiresAt: now.Add(TokenTTL)}, nil
}

// Confirm consumes one attempt, even a malformed/wrong token. The retained
// bytes, full target tree and final journal/clock checks precede first rename.
func (s *NativeLiveSkillSession) Confirm(ctx context.Context, token string) (out []*InstallResult, resultErr error) {
	if s == nil {
		return nil, nativeSessionDiagnostic(ErrNativeSessionUnavailable)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.plan
	s.plan = nil
	if s.fs != nil && s.skillOps != nil {
		s.fs.ops = *s.skillOps
	}
	defer func() {
		if resultErr != nil && s.published {
			s.poisoned = true
			s.terminal = true
			s.failureErr = errors.Join(s.failureErr, resultErr)
		}
		resultErr = s.diagnostic(resultErr)
	}()
	if err := s.usable(ctx); err != nil {
		return nil, err
	}
	if p == nil {
		return nil, ErrNativeConsentInvalid
	}
	if len(token) != 43 {
		return nil, ErrNativeConsentInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token || subtle.ConstantTimeCompare(raw, p.nonce[:]) != 1 {
		return nil, ErrNativeConsentInvalid
	}
	s.active = p
	defer func() { s.active = nil }()
	if !nativeLiveReserve(&s.workBytes, int64(16*maxAgentContext+4*len(s.prepared.archive))) {
		s.terminal = true
		return nil, ErrNativeEvidenceInvalid
	}
	if err = s.recheckLocked(ctx); err != nil {
		return nil, err
	}
	s.observe("before-target-recheck")
	target, err := s.fs.tree(ctx, s.prepared.bundle.Name, true, s.prepared.bundle.Name)
	if err != nil {
		return nil, err
	}
	if !nativeSkillTreesEqual(p.target, target) {
		return nil, ErrPlanDrift
	}
	h, err := s.consentHash(p.row, target)
	if err != nil {
		return nil, err
	}
	if h != p.hash {
		return nil, ErrNativeConsentInvalid
	}
	r, err := s.publish(ctx, p)
	if r != nil {
		out = []*InstallResult{r}
	}
	if err != nil {
		return out, err
	}
	s.terminal = true
	return out, nil
}

func (s *NativeLiveSkillSession) recheckLocked(ctx context.Context) error {
	if s == nil || s.closed || s.poisoned || s.lease == nil || s.prepared == nil {
		return ErrNativeSessionUnavailable
	}
	if err := s.lease.recheck(ctx, s.rootDigest); err != nil {
		s.poisoned = true
		return err
	}
	if s.active != nil {
		now := s.journal.now().UTC()
		if now.Before(s.active.issued) || now.After(s.active.issued.Add(TokenTTL)) {
			return ErrNativeConsentInvalid
		}
	}
	p := s.prepared
	if !nativeLiveReserve(&s.workBytes, int64(len(p.archive))+int64(4*len(p.contextRaw))*int64(len(s.journal.selection.artifactRoots.Signers)+1)) {
		s.poisoned = true
		return ErrNativeEvidenceInvalid
	}
	if p.bundle.Digest != s.rootDigest || agentDigest(p.archive) != s.rootDigest {
		return ErrNativeEvidenceInvalid
	}
	if err := nativeSkillContextTenant(s.journal.selection, p.bundle.Attestation); err != nil {
		return err
	}
	return verifyAgentContext(s.journal.selection.artifactRoots, p.bundle.Attestation, s.rootDigest, p.bundle.Name, p.bundle.Version, s.journal.now().UTC())
}

func nativeSkillContextTenant(selected *NativeInstallSelection, c *AttestationContext) error {
	if selected == nil || selected.authority == nil || c == nil {
		return ErrNativeEvidenceInvalid
	}
	events := append([]map[string]any{c.AdmitEvent, c.GovernanceAttestation}, c.GovernanceAttestations...)
	for _, event := range events {
		for key := range event {
			if key != "tenant_scope" && strings.EqualFold(strings.ReplaceAll(key, "_", ""), "tenantscope") {
				return ErrNativeEvidenceInvalid
			}
		}
		v, ok := event["tenant_scope"]
		if !ok {
			return ErrNativeEvidenceInvalid
		}
		if selected.authority.tenant == nil {
			if v != nil {
				return ErrNativeEvidenceInvalid
			}
		} else if v != *selected.authority.tenant {
			return ErrNativeEvidenceInvalid
		}
		if registry, ok := event["registry"]; ok && registry != selected.authority.registry {
			return ErrNativeEvidenceInvalid
		}
	}
	return nil
}

func (s *NativeLiveSkillSession) consentHash(row NativeSkillInstallPlanRow, target *nativeSkillTree) (string, error) {
	selected := s.journal.selection
	// Private selection/root values were bounded and snapshotted at construction.
	// Hash the fixed-size tree digest; never Marshal a caller-sized target tree.
	if target == nil || len(selected.artifactRoots.Signers) > 256 {
		return "", ErrNativeConsentInvalid
	}
	left := 64<<10 - 4096
	charge := func(text string) bool {
		if len(text) > left/6 {
			return false
		}
		left -= 6 * len(text)
		return true
	}
	for _, text := range []string{selected.authority.historyID, selected.profileDigest, selected.selectionID, selected.project, selected.home, s.rootDigest, s.sourceBinding, target.digest, selected.artifactRoots.GovernanceMinimum, row.Name, row.Version, row.Kind, row.Digest, row.Target, row.Operation, row.OldDigest, row.BackupPath} {
		if !charge(text) {
			return "", ErrNativeConsentInvalid
		}
	}
	for _, pin := range selected.artifactRoots.Signers {
		if left < 256 {
			return "", ErrNativeConsentInvalid
		}
		left -= 256
		if !charge(pin.ReviewerID) {
			return "", ErrNativeConsentInvalid
		}
	}
	if !nativeLiveReserve(&s.workBytes, 256<<10) {
		return "", ErrNativeEvidenceInvalid
	}
	type pin struct{ ID, Key string }
	pins := make([]pin, 0, len(selected.artifactRoots.Signers))
	for _, p := range selected.artifactRoots.Signers {
		pins = append(pins, pin{p.ReviewerID, base64.StdEncoding.EncodeToString(p.pub)})
	}
	v := struct {
		Domain, History, Profile, Selection, Project, Home, Root, Runtime, Context, Source, Tree, ArtifactKey, Floor string
		Quorum                                                                                                       int
		Pins                                                                                                         []pin
		Row                                                                                                          NativeSkillInstallPlanRow
	}{"m3c.native-skill-install-consent/v1", selected.authority.historyID, selected.profileDigest, selected.selectionID, selected.project, selected.home, s.rootDigest, agentDigest(selected.runtimeRaw), agentDigest(s.prepared.contextRaw), s.sourceBinding, target.digest, base64.StdEncoding.EncodeToString(selected.artifactRoots.pub), selected.artifactRoots.GovernanceMinimum, selected.artifactRoots.quorum(), pins, row}
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > 64<<10 {
		return "", ErrNativeConsentInvalid
	}
	return agentDigest(raw), nil
}

func (s *NativeLiveSkillSession) diagnostic(err error) error {
	if s.fs != nil && s.fs.ioErr != nil {
		s.poisoned = true
		err = errors.Join(err, s.fs.ioErr)
	}
	if err == nil {
		return nil
	}
	if s.published {
		err = errors.Join(ErrAgentPublicationIncomplete, ErrNativePersistence, err)
	}
	return nativeSessionDiagnostic(err)
}

// Close is serialized, checks owned cleanup, then releases publication handles
// and the journal last. No unknown workspace or historical backup is removed.
func (s *NativeLiveSkillSession) Close() error {
	if s == nil {
		return nativeSessionDiagnostic(ErrNativeSessionUnavailable)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	s.plan = nil
	var err error
	if s.fs != nil && s.skillOps != nil {
		s.fs.ops = *s.skillOps
	}
	if s.workspace != nil && !s.workspace.complete && !s.published {
		err = s.cancelWorkspace()
	}
	if s.workspace != nil && s.workspace.lock != nil {
		err = errors.Join(err, s.fs.closeFile(s.workspace.lock))
		s.workspace.lock = nil
	}
	if s.fs != nil {
		err = errors.Join(err, s.fs.Close())
		s.fs = nil
	}
	if s.lease != nil {
		err = errors.Join(err, s.lease.Close())
		s.lease = nil
	}
	if err != nil {
		err = errors.Join(ErrNativePersistence, err)
	}
	s.closeErr = s.diagnostic(err)
	return s.closeErr
}
