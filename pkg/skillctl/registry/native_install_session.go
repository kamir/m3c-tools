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

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

// NativeInstallSession holds the selected journal lease through planning,
// consent and checked publication. Only BeginOfflineInstall constructs one.
// Callers must check Close, including after a successful ConfirmInstall.
type NativeInstallSession struct {
	mu                                    sync.Mutex
	journal                               *NativeJournal
	lease                                 *nativeJournalLease
	rootDigest                            string
	closed, poisoned, terminal, published bool
	plan                                  *nativeRetainedPlan
	activeConsent                         *nativeRetainedPlan
	closeErr                              error
	agentOps                              *agentFileOps
	phase                                 func(string) // private observation seam, never an authorization callback
}

// NativeInstallPlan contains copied display data and an opaque single-use token.
type NativeInstallPlan struct {
	Rows      []NativeInstallPlanRow
	Token     string
	ExpiresAt time.Time
}
type NativeInstallPlanRow struct {
	Name, Version, Kind, Digest, Target, Operation, OldDigest string
}
type nativeRetainedPlan struct {
	prepared            *preparedAgent
	inputHash, planHash string
	nonce               [32]byte
	issued              time.Time
	row                 NativeInstallPlanRow
	targets             []nativeTargetObservation
}

type nativeSessionError struct{ cause error }

func (e *nativeSessionError) Error() string {
	if errors.Is(e.cause, ErrAgentPublicationIncomplete) {
		return "native offline installation incomplete; files may already have changed; inspect destination, close session and begin again"
	}
	if errors.Is(e.cause, ErrNativePersistence) {
		return "native trust persistence is uncertain; inspect trust status, close session and begin again"
	}
	return "native offline installation refused; inspect trust status before retrying"
}
func (e *nativeSessionError) Unwrap() error { return e.cause }
func nativeSessionDiagnostic(err error) error {
	if err == nil {
		return nil
	}
	return &nativeSessionError{cause: err}
}

// BeginOfflineInstall requires existing authenticated history. It never enrolls
// or adopts evidence from an install request.
func (j *NativeJournal) BeginOfflineInstall(ctx context.Context, rootDigest string) (*NativeInstallSession, error) {
	if j == nil || ctx == nil || !nativeSubject(rootDigest) {
		return nil, nativeSessionDiagnostic(ErrNativeSessionUnavailable)
	}
	l, err := j.acquire(ctx)
	if err != nil {
		return nil, nativeSessionDiagnostic(err)
	}
	if err = l.recheck(ctx, rootDigest); err != nil {
		return nil, nativeSessionDiagnostic(errors.Join(err, l.Close()))
	}
	return &NativeInstallSession{journal: j, lease: l, rootDigest: rootDigest}, nil
}

func nativeSubject(s string) bool {
	return len(s) == 71 && strings.HasPrefix(s, "sha256:") && nativeSHA(s[7:])
}
func (s *NativeInstallSession) usable(ctx context.Context) error {
	if ctx == nil || s == nil || s.closed || s.poisoned || s.terminal || s.journal == nil || s.lease == nil {
		return ErrNativeSessionUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.journal.selection.validate()
}
func (s *NativeInstallSession) observe(phase string) {
	if s.phase != nil {
		s.phase(phase)
	}
}

// PlanInstall authenticates and retains exactly one dependency-free agent.
// Replanning invalidates the previous token even when the new plan is refused.
func (s *NativeInstallSession) PlanInstall(ctx context.Context, bundles []*StagedBundle) (plan *NativeInstallPlan, resultErr error) {
	if s == nil {
		return nil, nativeSessionDiagnostic(ErrNativeSessionUnavailable)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.plan = nil
	defer func() {
		resultErr = nativeSessionDiagnostic(resultErr)
		if resultErr != nil {
			plan = nil
		}
	}()
	if err := s.usable(ctx); err != nil {
		return nil, err
	}
	input, inputHash, err := s.snapshotInput(bundles)
	if err != nil {
		return nil, err
	}
	if err = s.lease.recheck(ctx, s.rootDigest); err != nil {
		s.poisoned = true
		return nil, err
	}
	opts := s.installOpts(ctx)
	raw, err := readNativeAgentSnapshot(input.StagedSkbPath, s.rootDigest, agentOpsOf(opts))
	if err != nil {
		return nil, err
	}
	prepared, err := prepareNativeAgentEvidence(input, raw, opts)
	if err != nil {
		return nil, err
	}
	if err = s.validatePrepared(prepared); err != nil {
		return nil, err
	}
	if err = s.recheckLocked(ctx, prepared); err != nil {
		return nil, err
	}
	targets, err := nativeObserveTargets(s.journal.selection, prepared.bundle.Name)
	if err != nil {
		return nil, err
	}
	if targets[2].Exists && agentVersionOlder(input.Version, targets[2].Version) {
		return nil, errAgentDowngrade(input.Name, targets[2].Version, input.Version)
	}
	row := NativeInstallPlanRow{Name: input.Name, Version: input.Version, Kind: input.Kind, Digest: s.rootDigest, Target: filepath.Join(s.journal.selection.home, ".claude", "agents", input.Name+".md"), Operation: "create"}
	if targets[0].Exists {
		row.Operation = "overwrite"
		row.OldDigest = targets[0].Digest
	}
	issued := s.journal.now().UTC()
	hash, err := s.consentHash(prepared, row, targets)
	if err != nil {
		return nil, err
	}
	retained := &nativeRetainedPlan{prepared: prepared, inputHash: inputHash, planHash: hash, issued: issued, row: row, targets: targets}
	if _, err = rand.Read(retained.nonce[:]); err != nil {
		return nil, err
	}
	s.plan = retained
	return &NativeInstallPlan{Rows: []NativeInstallPlanRow{row}, Token: base64.RawURLEncoding.EncodeToString(retained.nonce[:]), ExpiresAt: issued.Add(TokenTTL)}, nil
}

// ConfirmInstall consumes the current native consent before any validation.
// Published bytes come from Plan's retained authenticated archive, never a
// reopened cache path. Each failed attempt requires a new explicit Plan.
func (s *NativeInstallSession) ConfirmInstall(ctx context.Context, bundles []*StagedBundle, token string) (results []*InstallResult, resultErr error) {
	if s == nil {
		return nil, nativeSessionDiagnostic(ErrNativeSessionUnavailable)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.plan
	s.plan = nil
	defer func() {
		if resultErr != nil {
			results = nil
			if s.published {
				resultErr = agentPublicationFailure(resultErr)
			}
		}
		resultErr = nativeSessionDiagnostic(resultErr)
	}()
	if err := s.usable(ctx); err != nil {
		return nil, err
	}
	if p == nil || len(token) != 43 {
		return nil, ErrNativeConsentInvalid
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(nonce) != 32 || subtle.ConstantTimeCompare(nonce, p.nonce[:]) != 1 {
		return nil, ErrNativeConsentInvalid
	}
	now := s.journal.now().UTC()
	if now.Before(p.issued) || now.After(p.issued.Add(TokenTTL)) {
		return nil, ErrNativeConsentInvalid
	}
	s.activeConsent = p
	defer func() { s.activeConsent = nil }()
	_, hash, err := s.snapshotInput(bundles)
	if err != nil || hash != p.inputHash {
		return nil, errors.Join(ErrNativeConsentInvalid, err)
	}
	if err = s.recheckLocked(ctx, p.prepared); err != nil {
		return nil, err
	}
	targets, err := nativeObserveTargets(s.journal.selection, p.prepared.bundle.Name)
	if err != nil {
		return nil, err
	}
	if !nativeTargetsEqual(p.targets, targets) {
		return nil, ErrPlanDrift
	}
	currentHash, err := s.consentHash(p.prepared, p.row, targets)
	if err != nil || currentHash != p.planHash {
		return nil, errors.Join(ErrNativeConsentInvalid, err)
	}
	s.observe("before-agent-lock")
	if err = s.recheckLocked(ctx, p.prepared); err != nil {
		return nil, err
	}
	opts := s.installOpts(ctx)
	l, err := acquireAgentPublication(ctx, agentsDirFor(opts.SkillsDir), agentOpsOf(opts))
	if err != nil {
		s.poisoned = true
		return nil, err
	}
	opts.agentLease = l
	defer func() {
		s.published = s.published || l.published
		closeErr := l.Close()
		if closeErr != nil {
			s.poisoned = true
		}
		resultErr = errors.Join(resultErr, closeErr)
	}()
	// Recheck under the publication lease, before any staging writes. A target
	// changed by another cooperating installer invalidates the original consent.
	targets, err = nativeObserveTargets(s.journal.selection, p.prepared.bundle.Name)
	if err != nil {
		return nil, err
	}
	if !nativeTargetsEqual(p.targets, targets) {
		return nil, ErrPlanDrift
	}
	r, err := publishPreparedAgent(p.prepared, opts, s)
	if err != nil {
		s.poisoned = true
		return nil, err
	}
	r.OldDigest = p.row.OldDigest
	return []*InstallResult{r}, nil
}

func (s *NativeInstallSession) installOpts(ctx context.Context) InstallOpts {
	selected := s.journal.selection
	return InstallOpts{Ctx: ctx, SkillsDir: filepath.Join(selected.home, ".claude", "skills"), NativeTrustRoots: selected.artifactRoots, RegistrySpec: selected.authority.registry, TrustRootsFingerprint: selfFingerprint(selected.artifactRoots.pub), agentOps: s.agentOps, agentNow: func() time.Time { return s.journal.now().UTC() }}
}

// recheckLocked is called only with the session mutex and journal OS lease held.
// It does not acquire the journal recursively or load mutable authority files.
func (s *NativeInstallSession) recheckLocked(ctx context.Context, p *preparedAgent) error {
	if s == nil || s.closed || s.poisoned || s.lease == nil || p == nil {
		return ErrNativeSessionUnavailable
	}
	if err := s.lease.recheck(ctx, s.rootDigest); err != nil {
		s.poisoned = true
		return err
	}
	if s.activeConsent != nil {
		now := s.journal.now().UTC()
		if now.Before(s.activeConsent.issued) || now.After(s.activeConsent.issued.Add(TokenTTL)) {
			return ErrNativeConsentInvalid
		}
	}
	if err := s.validatePrepared(p); err != nil {
		return err
	}
	return verifyAgentContext(s.journal.selection.artifactRoots, p.bundle.Attestation, s.rootDigest, p.bundle.Name, p.bundle.Version, s.journal.now().UTC())
}

func (s *NativeInstallSession) snapshotInput(bundles []*StagedBundle) (*StagedBundle, string, error) {
	if len(bundles) != 1 || bundles[0] == nil {
		return nil, "", ErrNativeDependenciesUnavailable
	}
	b := bundles[0]
	if b.Kind != skillbundle.KindAgent {
		return nil, "", ErrNativeDependenciesUnavailable
	}
	if !validAgentName(b.Name) || b.Digest != s.rootDigest || !agentText(b.Version, 256) {
		return nil, "", ErrAgentEvidenceInvalid
	}
	metadataLeft := (128 << 10) - 2048
	for _, v := range []string{b.Name, b.Version, b.Digest, b.Kind, b.Governance, b.PackedOnHost, b.AdmittedAt, b.StagedSkbPath, b.ProvenancePath, b.SourceDocID, b.AuthorIdentity} {
		if len(v) > 8192 || len(v) > metadataLeft/6 {
			return nil, "", ErrAgentEvidenceInvalid
		}
		metadataLeft -= 6 * len(v)
	}
	c, _, err := snapshotAgentContext(b.Attestation)
	if err != nil {
		return nil, "", err
	}
	frozen := *b
	frozen.Attestation = c
	raw, err := json.Marshal(&frozen)
	if err != nil || len(raw) > maxAgentContext+(128<<10) {
		return nil, "", ErrAgentEvidenceInvalid
	}
	return &frozen, agentDigest(raw), nil
}

func (s *NativeInstallSession) validatePrepared(p *preparedAgent) error {
	if p == nil || p.bundle == nil || p.bundle.Digest != s.rootDigest || agentDigest(p.archive) != s.rootDigest {
		return ErrAgentEvidenceInvalid
	}
	a := s.journal.selection.authority
	c := p.bundle.Attestation
	events := make([]map[string]any, 0, len(c.GovernanceAttestations)+2)
	events = append(events, c.AdmitEvent, c.GovernanceAttestation)
	events = append(events, c.GovernanceAttestations...)
	for _, ev := range events {
		tenant, ok := ev["tenant_scope"]
		if !ok || (a.tenant == nil && tenant != nil) || (a.tenant != nil && tenant != *a.tenant) {
			return ErrAgentEvidenceInvalid
		}
		for key := range ev {
			if key != "tenant_scope" && strings.EqualFold(strings.ReplaceAll(key, "_", ""), "tenantscope") {
				return ErrAgentEvidenceInvalid
			}
		}
		if registry, ok := ev["registry"]; ok && registry != a.registry {
			return ErrAgentEvidenceInvalid
		}
	}
	return nativeEmptyAgentDependencies(p.entries)
}

func nativeEmptyAgentDependencies(entries []skillbundle.Entry) error {
	for _, entry := range entries {
		if entry.Rel != "bundle.json" {
			continue
		}
		m, err := readAgentJSON(entry.Content, 1<<20)
		if err != nil {
			return err
		}
		for key := range m {
			fold := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", ""))
			for _, canonical := range []string{"depends_on", "data_dependencies", "package_dependencies"} {
				if fold == strings.ReplaceAll(canonical, "_", "") && key != canonical {
					return ErrNativeDependenciesUnavailable
				}
			}
		}
		if _, exists := m["package_dependencies"]; exists {
			return ErrNativeDependenciesUnavailable
		}
		for _, key := range []string{"depends_on", "data_dependencies"} {
			v, exists := m[key]
			if !exists && key == "data_dependencies" {
				continue
			}
			array, ok := v.([]any)
			if !exists || !ok || len(array) != 0 {
				return ErrNativeDependenciesUnavailable
			}
		}
		return nil
	}
	return ErrAgentEvidenceInvalid
}

func (s *NativeInstallSession) consentHash(p *preparedAgent, row NativeInstallPlanRow, targets []nativeTargetObservation) (string, error) {
	selected := s.journal.selection
	// Charge an escaped-JSON upper bound before copying reviewer strings or
	// constructing the serialized descriptor. Fixed structural overhead is ample
	// for one row, three target observations and at most 256 reviewer pins.
	left := 64<<10 - 4096
	charge := func(text string) bool {
		if len(text) > left/6 {
			return false
		}
		left -= 6 * len(text)
		return true
	}
	for _, text := range []string{selected.authority.historyID, selected.profileDigest, selected.selectionID, selected.project, selected.home, s.rootDigest, selected.artifactRoots.GovernanceMinimum, row.Name, row.Version, row.Kind, row.Digest, row.Target, row.Operation, row.OldDigest} {
		if !charge(text) {
			return "", ErrNativeConsentInvalid
		}
	}
	if len(targets) != 3 || len(selected.artifactRoots.Signers) > 256 {
		return "", ErrNativeConsentInvalid
	}
	for _, target := range targets {
		for _, text := range []string{target.Path, target.Digest, target.Modified, target.Version} {
			if !charge(text) {
				return "", ErrNativeConsentInvalid
			}
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
	// Roots are bounded immutable copies. pub key slices are intentionally
	// encoded separately: unexported legacy key fields never vanish from consent.
	type signer struct{ ID, Key string }
	signers := make([]signer, 0, len(selected.artifactRoots.Signers))
	for _, pin := range selected.artifactRoots.Signers {
		signers = append(signers, signer{pin.ReviewerID, base64.StdEncoding.EncodeToString(pin.pub)})
	}
	value := struct {
		Domain, History, Profile, Selection, Project, Home, Root, Runtime, Context, ArtifactKey, Floor string
		Quorum                                                                                         int
		Signers                                                                                        []signer
		Row                                                                                            NativeInstallPlanRow
		Targets                                                                                        []nativeTargetObservation
	}{"m3c.native-offline-install-consent/v1", selected.authority.historyID, selected.profileDigest, selected.selectionID, selected.project, selected.home, s.rootDigest, agentDigest(selected.runtimeRaw), agentDigest(p.contextRaw), base64.StdEncoding.EncodeToString(selected.artifactRoots.pub), selected.artifactRoots.GovernanceMinimum, selected.artifactRoots.quorum(), signers, row, targets}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 64<<10 {
		return "", ErrNativeConsentInvalid
	}
	return agentDigest(raw), nil
}

// Close is serialized with Plan and Confirm, releases the journal last, and
// preserves uncertainty if a checked release fails after publication.
func (s *NativeInstallSession) Close() error {
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
	if s.lease == nil {
		s.closeErr = nativeSessionDiagnostic(ErrNativeSessionUnavailable)
		return s.closeErr
	}
	err := s.lease.Close()
	if err != nil && s.published {
		err = agentPublicationFailure(err)
	}
	s.closeErr = nativeSessionDiagnostic(err)
	return s.closeErr
}
