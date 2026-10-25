package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/dependencies"
	"github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

type installedSkillSource struct {
	policy   *projectpolicy.Policy
	limits   installedProofLimits
	budget   installedProofBudget
	anchors  []*installedProofRoot
	active   map[string]*installedProofRoot
	terminal error
	closed   bool
}

func newInstalledSkillSource(policy *projectpolicy.Policy) *installedSkillSource {
	s := &installedSkillSource{policy: policy, limits: defaultInstalledProofLimits, active: make(map[string]*installedProofRoot)}
	s.budget.limits = &s.limits
	return s
}
func (s *installedSkillSource) fail(kind, name string) ([]dependencies.Artifact, error) {
	if s.terminal == nil {
		if kind != "skill" && kind != "agent" {
			kind = "artifact"
		}
		if len(name) > 128 || !utf8.ValidString(name) {
			name = "invalid"
		}
		s.terminal = fmt.Errorf("install: dependency %s %q requires a current installed skill with matching signed retained proof; install or reinstall it using the selected project profile: %w", kind, name, verify.ErrDepsUnsatisfied)
	}
	return nil, s.terminal
}
func (s *installedSkillSource) openActive(ctx context.Context, name string) (*installedProofRoot, error) {
	if ctx == nil {
		return nil, errors.New("installed proof context required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(name) > 128 {
		return nil, verify.ErrDepsUnsatisfied
	}
	if canonical, err := CanonicalSkillName(name); err != nil || canonical != name {
		return nil, verify.ErrDepsUnsatisfied
	}
	if err := s.validateLive(ctx); err != nil {
		return nil, err
	}
	if p := s.active[name]; p != nil {
		return p, nil
	}
	if len(s.anchors) == 0 {
		for _, part := range []string{s.policy.ArtifactHome(), ".claude", "skills"} {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			var parent *installedProofRoot
			if len(s.anchors) > 0 {
				parent = s.anchors[len(s.anchors)-1]
			}
			p, err := openProofRoot(&s.budget, parent, part)
			if err != nil {
				return nil, err
			}
			s.anchors = append(s.anchors, p)
		}
	}
	p, err := openProofRoot(&s.budget, s.anchors[len(s.anchors)-1], name)
	if err != nil {
		return nil, err
	}
	s.active[name] = p
	return p, nil
}
func (s *installedSkillSource) validateLive(ctx context.Context) error {
	if s.terminal != nil {
		return s.terminal
	}
	if s.closed {
		return errors.New("installed proof source closed")
	}
	if ctx == nil {
		return errors.New("installed proof context required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, p := range s.anchors {
		if err := p.validate(); err != nil {
			return err
		}
	}
	for _, p := range s.active {
		if err := p.validate(); err != nil {
			return err
		}
	}
	return nil
}
func (s *installedSkillSource) validateProofs(ctx context.Context) error {
	if err := s.validateLive(ctx); err != nil {
		return err
	}
	for _, p := range s.active {
		if p.baseline == nil {
			return verify.ErrDepsUnsatisfied
		}
		if err := p.sameInventory(ctx, p.baseline); err != nil {
			return err
		}
	}
	return s.validateLive(ctx)
}
func (s *installedSkillSource) Close() error {
	s.closed = true
	var err error
	for _, p := range s.active {
		err = errors.Join(err, p.close())
	}
	for i := len(s.anchors) - 1; i >= 0; i-- {
		err = errors.Join(err, s.anchors[i].close())
	}
	s.active = make(map[string]*installedProofRoot)
	s.anchors = nil
	return err
}
func (s *installedSkillSource) Candidates(ctx context.Context, kind, name string) ([]dependencies.Artifact, error) {
	if s.terminal != nil {
		return nil, s.terminal
	}
	if s.closed {
		return s.fail(kind, name)
	}
	if kind != "skill" || s.policy == nil || s.policy.TrustRoot().IdentityKeysAuthorized != "pinned" {
		return s.fail(kind, name)
	}
	p, err := s.openActive(ctx, name)
	if err != nil {
		return s.fail(kind, name)
	}
	entries, err := p.inventory(ctx)
	if err != nil {
		return s.fail(kind, name)
	}
	var blobEntry, metaEntry *installedProofEntry
	for i := range entries {
		e := &entries[i]
		if !strings.Contains(e.rel, "/") && strings.HasSuffix(e.rel, ".skb") {
			if e.info.IsDir() || blobEntry != nil {
				return s.fail(kind, name)
			}
			blobEntry = e
		}
		if e.rel == offlineMetaFile {
			if e.info.IsDir() {
				return s.fail(kind, name)
			}
			metaEntry = e
		}
	}
	if blobEntry == nil || metaEntry == nil {
		return s.fail(kind, name)
	}
	raw, err := p.read(ctx, *metaEntry, 1<<20)
	if err != nil {
		return s.fail(kind, name)
	}
	// Validate the bounded envelope before decoding or allocating typed vectors.
	if err = s.budget.charge(int64(len(raw)) * 8); err != nil {
		return s.fail(kind, name)
	}
	meta, err := installedProofMeta(raw)
	if err != nil {
		return s.fail(kind, name)
	}
	blob, err := p.read(ctx, *blobEntry, registry.MaxBlobSize)
	if err != nil {
		return s.fail(kind, name)
	}
	// Snapshot copies and hashes these same bytes. Reserve both operations first.
	if err = s.budget.charge(int64(len(blob)) * 2); err != nil {
		return s.fail(kind, name)
	}
	allowance := s.limits.WorkBytes - s.budget.work
	if allowance <= 1 {
		return s.fail(kind, name)
	}
	// Conservatively reserve decoder object/copy work from stream bytes. The
	// manifest has a one-MiB wire cap but JSON objects cost more than wire bytes.
	const decodeWorkFactor int64 = 64
	inflatedCap := allowance/decodeWorkFactor - 1
	// The stream also bounds all surfaced header/path allocations before the
	// snapshot parser runs. This deliberately rejects large payloads when the
	// remaining aggregate path or entry reservation cannot cover that stream.
	if remaining := int64(s.limits.PathBytes - s.budget.paths - 1); inflatedCap > remaining {
		inflatedCap = remaining
	}
	if remaining := int64(s.limits.Entries-s.budget.entries)*512 - 1; inflatedCap > remaining {
		inflatedCap = remaining
	}
	if inflatedCap <= 0 {
		return s.fail(kind, name)
	}
	// Reserve the largest possible surfaced header/path allocation before decode.
	// A surfaced tar header costs at least 512 stream bytes; cap+1 covers the
	// overflow probe on failure. Outstanding reservations block other charges.
	reservedEntries := int((inflatedCap + 1) / 512)
	if reservedEntries > skillbundle.DefaultMaxExtractedFiles {
		reservedEntries = skillbundle.DefaultMaxExtractedFiles
	}
	s.budget.reservedWork = (inflatedCap + 1) * decodeWorkFactor
	s.budget.reservedEntries = reservedEntries
	s.budget.reservedPaths = int(inflatedCap + 1)
	snapshot, verifyErr := verify.VerifySnapshot(verify.VerifyOpts{Ctx: ctx, BundleMeta: meta, TrustRoot: s.policy.TrustRoot(), Tenant: s.policy.TrustRoots().TenantScope}, blob, inflatedCap)
	// Settle the temporary reservation against actual work, including failed
	// decoder bytes. No performed read/copy/hash/decode work is refunded.
	s.budget.reservedWork = 0
	s.budget.reservedEntries = 0
	s.budget.reservedPaths = 0
	if snapshot != nil {
		err = s.budget.charge(snapshot.Usage.InflatedBytes * decodeWorkFactor)
		if snapshot.Usage.Entries > reservedEntries {
			return s.fail(kind, name)
		}
		s.budget.entries += snapshot.Usage.Entries
	}
	if verifyErr != nil || err != nil || snapshot == nil || snapshot.Verification == nil {
		return s.fail(kind, name)
	}
	for _, entry := range snapshot.Entries {
		depth := strings.Count(entry.Rel, "/") + 1
		if !utf8.ValidString(entry.Rel) || depth > s.limits.Depth || len(entry.Rel) > s.limits.PathLength || len(entry.Rel) > s.limits.PathBytes-s.budget.paths {
			return s.fail(kind, name)
		}
		s.budget.paths += len(entry.Rel)
	}
	manifest, err := projectSnapshotManifest(snapshot)
	if err != nil {
		return s.fail(kind, name)
	}
	signedName, nok := manifest["name"].(string)
	version, vok := manifest["version"].(string)
	signedKind := "skill"
	if v, present := manifest["kind"]; present {
		var ok bool
		signedKind, ok = v.(string)
		if !ok {
			return s.fail(kind, name)
		}
	}
	if signedKind == "" {
		signedKind = "skill"
	}
	if !nok || !vok || signedName != name || signedKind != "skill" {
		return s.fail(kind, name)
	}
	if v, present := manifest["schema"]; present {
		schema, ok := v.(string)
		if !ok || !skillbundle.KnownSchema(schema) {
			return s.fail(kind, name)
		}
	}
	assessment := skillbundle.AssessRuntimeDeclarations(manifest)
	if assessment.Status == skillbundle.RuntimeDependenciesInvalid {
		return s.fail(kind, name)
	}
	if err = p.compare(ctx, entries, snapshot.Entries); err != nil {
		return s.fail(kind, name)
	}
	if err = p.sameInventory(ctx, entries); err != nil {
		return s.fail(kind, name)
	}
	p.baseline = entries
	if err = s.validateLive(ctx); err != nil {
		return s.fail(kind, name)
	}
	return []dependencies.Artifact{{Authority: s.policy.ProfileDigest(), Kind: "skill", Name: name, Version: version, Digest: snapshot.Verification.Digest, Declarations: assessment.Declarations}}, nil
}
func installedProofMeta(raw []byte) (*registry.BundleMeta, error) {
	if !utf8.Valid(raw) {
		return nil, verify.ErrDigestMismatch
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	nodes := 0
	if err := proofJSONValue(dec, 0, &nodes); err != nil {
		return nil, err
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(raw, &envelope) != nil || envelope == nil {
		return nil, verify.ErrDigestMismatch
	}
	for k := range envelope {
		if k != "bundle_meta" && strings.EqualFold(k, "bundle_meta") {
			return nil, verify.ErrDigestMismatch
		}
	}
	var m registry.BundleMeta
	if json.Unmarshal(envelope["bundle_meta"], &m) != nil {
		return nil, verify.ErrDigestMismatch
	}
	if err := validateProjectMeta(&m); err != nil {
		return nil, err
	}
	return &m, nil
}
func proofJSONValue(d *json.Decoder, depth int, nodes *int) error {
	*nodes++
	if depth > 64 || *nodes > 16384 {
		return verify.ErrDigestMismatch
	}
	tok, err := d.Token()
	if err != nil {
		return err
	}
	switch tok {
	case json.Delim('{'):
		seen := make(map[string]bool)
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			s, ok := key.(string)
			if !ok {
				return verify.ErrDigestMismatch
			}
			folded := strings.ToLower(s)
			if seen[folded] {
				return verify.ErrDigestMismatch
			}
			seen[folded] = true
			if err = proofJSONValue(d, depth+1, nodes); err != nil {
				return err
			}
		}
		tok, err = d.Token()
		if err != nil || tok != json.Delim('}') {
			return verify.ErrDigestMismatch
		}
	case json.Delim('['):
		for d.More() {
			if err = proofJSONValue(d, depth+1, nodes); err != nil {
				return err
			}
		}
		tok, err = d.Token()
		if err != nil || tok != json.Delim(']') {
			return verify.ErrDigestMismatch
		}
	case json.Delim('}'), json.Delim(']'):
		return verify.ErrDigestMismatch
	}
	return nil
}
func projectSnapshotManifest(snapshot *verify.SnapshotResult) (map[string]any, error) {
	for _, e := range snapshot.Entries {
		if e.Rel == "bundle.json" && !e.IsDir {
			if !utf8.Valid(e.Content) {
				return nil, verify.ErrDigestMismatch
			}
			return validateProjectManifest(snapshot.Manifest)
		}
	}
	return nil, verify.ErrDigestMismatch
}
func (p *installedProofRoot) compare(ctx context.Context, actual []installedProofEntry, expected []skillbundle.Entry) error {
	want := make(map[string]skillbundle.Entry, len(expected))
	for _, e := range expected {
		if e.Rel == "." {
			continue
		}
		if _, exists := want[e.Rel]; exists {
			return verify.ErrDigestMismatch
		}
		// A signed payload cannot hide behind an install-owned exemption.
		if proofExempt(e.Rel) {
			return verify.ErrDigestMismatch
		}
		want[e.Rel] = e
	}
	// Extraction creates implied parent directories even when tar omits their
	// headers. Only ancestors of signed entries may be added to the comparison.
	for _, e := range expected {
		for parent := path.Dir(e.Rel); parent != "."; parent = path.Dir(parent) {
			if v, ok := want[parent]; ok {
				if !v.IsDir {
					return verify.ErrDigestMismatch
				}
				continue
			}
			if proofExempt(parent) {
				return verify.ErrDigestMismatch
			}
			if err := p.budget.entry(parent, strings.Count(parent, "/")+1); err != nil {
				return err
			}
			want[parent] = skillbundle.Entry{Rel: parent, IsDir: true}
		}
	}
	for _, a := range actual {
		if proofExempt(a.rel) {
			if a.info.IsDir() {
				return verify.ErrDigestMismatch
			}
			continue
		}
		e, ok := want[a.rel]
		if !ok || e.IsDir != a.info.IsDir() {
			return verify.ErrDigestMismatch
		}
		delete(want, a.rel)
		if e.IsDir {
			continue
		}
		if int64(len(e.Content)) != a.info.Size() {
			return verify.ErrDigestMismatch
		}
		// Charge comparison separately from the bounded active file read.
		if err := p.budget.charge(int64(len(e.Content))); err != nil {
			return err
		}
		raw, err := p.read(ctx, a, int64(len(e.Content)))
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, e.Content) {
			return verify.ErrDigestMismatch
		}
	}
	if len(want) != 0 {
		return verify.ErrDigestMismatch
	}
	return nil
}
