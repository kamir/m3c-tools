// Package oci implements a SPEC-0356 D7 artifact.Backend over an OCI registry
// (or a local OCI image-layout), using oras.land/oras-go/v2 (pure-Go, CGO-free →
// distroless-safe). It carries the SAME .skb bytes and the SAME signed SPEC-0190
// events as every other backend.
//
// Wire mapping (the elegant part): the .skb is pushed as ONE blob whose OCI
// descriptor digest EQUALS our sha256:<hex>. Our identity IS the layer digest,
// so Fetch by digest is native. The skill is an artifact manifest (artifactType
// application/vnd.m3c.skill.bundle.v1+gzip) with that blob as its single layer,
// tagged <name>:<version> (name+version also in annotations, advisory). Each
// signed lifecycle event (admit/attest/revoke/install) is a REFERRER. An artifact
// manifest whose `subject` is the skill manifest and whose layer is the event JSON.
// Events() lists referrers; the §7 verifier re-verifies them. cosign is NOT used
// here: it signs the OCI manifest digest (registry-native admission, optional,
// out-of-band); our Ed25519 chain signs the .skb digest and stays the sole trust
// root (SPEC-0356 §7).
package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	"github.com/kamir/m3c-tools/pkg/skillctl/semver"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustcore"
)

const (
	// BundleArtifactType marks the skill-bundle manifest (matches scripts/publish-skb.sh).
	BundleArtifactType = "application/vnd.m3c.skill.bundle.v1+gzip"
	// EventArtifactType marks a signed lifecycle-event referrer.
	EventArtifactType = "application/vnd.m3c.skill.event.v1+json"

	annName    = "land.m3c.skill.name"
	annVersion = "land.m3c.skill.version"
	annDigest  = "land.m3c.skill.digest" // the .skb digest (== the layer digest)
	annGov     = "land.m3c.skill.governance"
	annKind    = "land.m3c.skill.event.kind" // admitted|attested|revoked|installed
)

func init() { artifact.Register("oci", openOCI) }

// ociTarget is the subset of oras-go a store or a remote repository provides.
// Both content/oci.Store and remote.Repository satisfy it.
type ociTarget interface {
	oras.Target // Push + Fetch + Exists + Resolve + Tag
	Tags(ctx context.Context, last string, fn func(tags []string) error) error
	Predecessors(ctx context.Context, node ocispec.Descriptor) ([]ocispec.Descriptor, error)
}

type ociBackend struct {
	target  ociTarget
	display string // e.g. "oci://ghcr.io/kamir/skills"
	scheme  string
	// CD-13 write-mode swap: when target is a live remote.Repository, authRepo
	// points at it and creds/credHost let Publish re-resolve the WRITE credential
	// (the shared oras client is baked read-only at Open). All nil/zero for a local
	// oci.Store (no network, no credential). Publish's swap is then a no-op.
	authRepo *remote.Repository
	creds    artifact.CredentialSource
	credHost string
}

func newOCIBackend(target ociTarget, display string) *ociBackend {
	b := &ociBackend{target: target, display: display, scheme: "oci"}
	if r, ok := target.(*remote.Repository); ok {
		b.authRepo = r
	}
	return b
}

var (
	_ artifact.Backend       = (*ociBackend)(nil)
	_ artifact.GovernanceLog = (*ociBackend)(nil)
)

func (b *ociBackend) Describe() artifact.Descriptor {
	return artifact.Descriptor{
		Scheme:  "oci",
		Display: b.display,
		Capabilities: artifact.Capabilities{
			CanAdmit: true, CanAttest: true, CanRevoke: true, CanInstall: true,
			ServerEventLog: true,                     // via referrers (GovernanceLog.Events)
			Paginated:      false,                    // single-shot complete tag listing
			HonoursSince:   true,                     // Events applies ListFilter.Since on occurred_at
			Governance:     artifact.GovFromEventLog, // newest signed attestation
			LatestPolicy:   artifact.LatestSemverMax, // highest semver among non-revoked
			ClaimCheck:     false,                    // the .skb IS the OCI layer blob (no out-of-line store)
		},
	}
}

func (b *ociBackend) Close() error { return nil }

// tagFor is the reference a skill version is tagged under in the layout. OCI tags
// forbid ':' and '@'; a readable sanitized prefix keeps the tag greppable while a
// 12-hex suffix over (name,version) makes it INJECTIVE. SanitizeTag is lossy and
// '_' is legal in both fields, so "a_b"+"1.0" and "a"+"b_1.0" would otherwise
// collide onto one tag. List/Resolve read the AUTHORITATIVE name+version from the
// manifest annotations, never by parsing the tag.
func tagFor(name, version string) string {
	return sanitizeTag(name+"_"+version) + "-" + tagHash(name, version)
}

func sanitizeTag(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := b.String()
	if out == "" {
		out = "x"
	}
	return out
}

// --- Publish ---

func (b *ociBackend) Publish(ctx context.Context, req artifact.PublishRequest) (*artifact.PublishResult, error) {
	// CD-13: Publish is the only write op. Swap the shared oras client from its
	// read-only default (baked at Open) to the WRITE credential. No-op for a local
	// oci.Store (authRepo nil) and for a single-token operator (ModeWrite resolves
	// the same token). Re-runs the plain-HTTP egress guard for the write token.
	if b.authRepo != nil && b.creds != nil {
		if err := applyOCIAuth(b.authRepo, b.creds, b.credHost, artifact.ModeWrite); err != nil {
			return nil, err
		}
	}
	name, ver, dig := req.Meta.Name, req.Meta.Version, req.Meta.Digest
	if err := validateName(name); err != nil {
		return nil, err
	}
	if err := validateVersion(ver); err != nil {
		return nil, err
	}
	if err := validateDigest(dig); err != nil {
		return nil, err
	}
	evBytes, err := json.MarshalIndent(req.Event, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("oci: marshal event: %w", err)
	}

	if req.Kind == artifact.KindAdmit {
		if len(req.Blob) == 0 {
			return nil, fmt.Errorf("oci: %s requires the .skb blob", req.Kind)
		}
		// Idempotent on the tag, but ONLY a genuine re-publish of the same content is
		// a no-op. A registry that pre-plants the tag pointing at different content
		// must NOT make a legitimate publish silently succeed-without-pushing (which
		// would drop the real .skb + admit referrer). Verify the resolved manifest's
		// signed-mirror annotations match (name, version, digest) before short-circuiting.
		if existing, rerr := b.target.Resolve(ctx, tagFor(name, ver)); rerr == nil {
			man, merr := b.fetchManifest(ctx, existing)
			if merr == nil && man.Annotations[annName] == name && man.Annotations[annVersion] == ver && man.Annotations[annDigest] == dig {
				return &artifact.PublishResult{Ref: b.ref(name, ver, dig), NativeID: tagFor(name, ver), Transport: "oci", AlreadyExists: true}, nil
			}
			return nil, fmt.Errorf("oci: tag %s already occupied by different content (name/version/digest mismatch), refusing to overwrite", tagFor(name, ver))
		}
		// Push the .skb blob, its descriptor digest is our sha256:<hex>.
		skbDesc, err := oras.PushBytes(ctx, b.target, BundleArtifactType, req.Blob)
		if err != nil {
			return nil, fmt.Errorf("oci: push .skb: %w", err)
		}
		if skbDesc.Digest.String() != dig {
			return nil, fmt.Errorf("oci: pushed blob digest %s != declared %s", skbDesc.Digest, dig)
		}
		manDesc, err := oras.PackManifest(ctx, b.target, oras.PackManifestVersion1_1, BundleArtifactType, oras.PackManifestOptions{
			Layers: []ocispec.Descriptor{skbDesc},
			ManifestAnnotations: map[string]string{
				annName: name, annVersion: ver, annDigest: dig, annGov: req.Meta.GovernanceLevel,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("oci: pack skill manifest: %w", err)
		}
		if err := b.target.Tag(ctx, manDesc, tagFor(name, ver)); err != nil {
			return nil, fmt.Errorf("oci: tag %s: %w", tagFor(name, ver), err)
		}
		if err := b.pushEventReferrer(ctx, manDesc, string(artifact.KindAdmit), dig, evBytes); err != nil {
			return nil, err
		}
		return &artifact.PublishResult{Ref: b.ref(name, ver, dig), NativeID: tagFor(name, ver), Transport: "oci"}, nil
	}

	// attest / revoke / install: attach a signed-event referrer to the EXISTING skill
	// manifest for this digest (append-only; no manifest mutation). An OCI event is a
	// REFERRER, so it needs a subject manifest: recording a governance event for a
	// digest never admitted on THIS target is refused here. Cross-target install-event
	// recording (federation "install from A, record on B") is a tracked follow-up.
	manDesc, ok, err := b.manifestForDigest(ctx, dig)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("oci: no admitted skill for digest %s to %s", dig, req.Kind)
	}
	if err := b.pushEventReferrer(ctx, manDesc, string(req.Kind), dig, evBytes); err != nil {
		return nil, err
	}
	return &artifact.PublishResult{Ref: b.ref(name, ver, dig), NativeID: string(req.Kind) + "@" + dig, Transport: "oci"}, nil
}

// pushEventReferrer packs one signed event as an artifact manifest whose subject
// is the skill manifest and whose single layer is the event JSON.
func (b *ociBackend) pushEventReferrer(ctx context.Context, subject ocispec.Descriptor, kind, dig string, evBytes []byte) error {
	layer, err := oras.PushBytes(ctx, b.target, EventArtifactType, evBytes)
	if err != nil {
		return fmt.Errorf("oci: push event blob: %w", err)
	}
	subj := subject
	if _, err := oras.PackManifest(ctx, b.target, oras.PackManifestVersion1_1, EventArtifactType, oras.PackManifestOptions{
		Subject:             &subj,
		Layers:              []ocispec.Descriptor{layer},
		ManifestAnnotations: map[string]string{annKind: kind, annDigest: dig},
	}); err != nil {
		return fmt.Errorf("oci: pack %s referrer: %w", kind, err)
	}
	return nil
}

func (b *ociBackend) ref(name, ver, dig string) artifact.ArtifactRef {
	return artifact.ArtifactRef{Name: name, Version: ver, Digest: dig, Locator: tagFor(name, ver), Scheme: b.scheme}
}

// --- read helpers ---

// eachSkillManifest calls fn for every skill (bundle) manifest in the target,
// with its resolved descriptor + annotations.
func (b *ociBackend) eachSkillManifest(ctx context.Context, fn func(desc ocispec.Descriptor, ann map[string]string) error) error {
	var tags []string
	// Cap enumeration: an untrusted registry must not be able to OOM/hang the host
	// by returning an unbounded tag set.
	if err := b.target.Tags(ctx, "", func(t []string) error {
		if len(tags) >= maxTags {
			return nil
		}
		tags = append(tags, t...)
		return nil
	}); err != nil {
		return fmt.Errorf("oci: list tags: %w", err)
	}
	if len(tags) > maxTags {
		tags = tags[:maxTags]
	}
	for _, tag := range tags {
		desc, err := b.target.Resolve(ctx, tag)
		if err != nil {
			continue
		}
		man, err := b.fetchManifest(ctx, desc)
		if err != nil || man.ArtifactType != BundleArtifactType {
			continue
		}
		if err := fn(desc, man.Annotations); err != nil {
			return err
		}
	}
	return nil
}

func (b *ociBackend) fetchManifest(ctx context.Context, desc ocispec.Descriptor) (ocispec.Manifest, error) {
	var man ocispec.Manifest
	data, err := b.fetchCapped(ctx, desc, maxManifestBytes)
	if err != nil {
		return man, err
	}
	err = json.Unmarshal(data, &man)
	return man, err
}

// fetchCapped reads a descriptor's content with TWO bounds against the untrusted
// registry: (1) reject a descriptor whose DECLARED size exceeds max before reading
// a byte (content.FetchAll otherwise honours an attacker-declared 100 GiB size);
// (2) content.FetchAll then verifies the bytes against the descriptor digest + size.
func (b *ociBackend) fetchCapped(ctx context.Context, desc ocispec.Descriptor, max int64) ([]byte, error) {
	if desc.Size > max {
		return nil, fmt.Errorf("oci: descriptor size %d exceeds cap %d", desc.Size, max)
	}
	return content.FetchAll(ctx, b.target, desc)
}

// manifestForDigest finds the skill manifest whose annotated .skb digest matches.
func (b *ociBackend) manifestForDigest(ctx context.Context, dig string) (ocispec.Descriptor, bool, error) {
	var found ocispec.Descriptor
	ok := false
	err := b.eachSkillManifest(ctx, func(desc ocispec.Descriptor, ann map[string]string) error {
		if ann[annDigest] == dig {
			found, ok = desc, true
		}
		return nil
	})
	return found, ok, err
}

// --- List ---

func (b *ociBackend) List(ctx context.Context, filter artifact.ListFilter, page artifact.Page) (*artifact.Listing, error) {
	rows := map[string][]artifact.VersionRow{}
	revoked := map[string]bool{} // digest -> revoked
	// First pass: gather versions.
	if err := b.eachSkillManifest(ctx, func(desc ocispec.Descriptor, ann map[string]string) error {
		name := ann[annName]
		if filter.Name != "" && filter.Name != name {
			return nil
		}
		rows[name] = append(rows[name], artifact.VersionRow{
			Version: ann[annVersion], Digest: ann[annDigest], Governance: ann[annGov], Status: "admitted",
		})
		if b.digestRevoked(ctx, desc) {
			revoked[ann[annDigest]] = true
		}
		return nil
	}); err != nil {
		return nil, err
	}
	var skills []artifact.SkillIndexEntry
	for name, vrows := range rows {
		for i := range vrows {
			if revoked[vrows[i].Digest] {
				vrows[i].Status = "revoked"
			}
		}
		var nonRevoked []string
		for _, r := range vrows {
			if r.Status != "revoked" {
				nonRevoked = append(nonRevoked, r.Version)
			}
		}
		latest := semver.Max(nonRevoked)
		if latest == "" {
			latest = semver.Max(versionStrings(vrows))
		}
		entry := artifact.SkillIndexEntry{Name: name, IsRevoked: len(nonRevoked) == 0, Versions: vrows}
		if r, ok := rowFor(vrows, latest); ok {
			entry.LatestVersion, entry.LatestDigest, entry.LatestGovernance = r.Version, r.Digest, r.Governance
		}
		if filter.Latest {
			if r, ok := rowFor(vrows, latest); ok {
				entry.Versions = []artifact.VersionRow{r}
			}
		}
		skills = append(skills, entry)
	}
	sort.Slice(skills, func(i, j int) bool { return skills[i].Name < skills[j].Name })
	return &artifact.Listing{Skills: skills}, nil // complete; no cursor
}

// digestRevoked feeds only the DISPLAY status column of List/Resolve. It reads the
// advisory annKind, which an untrusted registry controls. This is intentionally NOT
// a trust gate: the authoritative revocation check is the pull gauntlet's signed-
// envelope path (Events → OfferRevoke on the signed `revoked_by`). A registry that
// lies here only mis-paints a column; it cannot make a revoked bundle install.
func (b *ociBackend) digestRevoked(ctx context.Context, manDesc ocispec.Descriptor) bool {
	refs, err := registry.Referrers(ctx, b.target, manDesc, EventArtifactType)
	if err != nil {
		return false
	}
	if len(refs) > maxReferrers {
		refs = refs[:maxReferrers]
	}
	for _, r := range refs {
		if r.Annotations[annKind] == string(artifact.KindRevoke) {
			return true
		}
	}
	return false
}

// --- Resolve ---

func (b *ociBackend) Resolve(ctx context.Context, q artifact.RefQuery) (*artifact.ArtifactRef, error) {
	if q.Digest != "" && q.Name == "" {
		if err := validateDigest(q.Digest); err != nil {
			return nil, err
		}
		desc, ok, err := b.manifestForDigest(ctx, q.Digest)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("oci: no artifact for digest %s", q.Digest)
		}
		// Populate the full ref from the manifest annotations (parity with git).
		man, _ := b.fetchManifest(ctx, desc)
		n, v := man.Annotations[annName], man.Annotations[annVersion]
		return &artifact.ArtifactRef{Name: n, Version: v, Digest: q.Digest, Locator: tagFor(n, v), Scheme: b.scheme}, nil
	}
	lst, err := b.List(ctx, artifact.ListFilter{Name: q.Name}, artifact.Page{})
	if err != nil {
		return nil, err
	}
	if len(lst.Skills) == 0 {
		return nil, fmt.Errorf("oci: skill %q not found", q.Name)
	}
	s := lst.Skills[0]
	if q.Version == "" {
		// A fully-revoked skill has no installable latest: error rather than hand
		// back a revoked bundle as "latest" (parity with the git backend; the pull
		// gauntlet would refuse it anyway, this keeps resolve/install consistent).
		if s.IsRevoked {
			return nil, fmt.Errorf("oci: no non-revoked version for %q", s.Name)
		}
		return &artifact.ArtifactRef{Name: s.Name, Version: s.LatestVersion, Digest: s.LatestDigest, Locator: tagFor(s.Name, s.LatestVersion), Scheme: b.scheme}, nil
	}
	if r, ok := rowFor(s.Versions, q.Version); ok {
		return &artifact.ArtifactRef{Name: s.Name, Version: r.Version, Digest: r.Digest, Locator: tagFor(s.Name, r.Version), Scheme: b.scheme}, nil
	}
	return nil, fmt.Errorf("oci: %s@%s not found", q.Name, q.Version)
}

// --- Fetch ---

func (b *ociBackend) Fetch(ctx context.Context, ref artifact.ArtifactRef) ([]byte, error) {
	dig := ref.Digest
	if dig == "" {
		r, err := b.Resolve(ctx, artifact.RefQuery{Name: ref.Name, Version: ref.Version})
		if err != nil {
			return nil, err
		}
		dig = r.Digest
	}
	if err := validateDigest(dig); err != nil {
		return nil, err
	}
	manDesc, ok, err := b.manifestForDigest(ctx, dig)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("oci: no artifact for digest %s", dig)
	}
	man, err := b.fetchManifest(ctx, manDesc)
	if err != nil {
		return nil, err
	}
	for _, layer := range man.Layers {
		if layer.Digest.String() == dig {
			// fetchCapped rejects an over-cap declared size, then re-verifies the blob
			// against `dig` (the layer descriptor's digest) + size before returning:
			// the pull gauntlet recomputes sha256 again, but a lying registry is caught here too.
			return b.fetchCapped(ctx, layer, maxBlobBytes)
		}
	}
	return nil, fmt.Errorf("oci: manifest for %s has no matching .skb layer", dig)
}

// --- GovernanceLog: signed event referrers ---

func (b *ociBackend) Events(ctx context.Context, filter artifact.ListFilter, page artifact.Page) (*artifact.EventPage, error) {
	out := &artifact.EventPage{}
	err := b.eachSkillManifest(ctx, func(desc ocispec.Descriptor, ann map[string]string) error {
		if filter.Name != "" && filter.Name != ann[annName] {
			return nil
		}
		refs, err := registry.Referrers(ctx, b.target, desc, EventArtifactType)
		if err != nil {
			return nil // a registry that fails to list referrers for one manifest must
			// not nuke the whole event page (parity with the git backend's per-dir continue)
		}
		if len(refs) > maxReferrers {
			refs = refs[:maxReferrers]
		}
		for _, r := range refs {
			man, err := b.fetchManifest(ctx, r)
			if err != nil || len(man.Layers) == 0 {
				continue
			}
			data, err := b.fetchCapped(ctx, man.Layers[0], maxManifestBytes)
			if err != nil {
				continue
			}
			var env map[string]any
			if json.Unmarshal(data, &env) != nil {
				continue // malformed → untrusted, never influences a verdict
			}
			// SECURITY (challenge-gate HIGH): Kind and Digest MUST come from the SIGNED
			// envelope, never from the registry-controlled annotation. The gauntlet
			// routes lifecycle state on rec.Kind and the gossip path keys the revoked
			// set on rec.Digest. Sourcing either from annKind/annDigest would let a
			// malicious registry relabel a signed revoke ("revoked"→"installed") to
			// SUPPRESS it, or rebind its digest to revoke an innocent skill. The
			// annotation is advisory display only. See reference_git_event_signed_identity.
			kind := trustcore.KindFromSignedEnvelope(env)
			signedDigest := trustcore.SignedDigest(env)
			if kind == "" || !trustcore.ValidDigest(signedDigest) {
				continue // unclassifiable / no well-formed signed anchor → never a verdict (parity with git/er1)
			}
			rec := artifact.EventRecord{
				Kind:       kind,
				Digest:     signedDigest,
				Governance: strFromMap(env, "governance_level"),
				Host:       strOr(strFromMap(env, "packed_on_host"), strFromMap(env, "installed_on_host")),
				Rationale:  strFromMap(env, "rationale"),
				Envelope:   env,
			}
			if ts := strFromMap(env, "occurred_at"); ts != "" {
				if t, perr := parseRFC3339(ts); perr == nil {
					rec.OccurredAt = t
					// --since (best-effort scope narrowing; never a trust gate).
					if !filter.Since.IsZero() && t.Before(filter.Since) {
						continue
					}
				}
			}
			out.Events = append(out.Events, rec)
		}
		return nil
	})
	return out, err
}
