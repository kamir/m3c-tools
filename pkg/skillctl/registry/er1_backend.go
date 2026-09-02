package registry

// SPEC-0356 D2: ER1Backend adapts the ER1 carrier (the PublishAdmitted /
// ListRegistry / ShowSkill / searchByTagsRaw free functions) to the
// artifact.Backend interface, so ER1 is a first-class peer of the git/OCI
// backends and the SAME conformance suite (pkg/skillctl/artifact/conformance)
// drives it. It is a THIN adapter over the existing, tested free functions — no
// signing/verify logic moves here. Construct with NewER1Backend; the CLI still
// uses the free-function ER1 path directly (unchanged), so this adapter is used
// by conformance/tests and future unification, not the shipped ER1 command flow.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustcore"
)

// ER1Backend is the artifact.Backend view of one ER1 self-tenant context.
type ER1Backend struct {
	cfg   *er1.Config
	ctxID string
}

// NewER1Backend adapts an ER1 config + context id to artifact.Backend.
func NewER1Backend(cfg *er1.Config, ctxID string) *ER1Backend {
	return &ER1Backend{cfg: cfg, ctxID: ctxID}
}

var (
	_ artifact.Backend       = (*ER1Backend)(nil)
	_ artifact.GovernanceLog = (*ER1Backend)(nil)
)

func (b *ER1Backend) Describe() artifact.Descriptor {
	return artifact.Descriptor{
		Scheme:  "er1",
		Display: "ER1 self tenant (ctx=" + b.ctxID + ")",
		Capabilities: artifact.Capabilities{
			CanAdmit: true, CanAttest: true, CanRevoke: true, CanInstall: true,
			ServerEventLog: true,                      // via GovernanceLog.Events
			Paginated:      false,                     // single-shot list today (the known limit=500 fetch)
			HonoursSince:   true,                      // Events applies ListFilter.Since on occurred_at
			Governance:     artifact.GovFromEventLog,  // newest signed attestation
			LatestPolicy:   artifact.LatestMostRecent, // admit-time newest (NOT semver-max — a real ER1↔git difference)
			Rooms:          false,                     // TODO: expose er1_room.go via Roomer (rooms are an ER1-only feature)
			ClaimCheck:     false,                     // inline-only today; the MinIO ClaimCheckFn seam is not wired
		},
	}
}

func (b *ER1Backend) Close() error { return nil }

// strOrEmpty returns the first non-empty string among vals (each may be any).
func strOrEmpty(vals ...any) string {
	for _, v := range vals {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func (b *ER1Backend) skillMeta(m artifact.ArtifactMeta) SkillMeta {
	return SkillMeta{
		Name: m.Name, Version: m.Version, BundleDigest: m.Digest,
		AuthorIdentity: m.AuthorIdentity, GovernanceLevel: m.GovernanceLevel,
		PackedOnHost: m.PackedOnHost, ProjectID: m.ProjectID, ShareRooms: m.Rooms,
	}
}

func (b *ER1Backend) ref(m artifact.ArtifactMeta, nativeID string) artifact.ArtifactRef {
	return artifact.ArtifactRef{Name: m.Name, Version: m.Version, Digest: m.Digest, Locator: nativeID, Scheme: "er1"}
}

func (b *ER1Backend) Publish(ctx context.Context, req artifact.PublishRequest) (*artifact.PublishResult, error) {
	now := time.Now().UTC()
	skill := b.skillMeta(req.Meta)
	switch req.Kind {
	case artifact.KindAdmit:
		res, err := PublishAdmitted(PublishAdmittedOpts{
			ER1Cfg: b.cfg, ContextID: b.ctxID, Event: req.Event, Skill: skill,
			SkbBytes: req.Blob, InlineMaxBytes: req.InlineMaxBytes, Now: now,
		})
		if errors.Is(err, ErrAlreadyPublished) {
			nid := ""
			if res != nil {
				nid = res.DocID
			}
			return &artifact.PublishResult{Ref: b.ref(req.Meta, nid), NativeID: nid, Transport: "er1", AlreadyExists: true}, nil
		}
		if err != nil {
			return nil, err
		}
		return &artifact.PublishResult{Ref: b.ref(req.Meta, res.DocID), NativeID: res.DocID, Transport: res.Transport}, nil
	case artifact.KindAttest:
		docID, err := PublishAttested(PublishAttestedOpts{ER1Cfg: b.cfg, ContextID: b.ctxID, Event: req.Event, Skill: skill, Now: now})
		if err != nil {
			return nil, err
		}
		return &artifact.PublishResult{Ref: b.ref(req.Meta, docID), NativeID: docID, Transport: "er1"}, nil
	case artifact.KindRevoke:
		docID, err := PublishRevoked(PublishRevokedOpts{ER1Cfg: b.cfg, ContextID: b.ctxID, Event: req.Event, Skill: skill, Now: now})
		if err != nil {
			return nil, err
		}
		return &artifact.PublishResult{Ref: b.ref(req.Meta, docID), NativeID: docID, Transport: "er1"}, nil
	case artifact.KindInstall:
		docID, err := PublishInstalled(PublishInstalledOpts{ER1Cfg: b.cfg, ContextID: b.ctxID, Event: req.Event, Skill: skill, Now: now})
		if err != nil {
			return nil, err
		}
		return &artifact.PublishResult{Ref: b.ref(req.Meta, docID), NativeID: docID, Transport: "er1"}, nil
	default:
		return nil, fmt.Errorf("er1: unsupported event kind %q", req.Kind)
	}
}

func (b *ER1Backend) List(ctx context.Context, filter artifact.ListFilter, page artifact.Page) (*artifact.Listing, error) {
	rl, err := ListRegistry(b.cfg, b.ctxID, ListOpts{OnlySkill: filter.Name, OnlyLatest: filter.Latest})
	if err != nil {
		return nil, err
	}
	out := &artifact.Listing{}
	for _, s := range rl.Skills {
		out.Skills = append(out.Skills, artifact.SkillIndexEntry{
			Name: s.Name, LatestVersion: s.LatestVersion, LatestDigest: s.LatestDigest,
			LatestGovernance: s.LatestGovernance, IsRevoked: s.IsRevoked,
		})
	}
	return out, nil
}

func (b *ER1Backend) Resolve(ctx context.Context, q artifact.RefQuery) (*artifact.ArtifactRef, error) {
	key := q.Name
	if key == "" {
		key = q.Digest
	}
	if key == "" {
		return nil, fmt.Errorf("er1: resolve needs a name or digest")
	}
	sv, err := ShowSkill(b.cfg, b.ctxID, key)
	if err != nil {
		return nil, err
	}
	ver, dig := q.Version, q.Digest
	if ver == "" {
		ver = sv.LatestVersion
	}
	if dig == "" {
		dig = sv.LatestDigest
	}
	return &artifact.ArtifactRef{Name: sv.Name, Version: ver, Digest: dig, Scheme: "er1"}, nil
}

func (b *ER1Backend) Fetch(ctx context.Context, ref artifact.ArtifactRef) ([]byte, error) {
	digest := ref.Digest
	if digest == "" {
		r, err := b.Resolve(ctx, artifact.RefQuery{Name: ref.Name, Version: ref.Version})
		if err != nil {
			return nil, err
		}
		digest = r.Digest
	}
	items, err := searchByTagsRaw(b.cfg, b.ctxID, []string{
		"m3c-skill-bundle", "skill-registry:self", "skill-event:" + EventKindAdmitted, "skill-digest:" + digest,
	})
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		body := itemBody(item)
		ev, err := extractEvent(body)
		if err != nil {
			continue
		}
		if d, _ := ev["bundle_digest"].(string); d == digest {
			return extractSkbBytes(body)
		}
	}
	return nil, fmt.Errorf("er1: no admit item for digest %s", digest)
}

// Events implements artifact.GovernanceLog: the signed admit/attest/revoke event
// envelopes for the target skill(s), so the §7 verifier can re-verify them.
func (b *ER1Backend) Events(ctx context.Context, filter artifact.ListFilter, page artifact.Page) (*artifact.EventPage, error) {
	out := &artifact.EventPage{}
	for _, kind := range []string{EventKindAdmitted, EventKindAttested, EventKindRevoked} {
		tags := []string{"m3c-skill-bundle", "skill-registry:self", "skill-event:" + kind}
		if filter.Name != "" {
			tags = append(tags, "skill:"+filter.Name)
		}
		items, err := searchByTagsRaw(b.cfg, b.ctxID, tags)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			ev, err := extractEvent(itemBody(item))
			if err != nil {
				continue
			}
			// FR-0090 IS-T4 (parity with git/oci Events): Kind + Digest come from the
			// SIGNED envelope, never the skill-event:<kind> TAG (the `kind` loop var is
			// only the coarse search prefilter). A hostile ER1 item could otherwise
			// relabel a signed revoke as skill-event:installed to suppress it. Digest was
			// already envelope-sourced; classifying Kind here closes the tag projection.
			signedKind := trustcore.KindFromSignedEnvelope(ev)
			d := trustcore.SignedDigest(ev)
			if signedKind == "" || !trustcore.ValidDigest(d) {
				continue // unclassifiable / no well-formed anchor → never a verdict
			}
			lvl, _ := ev["governance_level"].(string)
			rec := artifact.EventRecord{
				Kind: signedKind, Digest: d, Governance: lvl,
				Host:      strOrEmpty(ev["packed_on_host"], ev["installed_on_host"]),
				Rationale: strOrEmpty(ev["rationale"]),
				Envelope:  ev,
			}
			if ts, _ := ev["occurred_at"].(string); ts != "" {
				if t, perr := time.Parse(time.RFC3339, ts); perr == nil {
					rec.OccurredAt = t
				}
			}
			// --since (ListFilter.Since): drop events older than the bound; a
			// zero/unparseable timestamp is kept (best-effort, never a gate).
			if !filter.Since.IsZero() && !rec.OccurredAt.IsZero() && rec.OccurredAt.Before(filter.Since) {
				continue
			}
			out.Events = append(out.Events, rec)
		}
	}
	return out, nil
}
