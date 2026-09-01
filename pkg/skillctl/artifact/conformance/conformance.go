// Package conformance is the backend-agnostic lifecycle suite every SPEC-0356
// artifact.Backend must pass (D8). The SAME assertions run against the git
// backend (bare repo), the ER1 backend, and the in-memory fake — so "does ER1
// implement the same feature set as GitLab" is answered by a test, not a claim.
//
// It uses a self-generated ed25519 key and REAL signed SPEC-0190 events, so it
// works for backends that validate the envelope (ER1) as well as those that only
// carry the bytes (git). Governance/verify semantics are tested separately (the
// §7 gauntlet); this suite tests the Backend CONTRACT: Publish (admit/revoke),
// List, Resolve, Fetch, idempotency, and — when implemented — GovernanceLog.Events.
package conformance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// Run drives the full lifecycle against a FRESH, EMPTY backend. Every backend
// implementation calls this from its own test with its own factory (a bare repo,
// an ER1 test context, or the fake).
func Run(t *testing.T, be artifact.Backend) {
	t.Helper()
	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	admit := func(name, ver string) (artifact.PublishRequest, string) {
		blob := []byte("SKB:" + name + "@" + ver)
		sum := sha256.Sum256(blob)
		digest := "sha256:" + hex.EncodeToString(sum[:])
		sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, sum[:]))
		fp := "sha256:" + hex.EncodeToString(sum[:16]) // any stable fingerprint
		ev, err := registry.BuildBundleAdmittedEvent(registry.AdmittedEventInput{
			BundleDigest:       digest,
			Name:               name,
			Version:            ver,
			AuthorIntent:       "green",
			AdmittedByIdentity: "id:conformance",
			AdmittedAt:         time.Unix(0, 0).UTC(),
			Signatures: []registry.SignatureRef{
				{Role: "author", IdentityID: "id:conformance", SignatureB64: sig, PubKeyFingerprint: fp},
				{Role: "registry", IdentityID: "id:conformance", SignatureB64: sig, PubKeyFingerprint: fp},
			},
		})
		if err != nil {
			t.Fatalf("build admit event: %v", err)
		}
		if _, err := registry.SignEnvelopeSignature(priv, ev); err != nil {
			t.Fatalf("sign envelope: %v", err)
		}
		return artifact.PublishRequest{
			Kind:  artifact.KindAdmit,
			Event: ev,
			Meta:  artifact.ArtifactMeta{Name: name, Version: ver, Digest: digest, GovernanceLevel: "green"},
			Blob:  blob,
		}, digest
	}

	// --- empty backend lists empty ---
	if lst, err := be.List(ctx, artifact.ListFilter{}, artifact.Page{}); err != nil {
		t.Fatalf("List(empty): %v", err)
	} else if len(lst.Skills) != 0 {
		t.Fatalf("fresh backend should be empty, got %d skills", len(lst.Skills))
	}

	// --- publish two pdf versions + one browse ---
	reqPdf1, digPdf1 := admit("pdf", "1.0.0")
	reqPdf2, digPdf2 := admit("pdf", "1.2.0")
	reqBrowse, _ := admit("browse", "0.1.0")
	for _, r := range []artifact.PublishRequest{reqPdf1, reqPdf2, reqBrowse} {
		if _, err := be.Publish(ctx, r); err != nil {
			t.Fatalf("Publish %s@%s: %v", r.Meta.Name, r.Meta.Version, err)
		}
	}

	// --- List: complete, sorted, correct semver-max latest ---
	lst, err := be.List(ctx, artifact.ListFilter{}, artifact.Page{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got := backendPaginated(be); got && lst.NextCursor != "" {
		// If the backend claims completeness, one page must hold everything.
		t.Errorf("Paginated backend returned a cursor on a 3-item registry: %q", lst.NextCursor)
	}
	pdf := findSkill(lst.Skills, "pdf")
	if pdf == nil {
		t.Fatalf("pdf not listed: %+v", lst.Skills)
	}
	if pdf.LatestVersion != "1.2.0" || pdf.LatestDigest != digPdf2 {
		t.Errorf("pdf latest = %s/%s, want 1.2.0/%s", pdf.LatestVersion, pdf.LatestDigest, digPdf2)
	}
	if findSkill(lst.Skills, "browse") == nil {
		t.Errorf("browse not listed")
	}

	// --- Resolve latest + Fetch round-trip ---
	ref, err := be.Resolve(ctx, artifact.RefQuery{Name: "pdf"})
	if err != nil {
		t.Fatalf("Resolve pdf: %v", err)
	}
	if ref.Version != "1.2.0" || ref.Digest != digPdf2 {
		t.Errorf("Resolve pdf = %s/%s", ref.Version, ref.Digest)
	}
	if blob, err := be.Fetch(ctx, *ref); err != nil {
		t.Fatalf("Fetch pdf latest: %v", err)
	} else if string(blob) != "SKB:pdf@1.2.0" {
		t.Errorf("Fetch pdf latest = %q", blob)
	}
	// Fetch an older version by digest.
	if blob, err := be.Fetch(ctx, artifact.ArtifactRef{Digest: digPdf1}); err != nil {
		t.Fatalf("Fetch by digest: %v", err)
	} else if string(blob) != "SKB:pdf@1.0.0" {
		t.Errorf("Fetch by digest = %q", blob)
	}

	// --- idempotency: re-admit is a no-op ---
	if res, err := be.Publish(ctx, reqPdf1); err != nil {
		t.Fatalf("re-Publish: %v", err)
	} else if !res.AlreadyExists {
		t.Error("re-admit should report AlreadyExists")
	}

	// --- revoke latest → visible as revoked, latest falls back ---
	revEv, _ := registry.BuildBundleRevokedEvent(registry.RevokedEventInput{
		BundleDigest: digPdf2, ReasonCode: "deprecated", RevokedBy: "id:conformance", OccurredAt: time.Unix(1, 0).UTC(),
	})
	if _, err := registry.SignEnvelopeSignature(priv, revEv); err != nil {
		t.Fatalf("SignEnvelopeSignature(revoke): %v", err)
	}
	if _, err := be.Publish(ctx, artifact.PublishRequest{
		Kind: artifact.KindRevoke, Event: revEv,
		Meta: artifact.ArtifactMeta{Name: "pdf", Version: "1.2.0", Digest: digPdf2},
	}); err != nil {
		t.Fatalf("Publish revoke: %v", err)
	}
	ref2, err := be.Resolve(ctx, artifact.RefQuery{Name: "pdf"})
	if err != nil {
		t.Fatalf("Resolve after revoke: %v", err)
	}
	// Revoke VISIBILITY is a universal contract (checked via Events below); the
	// LATEST-after-revoke depends on the backend's declared LatestPolicy — a
	// semver-max backend falls back to 1.0.0, whereas a most-recent-admit backend
	// may still report 1.2.0 as latest (but must still surface it as revoked).
	if be.Describe().Capabilities.LatestPolicy == artifact.LatestSemverMax && ref2.Version != "1.0.0" {
		t.Errorf("semver-max backend: latest non-revoked = %q, want 1.0.0", ref2.Version)
	}

	// --- GovernanceLog (optional): Events surfaces the signed envelopes ---
	if gl, ok := be.(artifact.GovernanceLog); ok {
		ep, err := gl.Events(ctx, artifact.ListFilter{Name: "pdf"}, artifact.Page{})
		if err != nil {
			t.Fatalf("Events(pdf): %v", err)
		}
		var admits, revokes int
		for _, r := range ep.Events {
			if r.Envelope == nil {
				t.Errorf("event %s has nil Envelope", r.NativeID)
			}
			switch r.Kind {
			case artifact.KindAdmit:
				admits++
			case artifact.KindRevoke:
				revokes++
			}
		}
		if admits < 2 || revokes < 1 {
			t.Errorf("Events(pdf) = %d admit, %d revoke; want >=2 admit, >=1 revoke", admits, revokes)
		}
	} else if be.Describe().Capabilities.ServerEventLog {
		t.Error("Describe().Capabilities.ServerEventLog is true but backend does not implement GovernanceLog")
	}
}

func backendPaginated(be artifact.Backend) bool { return be.Describe().Capabilities.Paginated }

func findSkill(skills []artifact.SkillIndexEntry, name string) *artifact.SkillIndexEntry {
	for i := range skills {
		if skills[i].Name == name {
			return &skills[i]
		}
	}
	return nil
}
