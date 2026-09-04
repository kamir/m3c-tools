package oci

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	orasoci "oras.land/oras-go/v2/content/oci"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	"github.com/kamir/m3c-tools/pkg/skillctl/artifact/conformance"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustcore"
)

// ociStore builds an offline OCI layout in t.TempDir(): a real content store
// (oci.Store implements the same push/tag/referrer protocol as a live registry),
// so the whole suite runs with no network and no `docker`/registry:2.
func ociStore(t *testing.T) *orasoci.Store {
	t.Helper()
	s, err := orasoci.New(t.TempDir())
	if err != nil {
		t.Fatalf("oci.New: %v", err)
	}
	return s
}

// skbDig is the REAL sha256 of the deterministic test blob, because the OCI
// backend stores the .skb as a blob whose descriptor digest IS our identity, a
// test must advertise the digest the bytes actually hash to (production invariant:
// Meta.Digest == ComputeBundleDigest(Blob)).
func skbDig(name, ver string) string {
	sum := sha256.Sum256([]byte("SKB:" + name + "@" + ver))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func admitEvent(name, ver, dig string) artifact.PublishRequest {
	return artifact.PublishRequest{
		Kind: artifact.KindAdmit,
		Event: map[string]any{
			// The SIGNED discriminator (admitted_by_identity) is what Events() reads to
			// classify the kind, never the OCI annotation. bundle_digest is the anchor.
			"kind": "admitted", "name": name, "version": ver, "bundle_digest": dig,
			"admitted_by_identity": "id:test", "author_intent": "green",
			"schema_version": "1.0.0",
		},
		Meta: artifact.ArtifactMeta{Name: name, Version: ver, Digest: dig, GovernanceLevel: "green"},
		Blob: []byte("SKB:" + name + "@" + ver),
	}
}

// dig makes a well-formed but content-UNRELATED digest, for negative tests
// (validation, digest-mismatch) where the blob deliberately does not match.
func dig(seed byte) string { return "sha256:" + strings.Repeat(string(rune('a'+seed)), 64) }

// TestOCIBackendConformance runs the shared SPEC-0356 D8 conformance suite against
// the OCI backend: the SAME assertions that gate ER1 and git. Enterprise/container
// parity is proven here, offline.
func TestOCIBackendConformance(t *testing.T) {
	conformance.Run(t, newOCIBackend(ociStore(t), "oci://test.local/skills"))
}

func TestOCIBackendLifecycle(t *testing.T) {
	ctx := context.Background()
	b := newOCIBackend(ociStore(t), "oci://test.local/skills")
	defer b.Close()

	digPdf1, digPdf2, digBrowse := skbDig("pdf", "1.0.0"), skbDig("pdf", "1.2.0"), skbDig("browse", "0.1.0")
	for _, r := range []artifact.PublishRequest{
		admitEvent("pdf", "1.0.0", digPdf1),
		admitEvent("pdf", "1.2.0", digPdf2),
		admitEvent("browse", "0.1.0", digBrowse),
	} {
		if _, err := b.Publish(ctx, r); err != nil {
			t.Fatalf("Publish %s@%s: %v", r.Meta.Name, r.Meta.Version, err)
		}
	}

	lst, err := b.List(ctx, artifact.ListFilter{}, artifact.Page{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if lst.NextCursor != "" {
		t.Errorf("OCI listings are complete; NextCursor = %q, want empty", lst.NextCursor)
	}
	if len(lst.Skills) != 2 || lst.Skills[0].Name != "browse" || lst.Skills[1].Name != "pdf" {
		t.Fatalf("List = %+v, want sorted [browse, pdf]", lst.Skills)
	}
	pdf := lst.Skills[1]
	if pdf.LatestVersion != "1.2.0" || pdf.LatestDigest != digPdf2 {
		t.Errorf("pdf latest = %s/%s, want 1.2.0/%s (semver-max)", pdf.LatestVersion, pdf.LatestDigest, digPdf2)
	}

	// Resolve latest → newest semver.
	ref, err := b.Resolve(ctx, artifact.RefQuery{Name: "pdf"})
	if err != nil || ref.Version != "1.2.0" || ref.Digest != digPdf2 {
		t.Fatalf("Resolve pdf = %+v / %v, want 1.2.0/%s", ref, err, digPdf2)
	}

	// Fetch by ref: the descriptor digest IS our sha256, so O(1) content-address.
	blob, err := b.Fetch(ctx, *ref)
	if err != nil || string(blob) != "SKB:pdf@1.2.0" {
		t.Fatalf("Fetch = %q / %v", blob, err)
	}
	// Fetch an OLDER version by digest only.
	blob1, err := b.Fetch(ctx, artifact.ArtifactRef{Digest: digPdf1})
	if err != nil || string(blob1) != "SKB:pdf@1.0.0" {
		t.Fatalf("Fetch by digest = %q / %v", blob1, err)
	}

	// Idempotency: re-admit is a no-op.
	res, err := b.Publish(ctx, admitEvent("pdf", "1.0.0", digPdf1))
	if err != nil {
		t.Fatalf("re-Publish: %v", err)
	}
	if !res.AlreadyExists {
		t.Error("re-admit should report AlreadyExists")
	}

	// Revoke latest → latest falls back to the non-revoked version.
	if _, err := b.Publish(ctx, artifact.PublishRequest{
		Kind:  artifact.KindRevoke,
		Event: map[string]any{"kind": "revoked", "bundle_digest": digPdf2},
		Meta:  artifact.ArtifactMeta{Name: "pdf", Version: "1.2.0", Digest: digPdf2},
	}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	ref2, err := b.Resolve(ctx, artifact.RefQuery{Name: "pdf"})
	if err != nil || ref2.Version != "1.0.0" {
		t.Errorf("after revoking 1.2.0, latest = %+v, want 1.0.0", ref2)
	}
}

// TestOCIEventsAsReferrers proves the governance log is reconstructed from OCI
// referrers (subject = skill manifest) and honours the --since filter.
func TestOCIEventsAsReferrers(t *testing.T) {
	ctx := context.Background()
	var be artifact.Backend = newOCIBackend(ociStore(t), "oci://test.local/skills")
	defer be.Close()

	d := skbDig("pdf", "1.0.0")
	if _, err := be.Publish(ctx, admitEvent("pdf", "1.0.0", d)); err != nil {
		t.Fatalf("admit: %v", err)
	}
	if _, err := be.Publish(ctx, artifact.PublishRequest{
		Kind:  artifact.KindAttest,
		Event: map[string]any{"kind": "attested", "bundle_digest": d, "reviewer_id": "id:rev", "governance_level": "green"},
		Meta:  artifact.ArtifactMeta{Name: "pdf", Version: "1.0.0", Digest: d, GovernanceLevel: "green"},
	}); err != nil {
		t.Fatalf("attest: %v", err)
	}

	gl, ok := be.(artifact.GovernanceLog)
	if !ok {
		t.Fatal("OCI backend must implement GovernanceLog (events-as-referrers)")
	}
	ev, err := gl.Events(ctx, artifact.ListFilter{Name: "pdf"}, artifact.Page{})
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	kinds := map[string]bool{}
	for _, e := range ev.Events {
		kinds[string(e.Kind)] = true
	}
	if !kinds["admitted"] || !kinds["attested"] {
		t.Errorf("events = %+v, want both admitted + attested referrers", ev.Events)
	}
}

// TestOCIValidationRejectsMalice: name/version/digest become tags + annotations,
// so a hostile value must be refused before any push (SEC-M9).
func TestOCIValidationRejectsMalice(t *testing.T) {
	ctx := context.Background()
	b := newOCIBackend(ociStore(t), "oci://test.local/skills")
	defer b.Close()
	good := dig(3)
	for _, bad := range []artifact.ArtifactMeta{
		{Name: "../../etc/pwn", Version: "1.0.0", Digest: good},
		{Name: "ok", Version: "../../x", Digest: good},
		{Name: "-danger", Version: "1.0.0", Digest: good},
		{Name: "a b", Version: "1.0.0", Digest: good},
		{Name: "ok", Version: "1.0.0", Digest: "not-a-digest"},
	} {
		if _, err := b.Publish(ctx, artifact.PublishRequest{
			Kind: artifact.KindAdmit, Blob: []byte("x"),
			Event: map[string]any{"kind": "admitted"}, Meta: bad,
		}); err == nil {
			t.Errorf("Publish accepted malicious meta %+v", bad)
		}
	}
}

// TestOCIDigestMismatchRejected: the .skb pushed as an OCI blob must hash to the
// digest we advertise; a lying Meta.Digest is caught before the manifest is tagged.
func TestOCIDigestMismatchRejected(t *testing.T) {
	ctx := context.Background()
	b := newOCIBackend(ociStore(t), "oci://test.local/skills")
	defer b.Close()
	// Blob "SKB:x@1" does NOT hash to dig(5); Publish must refuse.
	if _, err := b.Publish(ctx, artifact.PublishRequest{
		Kind:  artifact.KindAdmit,
		Blob:  []byte("SKB:x@1"),
		Event: map[string]any{"kind": "admitted"},
		Meta:  artifact.ArtifactMeta{Name: "x", Version: "1.0.0", Digest: dig(5)},
	}); err == nil {
		t.Fatal("Publish accepted a blob whose sha256 != Meta.Digest")
	}
}

func TestOpenOCISchemeMapping(t *testing.T) {
	b, err := openOCI("oci://ghcr.io/kamir/skills", artifact.OpenOptions{})
	if err != nil {
		t.Fatalf("openOCI: %v", err)
	}
	defer b.Close()
	if got := b.Describe().Scheme; got != "oci" {
		t.Errorf("scheme = %q, want oci", got)
	}
	if _, err := openOCI("oci://", artifact.OpenOptions{}); err == nil {
		t.Error("empty oci spec must be rejected")
	}
}

// TestOCIKindFromSignedEnvelope pins the classifier: kind comes from the signed
// discriminator field, and the function never even sees an annotation. The OCI
// backend now derives this from the shared trustcore helper (FR-0090 IS-T0).
func TestOCIKindFromSignedEnvelope(t *testing.T) {
	cases := []struct {
		env  map[string]any
		want artifact.EventKind
	}{
		{map[string]any{"revoked_by": "id:r", "bundle_digest": "x"}, artifact.KindRevoke},
		{map[string]any{"reviewer_id": "id:v", "governance_level": "green"}, artifact.KindAttest},
		{map[string]any{"installed_on_host": "h1"}, artifact.KindInstall},
		{map[string]any{"admitted_by_identity": "id:a", "signatures": []any{}}, artifact.KindAdmit},
		{map[string]any{"bundle_digest": "x"}, ""}, // no discriminator → unclassifiable
		{map[string]any{"revoked_by": ""}, ""},     // empty discriminator → not present
	}
	for _, c := range cases {
		if got := trustcore.KindFromSignedEnvelope(c.env); got != c.want {
			t.Errorf("trustcore.KindFromSignedEnvelope(%v) = %q, want %q", c.env, got, c.want)
		}
	}
}

// TestOCIAnnotationRelabelDefeated is the flagship challenge-gate regression: a
// malicious registry serves a GENUINELY-signed revoke for digest X but relabels the
// referrer's annotation kind→"installed" (to SUPPRESS the revoke) and digest→Y (to
// REDIRECT it onto an innocent skill). Events() must ignore BOTH annotations and
// classify from the signed envelope: kind=revoked, digest=X. If this regresses, a
// revoked/key-compromised skill would install.
func TestOCIAnnotationRelabelDefeated(t *testing.T) {
	ctx := context.Background()
	b := newOCIBackend(ociStore(t), "oci://test.local/skills")
	defer b.Close()

	dX := skbDig("pdf", "1.0.0")
	dY := skbDig("innocent", "9.9.9")
	if _, err := b.Publish(ctx, admitEvent("pdf", "1.0.0", dX)); err != nil {
		t.Fatalf("admit: %v", err)
	}
	subj, ok, err := b.manifestForDigest(ctx, dX)
	if err != nil || !ok {
		t.Fatalf("subject manifest: ok=%v err=%v", ok, err)
	}
	// A real, well-formed revoke envelope for X.
	revEnv := map[string]any{
		"kind": "revoked", "bundle_digest": dX, "revoked_by": "id:rev",
		"reason_code": "key-compromise", "schema_version": "1.0.0",
	}
	evBytes, _ := json.MarshalIndent(revEnv, "", "  ")
	// The LIE: annKind="installed" (suppress) + annDigest=Y (redirect).
	if err := b.pushEventReferrer(ctx, subj, "installed", dY, evBytes); err != nil {
		t.Fatalf("push lying referrer: %v", err)
	}

	ep, err := b.Events(ctx, artifact.ListFilter{Name: "pdf"}, artifact.Page{})
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	var sawRevokeForX bool
	for _, e := range ep.Events {
		if e.Digest == dY {
			t.Errorf("annDigest rebind LEAKED: an event surfaced for redirected digest Y")
		}
		if e.Kind == artifact.KindRevoke {
			if e.Digest != dX {
				t.Errorf("revoke digest = %q, want signed X %q (annDigest ignored)", e.Digest, dX)
			}
			sawRevokeForX = true
		}
	}
	if !sawRevokeForX {
		t.Fatal("RELABEL ATTACK SUCCEEDED: a signed revoke annotated 'installed' was suppressed from Events (HIGH)")
	}
}

// TestOCIResolveFullyRevoked. BUG-1: when every version is revoked, Resolve errors
// rather than returning a revoked bundle as "latest".
func TestOCIResolveFullyRevoked(t *testing.T) {
	ctx := context.Background()
	b := newOCIBackend(ociStore(t), "oci://test.local/skills")
	defer b.Close()
	d1, d2 := skbDig("pdf", "1.0.0"), skbDig("pdf", "1.2.0")
	for _, v := range []struct{ ver, d string }{{"1.0.0", d1}, {"1.2.0", d2}} {
		if _, err := b.Publish(ctx, admitEvent("pdf", v.ver, v.d)); err != nil {
			t.Fatalf("admit %s: %v", v.ver, err)
		}
		if _, err := b.Publish(ctx, artifact.PublishRequest{
			Kind:  artifact.KindRevoke,
			Event: map[string]any{"kind": "revoked", "bundle_digest": v.d, "revoked_by": "id:r"},
			Meta:  artifact.ArtifactMeta{Name: "pdf", Version: v.ver, Digest: v.d},
		}); err != nil {
			t.Fatalf("revoke %s: %v", v.ver, err)
		}
	}
	if ref, err := b.Resolve(ctx, artifact.RefQuery{Name: "pdf"}); err == nil {
		t.Errorf("Resolve of a fully-revoked skill returned %+v, want error", ref)
	}
}

// TestOCIEventsSince: the --since filter (previously claimed but untested).
func TestOCIEventsSince(t *testing.T) {
	ctx := context.Background()
	b := newOCIBackend(ociStore(t), "oci://test.local/skills")
	defer b.Close()
	d := skbDig("pdf", "1.0.0")
	if _, err := b.Publish(ctx, admitEvent("pdf", "1.0.0", d)); err != nil {
		t.Fatalf("admit: %v", err)
	}
	subj, _, _ := b.manifestForDigest(ctx, d)
	old := map[string]any{"reviewer_id": "id:v", "bundle_digest": d, "governance_level": "green", "occurred_at": "2020-01-01T00:00:00Z"}
	recent := map[string]any{"reviewer_id": "id:v", "bundle_digest": d, "governance_level": "green", "occurred_at": "2030-01-01T00:00:00Z"}
	for _, e := range []map[string]any{old, recent} {
		bts, _ := json.MarshalIndent(e, "", "  ")
		if err := b.pushEventReferrer(ctx, subj, "attested", d, bts); err != nil {
			t.Fatalf("push: %v", err)
		}
	}
	cut := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	ep, err := b.Events(ctx, artifact.ListFilter{Name: "pdf", Since: cut}, artifact.Page{})
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	// The admit (no occurred_at) is kept best-effort; the 2020 attest is dropped; the
	// 2030 attest is kept. So NO event may be dated before the cutoff.
	for _, e := range ep.Events {
		if !e.OccurredAt.IsZero() && e.OccurredAt.Before(cut) {
			t.Errorf("event dated %s slipped past --since %s", e.OccurredAt, cut)
		}
	}
}

// TestOCIInstallRequiresPriorAdmit. BUG-2 documented semantics: because an OCI
// event is a REFERRER (it needs a subject manifest), recording a governance event
// for a digest never admitted on THIS target is refused. Cross-target install-event
// recording (federation "install from A, record on B") is a tracked follow-up.
func TestOCIInstallRequiresPriorAdmit(t *testing.T) {
	ctx := context.Background()
	b := newOCIBackend(ociStore(t), "oci://test.local/skills")
	defer b.Close()
	if _, err := b.Publish(ctx, artifact.PublishRequest{
		Kind:  artifact.KindInstall,
		Event: map[string]any{"kind": "installed", "bundle_digest": dig(7), "installed_on_host": "h1"},
		Meta:  artifact.ArtifactMeta{Name: "ghost", Version: "1.0.0", Digest: dig(7)},
	}); err == nil {
		t.Error("install for a never-admitted digest should be refused on the OCI referrers model")
	}
}

// TestOCIResolveByDigestFullRef. BUG-4: digest-only Resolve returns the full ref.
func TestOCIResolveByDigestFullRef(t *testing.T) {
	ctx := context.Background()
	b := newOCIBackend(ociStore(t), "oci://test.local/skills")
	defer b.Close()
	d := skbDig("pdf", "2.0.0")
	if _, err := b.Publish(ctx, admitEvent("pdf", "2.0.0", d)); err != nil {
		t.Fatalf("admit: %v", err)
	}
	ref, err := b.Resolve(ctx, artifact.RefQuery{Digest: d})
	if err != nil {
		t.Fatalf("Resolve by digest: %v", err)
	}
	if ref.Name != "pdf" || ref.Version != "2.0.0" || ref.Locator == "" {
		t.Errorf("digest Resolve = %+v, want name=pdf version=2.0.0 with a locator", ref)
	}
}

// TestOCIPublishTagOccupied. MED-3: a second admit of the same name@version with
// DIFFERENT content is refused (not a silent no-op that drops the real bundle).
func TestOCIPublishTagOccupied(t *testing.T) {
	ctx := context.Background()
	b := newOCIBackend(ociStore(t), "oci://test.local/skills")
	defer b.Close()
	if _, err := b.Publish(ctx, admitEvent("pdf", "1.0.0", skbDig("pdf", "1.0.0"))); err != nil {
		t.Fatalf("admit: %v", err)
	}
	blob2 := []byte("SKB:pdf@1.0.0-DIFFERENT")
	sum := sha256.Sum256(blob2)
	d2 := "sha256:" + hex.EncodeToString(sum[:])
	if _, err := b.Publish(ctx, artifact.PublishRequest{
		Kind:  artifact.KindAdmit,
		Blob:  blob2,
		Event: map[string]any{"kind": "admitted", "bundle_digest": d2, "admitted_by_identity": "id:x"},
		Meta:  artifact.ArtifactMeta{Name: "pdf", Version: "1.0.0", Digest: d2},
	}); err == nil {
		t.Error("re-publishing pdf@1.0.0 with different content should be refused (immutability)")
	}
}

func TestOCITagInjective(t *testing.T) {
	if tagFor("a_b", "1.0") == tagFor("a", "b_1.0") {
		t.Error("tagFor is not injective: two distinct (name,version) pairs collide")
	}
}

func TestOCIPlaintextCredRefused(t *testing.T) {
	t.Setenv("M3C_OCI_HTTP", "1")
	creds := fakeCreds{user: "deployer", token: "s3cret"}
	// Non-loopback host over plain HTTP with a credential → refuse.
	if _, err := openOCI("oci://ghcr.io/kamir/skills", artifact.OpenOptions{Creds: creds}); err == nil {
		t.Error("bearer over plain HTTP to a non-loopback host must be refused")
	}
	// Loopback host over plain HTTP is fine (LAN/test registry).
	if _, err := openOCI("oci://127.0.0.1:5000/skills", artifact.OpenOptions{Creds: creds}); err != nil {
		t.Errorf("plain HTTP to loopback should be allowed: %v", err)
	}
}

type fakeCreds struct{ user, token string }

func (f fakeCreds) Credential(ctx context.Context, scheme, host string, mode artifact.AccessMode) (artifact.Credential, error) {
	return artifact.Credential{User: f.user, Token: f.token, Scheme: scheme}, nil
}

func TestMain(m *testing.M) { os.Exit(m.Run()) }
