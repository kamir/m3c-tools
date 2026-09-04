package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
)

func testPeerKey(t *testing.T) (b64, fp string, pub ed25519.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pub), selfFingerprint(pub), pub
}

func TestPeerAsTrustRoots(t *testing.T) {
	b64, fp, pub := testPeerKey(t)
	pe := Peer{Name: "eric", Locator: "gitlab://h/eric/skills", PubKeyB64: b64, Fingerprint: fp, GovernanceMinimum: "green"}
	tr, err := pe.AsTrustRoots()
	if err != nil {
		t.Fatalf("AsTrustRoots: %v", err)
	}
	if !tr.PubKey().Equal(pub) {
		t.Error("AsTrustRoots pubkey != pinned key")
	}
	if tr.Registry != pe.Locator {
		t.Errorf("Registry = %q, want the locator", tr.Registry)
	}
	if !tr.MeetsFloor("green") || tr.MeetsFloor("yellow") {
		t.Error("green floor must admit green, reject yellow")
	}
	// Fingerprint mismatch → REFUSE (no TOFU).
	bad := pe
	bad.Fingerprint = "sha256:" + strings.Repeat("0", 64)
	if _, err := bad.AsTrustRoots(); err == nil {
		t.Error("a mismatched pin must be refused")
	}
}

func TestPeerStoreAddFindRemove(t *testing.T) {
	b64, fp, _ := testPeerKey(t)
	path := filepath.Join(t.TempDir(), "skill-peers.yaml")
	p := &Peers{}

	if err := p.AddPeer(Peer{Name: "eric", Locator: "gitlab://h/eric/skills", PubKeyB64: b64, Fingerprint: fp}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	// No pin → refused (fingerprint-required, no TOFU).
	if err := p.AddPeer(Peer{Name: "np", Locator: "local://y", PubKeyB64: b64}); err == nil {
		t.Error("a peer without --pin must be refused")
	}
	// Duplicate name / locator → refused.
	if err := p.AddPeer(Peer{Name: "eric", Locator: "other://z", PubKeyB64: b64, Fingerprint: fp}); err == nil {
		t.Error("duplicate name must be refused")
	}
	if err := p.AddPeer(Peer{Name: "other", Locator: "gitlab://h/eric/skills", PubKeyB64: b64, Fingerprint: fp}); err == nil {
		t.Error("duplicate locator must be refused")
	}

	if err := p.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := LoadPeers(path)
	if err != nil {
		t.Fatalf("LoadPeers: %v", err)
	}
	if pe, ok := got.FindPeerByLocator("gitlab://h/eric/skills"); !ok || pe.Name != "eric" {
		t.Error("FindPeerByLocator failed")
	}
	if !got.RemovePeer("eric") || len(got.Peers) != 0 {
		t.Error("RemovePeer failed")
	}
}

func TestLoadPeersMissingIsEmpty(t *testing.T) {
	got, err := LoadPeers(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil || got == nil || len(got.Peers) != 0 {
		t.Errorf("missing peer store should load empty, got %+v / %v", got, err)
	}
}

// FR-0115: a pinned peer must be able to express a reviewer whose key is NOT the
// registry key. Before the fix, AsTrustRoots dropped the whole D3 declaration, so
// the registry key was the only acceptable attester and a real separation of
// duties was unreachable through `peer add`.
func TestPeerAsTrustRootsCarriesSigners(t *testing.T) {
	regB64, fp, _ := testPeerKey(t)
	revB64, _, revPub := testPeerKey(t)

	pe := Peer{
		Name: "eric", Locator: "github://eric/skills",
		PubKeyB64: regB64, Fingerprint: fp, GovernanceMinimum: "green",
		GovernanceQuorum: 1,
		Signers:          []Signer{{ReviewerID: "id:rev@org", PubKeyB64: revB64}},
	}
	tr, err := pe.AsTrustRoots()
	if err != nil {
		t.Fatalf("AsTrustRoots: %v", err)
	}
	set := tr.signerSet()
	if len(set) != 1 {
		t.Fatalf("signerSet() = %d entries, want the 1 pinned reviewer", len(set))
	}
	if set[0].ReviewerID != "id:rev@org" {
		t.Errorf("reviewer_id = %q, want id:rev@org", set[0].ReviewerID)
	}
	// The KEY is what counts toward a quorum, so it has to be resolved, not just
	// carried as base64. An unresolved key never matches an attestation, and the
	// failure is silent: the pull reports "no attestation at or above the floor".
	if set[0].pub == nil || !set[0].pub.Equal(revPub) {
		t.Error("the pinned signer's key was not resolved to a verifying key")
	}
	if tr.quorum() != 1 {
		t.Errorf("quorum() = %d, want 1", tr.quorum())
	}
}

// Omitting --signer must NOT relax anything: with no signer pinned, the implicit
// signer is the registry key itself (the D2 model), which is exactly the
// behaviour that refuses a foreign reviewer's attestation.
func TestPeerAsTrustRootsWithoutSignersKeepsD2(t *testing.T) {
	regB64, fp, regPub := testPeerKey(t)
	pe := Peer{Name: "eric", Locator: "github://eric/skills", PubKeyB64: regB64, Fingerprint: fp}
	tr, err := pe.AsTrustRoots()
	if err != nil {
		t.Fatalf("AsTrustRoots: %v", err)
	}
	set := tr.signerSet()
	if len(set) != 1 || !set[0].pub.Equal(regPub) || set[0].ReviewerID != "" {
		t.Fatalf("without signers the implicit signer must be the registry key, got %+v", set)
	}
	if tr.quorum() != 1 {
		t.Errorf("quorum() = %d, want the 1-of-1 default", tr.quorum())
	}
}

// A quorum the pinned set cannot satisfy is refused at LOAD, not silently at pull
// time. Same rule the hand-written trust-roots file already enforced; it now
// applies to a peer because both go through resolveSigners.
func TestPeerAsTrustRootsRefusesUnsatisfiableQuorum(t *testing.T) {
	regB64, fp, _ := testPeerKey(t)
	revB64, _, _ := testPeerKey(t)
	pe := Peer{
		Name: "eric", Locator: "github://eric/skills", PubKeyB64: regB64, Fingerprint: fp,
		GovernanceQuorum: 2,
		Signers:          []Signer{{ReviewerID: "id:rev@org", PubKeyB64: revB64}},
	}
	_, err := pe.AsTrustRoots()
	if err == nil {
		t.Fatal("quorum 2 with 1 pinned signer must be refused")
	}
	if !strings.Contains(err.Error(), "governance_quorum") {
		t.Errorf("the error should name governance_quorum, got: %v", err)
	}
}

// A signer key that is not valid base64 is a configuration error, and it must
// fail loudly: an unresolved key would otherwise degrade into "this reviewer
// never matches", which reads like a missing attestation.
func TestPeerAsTrustRootsRefusesBrokenSignerKey(t *testing.T) {
	regB64, fp, _ := testPeerKey(t)
	pe := Peer{
		Name: "eric", Locator: "github://eric/skills", PubKeyB64: regB64, Fingerprint: fp,
		Signers: []Signer{{ReviewerID: "id:rev@org", PubKeyB64: "not-base64!!"}},
	}
	if _, err := pe.AsTrustRoots(); err == nil {
		t.Fatal("an unparseable signer key must be refused")
	}
}

// AddPeer runs the same adapter, so a peer with a broken D3 declaration never
// reaches the store.
func TestAddPeerValidatesSigners(t *testing.T) {
	regB64, fp, _ := testPeerKey(t)
	p := &Peers{}
	err := p.AddPeer(Peer{
		Name: "eric", Locator: "github://eric/skills", PubKeyB64: regB64, Fingerprint: fp,
		GovernanceQuorum: 3,
		Signers:          []Signer{{ReviewerID: "id:rev@org", PubKeyB64: regB64}},
	})
	if err == nil {
		t.Fatal("AddPeer must refuse an unsatisfiable quorum")
	}
	if len(p.Peers) != 0 {
		t.Error("a refused peer must not be stored")
	}
}
