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
