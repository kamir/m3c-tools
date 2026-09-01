package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// fingerprintOf reproduces the frozen pin derivation sha256:hex(sha256(rawpub)).
func fingerprintOf(pub ed25519.PublicKey) string {
	d := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(d[:])
}

// TestResolvePullTrustRoots is the D2 no-regression lock: self / er1:// / empty /
// an UNPINNED locator all resolve to the SELF trust-roots unchanged (peerName
// ""), and only an explicitly PINNED peer swaps in that peer's key.
func TestResolvePullTrustRoots(t *testing.T) {
	genKey := func() (b64 string, pub ed25519.PublicKey) {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(pub), pub
	}
	selfB64, selfPub := genKey()
	peerB64, peerPub := genKey()

	dir := t.TempDir()
	selfPath := filepath.Join(dir, "trust-roots.yaml")
	if err := os.WriteFile(selfPath, []byte("registry: self\npubkey_b64: "+selfB64+"\ngovernance_minimum: green\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Peer store with ONE pinned peer using a DIFFERENT key.
	peersPath := filepath.Join(dir, "skill-peers.yaml")
	peers := &registry.Peers{}
	pe := registry.Peer{Name: "eric", Locator: "gitlab://h/eric/skills", PubKeyB64: peerB64}
	pe.Fingerprint = fingerprintOf(peerPub) // required pin, derived from the key
	if err := peers.AddPeer(pe); err != nil {
		t.Fatal(err)
	}
	if err := peers.Save(peersPath); err != nil {
		t.Fatal(err)
	}
	old := peersConfigPath
	peersConfigPath = peersPath
	defer func() { peersConfigPath = old }()

	// self / er1:// / empty / unpinned → SELF key, no peer.
	for _, reg := range []string{"self", "er1://prod/skills", "", "gitlab://h/UNPINNED/skills"} {
		tr, peerName, err := resolvePullTrustRoots(reg, selfPath)
		if err != nil {
			t.Fatalf("resolve(%q): %v", reg, err)
		}
		if !tr.PubKey().Equal(selfPub) {
			t.Errorf("resolve(%q) used a non-self key (regression!)", reg)
		}
		if peerName != "" {
			t.Errorf("resolve(%q) reported peer %q, want none", reg, peerName)
		}
	}

	// The pinned peer locator → the PEER's key.
	tr, peerName, err := resolvePullTrustRoots("gitlab://h/eric/skills", selfPath)
	if err != nil {
		t.Fatal(err)
	}
	if !tr.PubKey().Equal(peerPub) {
		t.Error("pinned peer did not resolve to the peer's key")
	}
	if peerName != "eric" {
		t.Errorf("peerName = %q, want eric", peerName)
	}
}
