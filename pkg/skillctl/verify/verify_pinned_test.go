package verify

// Tests for SPEC-0276 R4.1 — pinned author identities. The point of the
// feature is fully-offline, third-party verification: the author signature is
// checked against a key pinned LOCALLY in trust-roots, with NO registry call.
// These tests therefore pass a nil IdentityFetcher on the happy path — if the
// verifier reached for the registry it would nil-panic, which is the strongest
// possible proof that pinned mode is network-free.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// pinnedTrustRoot builds a TrustRoot in pinned mode that pins authorID to
// authorPub and trusts regPub as the registry key. Pubkey raw bytes are set
// directly (Load hydrates them; a hand-built fixture must do it itself).
func pinnedTrustRoot(authorID string, authorPub, regPub ed25519.PublicKey, govMin string) *TrustRoot {
	if govMin == "" {
		govMin = "green"
	}
	return &TrustRoot{
		RegistryURL: "https://reg.example/api/skills",
		RegistryKeys: []RegistryKey{{
			ID:        "reg-key-1",
			Pubkey:    []byte(regPub),
			PubkeyB64: base64.StdEncoding.EncodeToString(regPub),
			Issued:    "2026-05-05",
		}},
		IdentityKeysAuthorized: "pinned",
		Authors: []AuthorKey{{
			ID:        authorID,
			Pubkey:    []byte(authorPub),
			PubkeyB64: base64.StdEncoding.EncodeToString(authorPub),
		}},
		GovernanceMinimum: govMin,
	}
}

// pinnedOpts wires a complete VerifyOpts in pinned mode with NO fetcher.
func pinnedOpts(t *testing.T) (VerifyOpts, keyMaterial) {
	t.Helper()
	authorKey := mustKeypair(t)
	regKey := mustKeypair(t)
	bundlePath, digestRaw, digestStr := writeBundle(t, []byte("pinned-mode bundle bytes"))
	authorSig := signOver(t, authorKey.priv, digestRaw)
	regSig := signOver(t, regKey.priv, digestRaw)
	authorID := "id:kamir@m3c"

	opts := VerifyOpts{
		BundlePath:      bundlePath,
		BundleMeta:      goodMeta(digestStr, authorID, authorSig, regSig, "green"),
		TrustRoot:       pinnedTrustRoot(authorID, authorKey.pub, regKey.pub, "green"),
		IdentityFetcher: nil, // pinned mode must not need it
	}
	return opts, authorKey
}

func TestVerify_Pinned_HappyPath_NoFetcher(t *testing.T) {
	opts, _ := pinnedOpts(t)
	var log bytes.Buffer
	opts.Logger = &log

	res, err := Verify(opts)
	if err != nil {
		t.Fatalf("pinned verify should pass with no fetcher, got: %v", err)
	}
	if res.AuthorIdentity != "id:kamir@m3c" {
		t.Errorf("author identity = %q, want id:kamir@m3c", res.AuthorIdentity)
	}
	if !bytes.Contains(log.Bytes(), []byte("source=pinned")) {
		t.Errorf("verbose log should record source=pinned; got:\n%s", log.String())
	}
}

func TestVerify_Pinned_DoesNotCallFetcher(t *testing.T) {
	opts, _ := pinnedOpts(t)
	called := false
	opts.IdentityFetcher = &spyFetcher{onCall: func() { called = true }}

	if _, err := Verify(opts); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if called {
		t.Fatal("pinned mode must NOT call the identity fetcher")
	}
}

// spyFetcher records whether GetIdentity was invoked.
type spyFetcher struct{ onCall func() }

func (s *spyFetcher) GetIdentity(_ context.Context, id string) (*registry.Identity, error) {
	s.onCall()
	return &registry.Identity{ID: id, AuthSource: "manual"}, nil
}

func TestVerify_Pinned_AuthorNotPinned(t *testing.T) {
	opts, _ := pinnedOpts(t)
	// Remove the pin so the author id is unknown locally.
	opts.TrustRoot.Authors = []AuthorKey{{
		ID:        "id:someone-else@m3c",
		Pubkey:    opts.TrustRoot.Authors[0].Pubkey,
		PubkeyB64: opts.TrustRoot.Authors[0].PubkeyB64,
	}}

	_, err := Verify(opts)
	if !errors.Is(err, ErrAuthorSigInvalid) {
		t.Fatalf("unpinned author should yield ErrAuthorSigInvalid, got: %v", err)
	}
}

func TestVerify_Pinned_WrongKey(t *testing.T) {
	opts, _ := pinnedOpts(t)
	// Pin a DIFFERENT key under the right id — signature won't verify.
	other := mustKeypair(t)
	opts.TrustRoot.Authors[0].Pubkey = []byte(other.pub)
	opts.TrustRoot.Authors[0].PubkeyB64 = other.b64

	_, err := Verify(opts)
	if !errors.Is(err, ErrAuthorSigInvalid) {
		t.Fatalf("wrong pinned key should yield ErrAuthorSigInvalid, got: %v", err)
	}
}

func TestVerify_Pinned_RetiredKeyRejected(t *testing.T) {
	opts, _ := pinnedOpts(t)
	opts.TrustRoot.Authors[0].Retired = "2026-06-01"

	_, err := Verify(opts)
	if !errors.Is(err, ErrAuthorSigInvalid) {
		t.Fatalf("retired pin should be inert → ErrAuthorSigInvalid, got: %v", err)
	}
}

// ----- trust-roots Load/validate tests for the pinned schema -----

func writeTrustRootsYAML(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "skill-trust-roots.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	return p
}

func TestTrustRoots_Pinned_RequiresAuthors(t *testing.T) {
	regKey := mustKeypair(t)
	body := "" +
		"trust_roots:\n" +
		"  - registry_url: https://reg.example/api/skills\n" +
		"    registry_keys:\n" +
		"      - id: reg-key-1\n" +
		"        pubkey: " + regKey.b64 + "\n" +
		"    identity_keys_authorized: pinned\n" +
		"    governance_minimum: green\n"
	_, err := Load(writeTrustRootsYAML(t, body))
	if err == nil {
		t.Fatal("pinned mode with no authors should fail validation")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("requires a non-empty authors")) {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestTrustRoots_Pinned_FingerprintMatch_Hydrates(t *testing.T) {
	regKey := mustKeypair(t)
	authorKey := mustKeypair(t)
	fp := authorFingerprint(authorKey.pub)
	body := "" +
		"trust_roots:\n" +
		"  - registry_url: https://reg.example/api/skills\n" +
		"    registry_keys:\n" +
		"      - id: reg-key-1\n" +
		"        pubkey: " + regKey.b64 + "\n" +
		"    identity_keys_authorized: pinned\n" +
		"    governance_minimum: green\n" +
		"    authors:\n" +
		"      - id: id:kamir@m3c\n" +
		"        pubkey: " + authorKey.b64 + "\n" +
		"        fingerprint: " + fp + "\n"
	tr, err := Load(writeTrustRootsYAML(t, body))
	if err != nil {
		t.Fatalf("valid pinned config should load, got: %v", err)
	}
	ak := tr.Roots[0].FindAuthor("id:kamir@m3c")
	if ak == nil {
		t.Fatal("FindAuthor should locate the pinned author")
	}
	if len(ak.Pubkey) != ed25519.PublicKeySize {
		t.Errorf("Pubkey not hydrated: %d bytes", len(ak.Pubkey))
	}
}

func TestTrustRoots_Pinned_FingerprintMismatch_Refuses(t *testing.T) {
	regKey := mustKeypair(t)
	authorKey := mustKeypair(t)
	wrong := authorFingerprint(mustKeypair(t).pub) // a real-looking but wrong fp
	body := "" +
		"trust_roots:\n" +
		"  - registry_url: https://reg.example/api/skills\n" +
		"    registry_keys:\n" +
		"      - id: reg-key-1\n" +
		"        pubkey: " + regKey.b64 + "\n" +
		"    identity_keys_authorized: pinned\n" +
		"    governance_minimum: green\n" +
		"    authors:\n" +
		"      - id: id:kamir@m3c\n" +
		"        pubkey: " + authorKey.b64 + "\n" +
		"        fingerprint: " + wrong + "\n"
	_, err := Load(writeTrustRootsYAML(t, body))
	if err == nil {
		t.Fatal("mismatched fingerprint must be refused")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("does not match pubkey")) {
		t.Errorf("unexpected error: %v", err)
	}
}
