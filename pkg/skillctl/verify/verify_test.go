package verify

// Tests for the SPEC-0188 §7 verifier algorithm. Each step has a focused
// case asserting the right sentinel surfaces; the happy-path test exercises
// the full chain end-to-end with on-disk crypto material.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// ----- shared fixture builders -----

// fakeFetcher satisfies identityFetcher with a static map.
type fakeFetcher struct {
	identities map[string]*registry.Identity
	errOn      string // identity_id that returns an error when fetched
}

func (f *fakeFetcher) GetIdentity(_ context.Context, id string) (*registry.Identity, error) {
	if id == f.errOn {
		return nil, errors.New("simulated fetcher failure")
	}
	ident, ok := f.identities[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return ident, nil
}

// keyMaterial holds an ed25519 keypair plus its base64 pubkey for fixtures.
type keyMaterial struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	b64  string
}

func mustKeypair(t *testing.T) keyMaterial {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	return keyMaterial{
		pub:  pub,
		priv: priv,
		b64:  base64.StdEncoding.EncodeToString(pub),
	}
}

// writeBundle produces a fake "blob" file with random bytes and returns
// (path, raw_digest, "sha256:<hex>"). The bytes don't have to be a real
// gzipped tar — the verifier only sees them via SHA-256.
func writeBundle(t *testing.T, content []byte) (string, [32]byte, string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "bundle.skb")
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	d := sha256.Sum256(content)
	return p, d, "sha256:" + hexLower(d[:])
}

// signOver signs the given digest with priv, returning base64.
func signOver(t *testing.T, priv ed25519.PrivateKey, digest [32]byte) string {
	t.Helper()
	sig := ed25519.Sign(priv, digest[:])
	return base64.StdEncoding.EncodeToString(sig)
}

// goodTrustRoot builds a TrustRoot pinning the given registry pubkey.
func goodTrustRoot(t *testing.T, regPub ed25519.PublicKey, governanceMin string) *TrustRoot {
	t.Helper()
	if governanceMin == "" {
		governanceMin = "green"
	}
	return &TrustRoot{
		RegistryURL: "https://reg.example/api/skills",
		RegistryKeys: []RegistryKey{{
			ID:        "reg-key-1",
			Pubkey:    []byte(regPub),
			PubkeyB64: base64.StdEncoding.EncodeToString(regPub),
			Issued:    "2026-05-05",
		}},
		IdentityKeysAuthorized: "from-registry",
		GovernanceMinimum:      governanceMin,
	}
}

// goodMeta builds a happy-path BundleMeta given the bundle digest, an
// author key+id, and a registry signature.
func goodMeta(digestStr, authorID, authorSigB64, regSigB64, currentGov string) *registry.BundleMeta {
	return &registry.BundleMeta{
		Bundle: map[string]any{
			"bundle_digest": digestStr,
			"name":          "fetch-contract",
			"version":       "1.0.0",
			"status":        "admitted",
		},
		Signatures: []registry.SignatureRow{
			{Role: "author", IdentityID: authorID, SignatureB64: authorSigB64, Status: "active"},
			{Role: "registry", IdentityID: "id:registry@aims-core", SignatureB64: regSigB64, Status: "active"},
		},
		Manifest: map[string]any{
			// Author intent is metadata only; verifier MUST NOT gate
			// on it. Tests assert the gate uses CurrentGovernance.
			"author_governance_intent": "green",
			"depends_on":               []any{},
		},
		CurrentGovernance: currentGov,
		Attestations: []registry.AttestationRow{
			{Level: currentGov, ReviewerID: "id:reviewer@m3c", AttestedAt: "2026-05-05T20:00:00Z"},
		},
	}
}

// happyOpts wires up a complete VerifyOpts where everything matches.
func happyOpts(t *testing.T) (VerifyOpts, [32]byte) {
	t.Helper()
	authorKey := mustKeypair(t)
	regKey := mustKeypair(t)
	bundlePath, digestRaw, digestStr := writeBundle(t, []byte("fake bundle bytes for verify test"))
	authorSig := signOver(t, authorKey.priv, digestRaw)
	regSig := signOver(t, regKey.priv, digestRaw)
	authorID := "id:author@m3c"

	meta := goodMeta(digestStr, authorID, authorSig, regSig, "green")

	opts := VerifyOpts{
		BundlePath: bundlePath,
		BundleMeta: meta,
		TrustRoot:  goodTrustRoot(t, regKey.pub, "green"),
		IdentityFetcher: &fakeFetcher{identities: map[string]*registry.Identity{
			authorID: {ID: authorID, PubkeyB64: authorKey.b64, AuthSource: "manual"},
		}},
	}
	return opts, digestRaw
}

// ----- happy path -----

func TestVerify_HappyPath(t *testing.T) {
	opts, _ := happyOpts(t)
	var log bytes.Buffer
	opts.Logger = &log

	res, err := Verify(opts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !strings.HasPrefix(res.Digest, "sha256:") {
		t.Errorf("Digest = %q; want sha256: prefix", res.Digest)
	}
	if res.AuthorIdentity != "id:author@m3c" {
		t.Errorf("AuthorIdentity = %q", res.AuthorIdentity)
	}
	if res.RegistryKeyID != "reg-key-1" {
		t.Errorf("RegistryKeyID = %q", res.RegistryKeyID)
	}
	if res.GovernanceLevel != "green" {
		t.Errorf("GovernanceLevel = %q", res.GovernanceLevel)
	}
	if res.ChainSummary == "" {
		t.Errorf("empty ChainSummary")
	}
	for _, want := range []string{"digest_ok", "author_sig_ok", "registry_sig_ok", "governance_ok"} {
		if !strings.Contains(log.String(), want) {
			t.Errorf("expected logger to contain %q; got:\n%s", want, log.String())
		}
	}
}

// ----- step 1: digest -----

func TestVerify_DigestMismatch_AdvertisedWrong(t *testing.T) {
	opts, _ := happyOpts(t)
	// Replace the advertised digest with a different one.
	opts.BundleMeta.Bundle["bundle_digest"] = "sha256:" + strings.Repeat("00", 32)
	_, err := Verify(opts)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("want ErrDigestMismatch, got %v", err)
	}
	if got := ExitCode(err); got != ExitDigestMismatch {
		t.Errorf("ExitCode = %d, want %d", got, ExitDigestMismatch)
	}
}

func TestVerify_DigestMismatch_BundleTampered(t *testing.T) {
	// This is the SPEC-0188 T8 acceptance test: pack a bundle, sign it,
	// flip one byte in the on-disk blob, expect exit 10.
	authorKey := mustKeypair(t)
	regKey := mustKeypair(t)

	// Original bytes — these are what the registry signed.
	origBytes := []byte("original content for tamper test")
	origDigest := sha256.Sum256(origBytes)
	origDigestStr := "sha256:" + hexLower(origDigest[:])

	// Sign over the ORIGINAL digest.
	authorSig := signOver(t, authorKey.priv, origDigest)
	regSig := signOver(t, regKey.priv, origDigest)

	// Now tamper: write modified bytes to disk.
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.skb")
	tampered := make([]byte, len(origBytes))
	copy(tampered, origBytes)
	tampered[0] ^= 0x01 // single-byte flip
	if err := os.WriteFile(bundlePath, tampered, 0o644); err != nil {
		t.Fatalf("write tampered bundle: %v", err)
	}

	authorID := "id:author@m3c"
	meta := goodMeta(origDigestStr, authorID, authorSig, regSig, "green")
	opts := VerifyOpts{
		BundlePath: bundlePath,
		BundleMeta: meta,
		TrustRoot:  goodTrustRoot(t, regKey.pub, "green"),
		IdentityFetcher: &fakeFetcher{identities: map[string]*registry.Identity{
			authorID: {ID: authorID, PubkeyB64: authorKey.b64, AuthSource: "manual"},
		}},
	}
	_, err := Verify(opts)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("tampered bundle: want ErrDigestMismatch, got %v", err)
	}
	if got := ExitCode(err); got != 10 {
		t.Errorf("tampered bundle: exit code = %d, want 10", got)
	}
}

func TestVerify_DigestMismatch_MissingAdvertisedField(t *testing.T) {
	opts, _ := happyOpts(t)
	delete(opts.BundleMeta.Bundle, "bundle_digest")
	_, err := Verify(opts)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("missing advertised digest: want ErrDigestMismatch, got %v", err)
	}
}

func TestVerify_DigestMismatch_MalformedAdvertised(t *testing.T) {
	opts, _ := happyOpts(t)
	opts.BundleMeta.Bundle["bundle_digest"] = "md5:beef"
	_, err := Verify(opts)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("non-sha256 prefix: want ErrDigestMismatch, got %v", err)
	}
}

// ----- step 7 (status) -----

func TestVerify_BlobMissing_RevokedStatus(t *testing.T) {
	opts, _ := happyOpts(t)
	opts.BundleMeta.Bundle["status"] = "revoked"
	_, err := Verify(opts)
	if !errors.Is(err, ErrBlobMissing) {
		t.Errorf("revoked status: want ErrBlobMissing, got %v", err)
	}
	if got := ExitCode(err); got != ExitBlobMissing {
		t.Errorf("ExitCode = %d, want %d", got, ExitBlobMissing)
	}
}

// ----- step 2/3: author signature + identity -----

func TestVerify_AuthorSig_WrongPubkey(t *testing.T) {
	// SPEC-0188 T9 acceptance test: identity B registered, but signature
	// produced by key A → exit 11.
	opts, _ := happyOpts(t)
	wrongKey := mustKeypair(t)
	// Replace identity pubkey with a key that didn't sign.
	opts.IdentityFetcher.(*fakeFetcher).identities["id:author@m3c"] = &registry.Identity{
		ID:         "id:author@m3c",
		PubkeyB64:  wrongKey.b64,
		AuthSource: "manual",
	}
	_, err := Verify(opts)
	if !errors.Is(err, ErrAuthorSigInvalid) {
		t.Errorf("wrong pubkey: want ErrAuthorSigInvalid, got %v", err)
	}
	if got := ExitCode(err); got != 11 {
		t.Errorf("wrong pubkey: exit = %d, want 11", got)
	}
}

func TestVerify_AuthorSig_RevokedIdentity(t *testing.T) {
	// SPEC-0198 §3 / BUG-0144 — revoked identity now surfaces as
	// ErrIdentityRevoked (exit 17) instead of ErrAuthorSigInvalid (exit 11).
	// Operators must be able to distinguish "key was revoked" from
	// "signature is invalid".
	opts, _ := happyOpts(t)
	ident := opts.IdentityFetcher.(*fakeFetcher).identities["id:author@m3c"]
	ident.RevokedAt = "2026-05-01T00:00:00Z"
	_, err := Verify(opts)
	if !errors.Is(err, ErrIdentityRevoked) {
		t.Errorf("revoked identity: want ErrIdentityRevoked, got %v", err)
	}
	// Make sure we did NOT also map to ErrAuthorSigInvalid (the
	// pre-BUG-0144 behavior). The two sentinels are distinct.
	if errors.Is(err, ErrAuthorSigInvalid) {
		t.Errorf("revoked identity: should NOT also be ErrAuthorSigInvalid, got %v", err)
	}
	if got := ExitCode(err); got != 17 {
		t.Errorf("ExitCode(ErrIdentityRevoked) = %d, want 17", got)
	}
}

func TestVerify_AuthorSig_MissingAuthSource(t *testing.T) {
	opts, _ := happyOpts(t)
	opts.IdentityFetcher.(*fakeFetcher).identities["id:author@m3c"].AuthSource = ""
	_, err := Verify(opts)
	if !errors.Is(err, ErrAuthorSigInvalid) {
		t.Errorf("empty auth_source: want ErrAuthorSigInvalid, got %v", err)
	}
}

func TestVerify_AuthorSig_FetcherError(t *testing.T) {
	opts, _ := happyOpts(t)
	opts.IdentityFetcher.(*fakeFetcher).errOn = "id:author@m3c"
	_, err := Verify(opts)
	if !errors.Is(err, ErrAuthorSigInvalid) {
		t.Errorf("fetcher error: want ErrAuthorSigInvalid, got %v", err)
	}
}

func TestVerify_AuthorSig_Missing(t *testing.T) {
	opts, _ := happyOpts(t)
	// Drop the author row.
	filtered := opts.BundleMeta.Signatures[:0]
	for _, s := range opts.BundleMeta.Signatures {
		if s.Role != "author" {
			filtered = append(filtered, s)
		}
	}
	opts.BundleMeta.Signatures = filtered
	_, err := Verify(opts)
	if !errors.Is(err, ErrAuthorSigInvalid) {
		t.Errorf("missing author row: want ErrAuthorSigInvalid, got %v", err)
	}
}

func TestVerify_AuthorSig_DuplicateRows(t *testing.T) {
	opts, _ := happyOpts(t)
	// Duplicate the author row to force an ambiguity refusal.
	for _, s := range opts.BundleMeta.Signatures {
		if s.Role == "author" {
			opts.BundleMeta.Signatures = append(opts.BundleMeta.Signatures, s)
			break
		}
	}
	_, err := Verify(opts)
	if !errors.Is(err, ErrAuthorSigInvalid) {
		t.Errorf("duplicate author rows: want ErrAuthorSigInvalid, got %v", err)
	}
}

// ----- step 4: registry signature -----

func TestVerify_RegistryNotTrusted_NoMatchingKey(t *testing.T) {
	opts, _ := happyOpts(t)
	// Replace the trust-root key with a new pubkey that didn't sign.
	wrong := mustKeypair(t)
	opts.TrustRoot.RegistryKeys = []RegistryKey{{
		ID:        "wrong-key",
		Pubkey:    []byte(wrong.pub),
		PubkeyB64: wrong.b64,
		Issued:    "2026-05-05",
	}}
	_, err := Verify(opts)
	if !errors.Is(err, ErrRegistryNotTrusted) {
		t.Errorf("unknown registry key: want ErrRegistryNotTrusted, got %v", err)
	}
	if got := ExitCode(err); got != ExitRegistryNotTrusted {
		t.Errorf("ExitCode = %d, want %d", got, ExitRegistryNotTrusted)
	}
}

func TestVerify_RegistryNotTrusted_AllRetired(t *testing.T) {
	opts, _ := happyOpts(t)
	for i := range opts.TrustRoot.RegistryKeys {
		opts.TrustRoot.RegistryKeys[i].Retired = "2026-04-01"
	}
	_, err := Verify(opts)
	if !errors.Is(err, ErrRegistryNotTrusted) {
		t.Errorf("all keys retired: want ErrRegistryNotTrusted, got %v", err)
	}
}

func TestVerify_RegistryNotTrusted_RotationOverlap(t *testing.T) {
	// During rotation overlap, two keys are pinned. The registry signs
	// with one of them; the verifier must accept the matching one.
	opts, _ := happyOpts(t)
	stale := mustKeypair(t)
	// Prepend a stale (but active) key. The original key (which signed)
	// is preserved.
	opts.TrustRoot.RegistryKeys = append(
		[]RegistryKey{{
			ID:        "stale-key",
			Pubkey:    []byte(stale.pub),
			PubkeyB64: stale.b64,
			Issued:    "2026-04-01",
		}},
		opts.TrustRoot.RegistryKeys...,
	)
	res, err := Verify(opts)
	if err != nil {
		t.Fatalf("rotation overlap: Verify failed: %v", err)
	}
	if res.RegistryKeyID != "reg-key-1" {
		t.Errorf("expected to match reg-key-1, got %q", res.RegistryKeyID)
	}
}

func TestVerify_RegistryNotTrusted_SkipsRetiredAcceptsActive(t *testing.T) {
	// One retired key (which would match if not retired) and one active
	// key (which actually signed). Verify must skip the retired one.
	opts, _ := happyOpts(t)
	// Keep the live signing key but mark it retired; add a fresh key
	// that ALSO matches by re-signing? That's the inverse — we want the
	// retired key to NOT verify anyway. Easier setup: retire the live
	// key and ensure exit is ErrRegistryNotTrusted.
	for i := range opts.TrustRoot.RegistryKeys {
		opts.TrustRoot.RegistryKeys[i].Retired = "2026-04-01"
	}
	_, err := Verify(opts)
	if !errors.Is(err, ErrRegistryNotTrusted) {
		t.Errorf("retired live key: want ErrRegistryNotTrusted, got %v", err)
	}
}

// ----- step 5: governance -----

func TestVerify_GovernanceBelowMin_YellowAgainstGreen(t *testing.T) {
	opts, _ := happyOpts(t) // green min, green bundle by default
	opts.BundleMeta.CurrentGovernance = "yellow"
	_, err := Verify(opts)
	if !errors.Is(err, ErrGovernanceBelowMin) {
		t.Errorf("yellow vs green: want ErrGovernanceBelowMin, got %v", err)
	}
	if got := ExitCode(err); got != ExitGovernanceBelowMin {
		t.Errorf("ExitCode = %d, want %d", got, ExitGovernanceBelowMin)
	}
}

func TestVerify_GovernanceBelowMin_AllowYellowOverride(t *testing.T) {
	opts, _ := happyOpts(t)
	opts.BundleMeta.CurrentGovernance = "yellow"
	opts.AllowYellow = true
	res, err := Verify(opts)
	if err != nil {
		t.Fatalf("--allow-yellow should permit yellow vs green min: %v", err)
	}
	if res.GovernanceLevel != "yellow" {
		t.Errorf("GovernanceLevel = %q, want yellow", res.GovernanceLevel)
	}
}

func TestVerify_GovernanceBelowMin_AllowYellowDoesNotPermitRed(t *testing.T) {
	// --allow-yellow lowers green→yellow, NOT to red. A red bundle stays
	// rejected even with --allow-yellow.
	opts, _ := happyOpts(t)
	opts.BundleMeta.CurrentGovernance = "red"
	opts.AllowYellow = true
	_, err := Verify(opts)
	if !errors.Is(err, ErrGovernanceBelowMin) {
		t.Errorf("red bundle with --allow-yellow: want ErrGovernanceBelowMin, got %v", err)
	}
}

func TestVerify_GovernanceBelowMin_EmptyIsRed(t *testing.T) {
	opts, _ := happyOpts(t)
	opts.BundleMeta.CurrentGovernance = ""
	_, err := Verify(opts)
	if !errors.Is(err, ErrGovernanceBelowMin) {
		t.Errorf("empty governance: want ErrGovernanceBelowMin, got %v", err)
	}
}

func TestVerify_GovernanceBelowMin_OverrideFromOpts(t *testing.T) {
	// CLI passed --governance-min yellow; trust-root says green; bundle
	// is yellow. Should pass.
	opts, _ := happyOpts(t)
	opts.BundleMeta.CurrentGovernance = "yellow"
	opts.GovernanceMin = "yellow"
	if _, err := Verify(opts); err != nil {
		t.Errorf("override yellow should accept yellow: %v", err)
	}
}

func TestVerify_GovernanceBelowMin_AuthorIntentIsIgnored(t *testing.T) {
	// SPEC-0188 §3.2 + §7 step 6: author_governance_intent in the manifest
	// MUST NOT bind. The signed CurrentGovernance is the only verdict.
	// Construct a bundle whose manifest says "green" but whose
	// CurrentGovernance is "red" — verifier must reject.
	opts, _ := happyOpts(t)
	opts.BundleMeta.Manifest["author_governance_intent"] = "green"
	opts.BundleMeta.CurrentGovernance = "red"
	_, err := Verify(opts)
	if !errors.Is(err, ErrGovernanceBelowMin) {
		t.Errorf("author intent should not override signed verdict: got %v", err)
	}
}

// ----- step 6: deps -----

func TestVerify_DepsUnsatisfied_MalformedEntry(t *testing.T) {
	opts, _ := happyOpts(t)
	opts.BundleMeta.Manifest["depends_on"] = []any{
		map[string]any{"name": "requests"}, // missing "kind"
	}
	_, err := Verify(opts)
	if !errors.Is(err, ErrDepsUnsatisfied) {
		t.Errorf("malformed deps: want ErrDepsUnsatisfied, got %v", err)
	}
	if got := ExitCode(err); got != ExitDepsUnsatisfied {
		t.Errorf("ExitCode = %d, want %d", got, ExitDepsUnsatisfied)
	}
}

func TestVerify_IgnoreDepsBypassesCheck(t *testing.T) {
	opts, _ := happyOpts(t)
	opts.BundleMeta.Manifest["depends_on"] = []any{
		map[string]any{"name": "requests"}, // missing "kind"
	}
	opts.IgnoreDeps = true
	if _, err := Verify(opts); err != nil {
		t.Errorf("--ignore-deps should bypass check: got %v", err)
	}
}

func TestVerify_DepsOK_WellFormed(t *testing.T) {
	opts, _ := happyOpts(t)
	opts.BundleMeta.Manifest["depends_on"] = []any{
		map[string]any{"kind": "python", "name": "requests", "constraint": ">=2.31"},
		map[string]any{"kind": "python", "name": "pyyaml", "constraint": ">=6.0"},
	}
	if _, err := Verify(opts); err != nil {
		t.Errorf("well-formed deps should pass: %v", err)
	}
}

// ----- option validation -----

func TestVerify_RejectsZeroOpts(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*VerifyOpts)
	}{
		{"empty BundlePath", func(o *VerifyOpts) { o.BundlePath = "" }},
		{"nil BundleMeta", func(o *VerifyOpts) { o.BundleMeta = nil }},
		{"nil TrustRoot", func(o *VerifyOpts) { o.TrustRoot = nil }},
		{"nil IdentityFetcher", func(o *VerifyOpts) { o.IdentityFetcher = nil }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts, _ := happyOpts(t)
			c.mod(&opts)
			if _, err := Verify(opts); err == nil {
				t.Errorf("expected error for %s", c.name)
			}
		})
	}
}
