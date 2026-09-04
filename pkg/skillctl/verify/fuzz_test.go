package verify

// Native Go fuzz targets for two untrusted-input surfaces in the verify package:
//   - VerifyRevocationList (+ CanonicalRevocationBytes): a signed, offline
//     revocation snapshot pulled from a registry. It must never fail OPEN. A
//     forged/unsigned list can neither block a healthy bundle nor be accepted
//     without a valid signature over the canonical bytes.
//   - ParseTrustRoots: the strict YAML trust-roots decoder+validator (the
//     step-1 refactor). Arbitrary YAML must never panic it.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// FuzzVerifyRevocationList feeds fuzzed JSON → RevocationList → VerifyRevocationList
// against a fixed active registry key. Oracles: never panics; a revoked set is
// returned ONLY together with a signature that genuinely verifies over the
// canonical bytes (re-checked independently). Anything else is fail-open.
func FuzzVerifyRevocationList(f *testing.F) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	const regURL = "https://reg.example.com"
	root := &TrustRoot{
		RegistryURL:  regURL,
		RegistryKeys: []RegistryKey{{ID: "k1", Pubkey: pub}}, // active (not retired)
	}

	// A genuinely-signed list: this seed MUST pass the oracle (its signature
	// verifies), which is exactly why the oracle re-checks rather than asserting
	// "err always non-nil".
	if good, err := NewSignedRevocationList(regURL, "2026-01-01T00:00:00Z", 1,
		[]string{"sha256:" + strings.Repeat("a", 64)}, priv); err == nil {
		if goodJSON, jerr := json.Marshal(good); jerr == nil {
			f.Add(goodJSON)
		}
	}
	f.Add([]byte(`{"registry_url":"` + regURL + `","revoked_digests":["sha256:` + strings.Repeat("b", 64) + `"],"signature_b64":"AAAA"}`))
	f.Add([]byte(`{"revoked_digests":["not-a-digest"],"signature_b64":"!!!"}`))
	f.Add([]byte(`{"signature_b64":"` + base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)) + `","epoch":5}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`garbage`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var list RevocationList
		if err := json.Unmarshal(data, &list); err != nil {
			return
		}
		set, err := VerifyRevocationList(&list, root, 0) // must never panic
		if err != nil {
			return
		}
		if set == nil {
			t.Fatalf("VerifyRevocationList returned a nil error AND a nil set")
		}
		// Fail-open guard: re-derive the canonical bytes and re-verify the
		// signature against the active pinned key.
		canon, cerr := CanonicalRevocationBytes(list.RegistryURL, list.IssuedAt, list.Epoch, list.RevokedDigests)
		if cerr != nil {
			t.Fatalf("returned a revoked set but canonical bytes errored: %v", cerr)
		}
		sig, derr := base64.StdEncoding.DecodeString(list.SignatureB64)
		if derr != nil || !ed25519.Verify(pub, canon, sig) {
			t.Fatalf("VerifyRevocationList returned a revoked set without a valid signature (fail-open)")
		}
	})
}

// FuzzParseTrustRoots drives the strict trust-roots YAML decoder+validator with
// arbitrary bytes. Oracle: never panics (an accept/reject decision is fine).
func FuzzParseTrustRoots(f *testing.F) {
	pk := base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	validYAML := "trust_roots:\n" +
		"  - registry_url: https://reg.example.com\n" +
		"    registry_keys:\n" +
		"      - id: k1\n" +
		"        pubkey: " + pk + "\n" +
		"        issued: 2026-01-01\n" +
		"    identity_keys_authorized: from-registry\n" +
		"    governance_minimum: green\n"
	f.Add([]byte(validYAML))
	f.Add([]byte("trust_roots: []\n"))
	f.Add([]byte(""))
	f.Add([]byte("not: valid: yaml: : :\n"))
	f.Add([]byte("unknown_key: 1\n")) // strict decode rejects unknown fields
	f.Add([]byte("trust_roots:\n  - registry_url: https://x\n    registry_keys: []\n"))
	f.Add([]byte("trust_roots:\n  - registry_url: \"http://8.8.8.8/api\"\n")) // non-private http rejected
	f.Add([]byte("trust_roots:\n  - registry_url: https://x\n    registry_keys:\n      - id: k\n        pubkey: \"!!!not-base64\"\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseTrustRoots(data) // must never panic
	})
}
