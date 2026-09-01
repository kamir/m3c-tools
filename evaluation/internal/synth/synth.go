// Package synth deterministically synthesizes a population of REAL, signed
// skill bundles + their BundleMeta envelopes + a matching pinned TrustRoot,
// so the SPEC-0280 evaluation harness measures the SHIPPED verifier against
// authentic, cryptographically-valid material (not mocks).
//
// It reuses the white-paper `evidence/mint-evidence.go` issuer pattern (a .skb
// is gzip(tar(SKILL.md+bundle.json)); the digest is signed by an author key and
// a registry key; the trust root pins both in `identity_keys_authorized: pinned`
// mode so verification is fully OFFLINE). The single difference from the white-
// paper fixture is DETERMINISM: every key is derived from a caller-supplied seed
// via a seeded reader, so the same seed yields a byte-identical population. This
// is what makes the benchmarks reproducible (SPEC-0280 §3 "deterministic seeds").
//
// SYNTHETIC, by construction: the population here is generated, not drawn from a
// real cohort. The harness labels every synthetic metric as such (SPEC-0280 §1).
package synth

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// RegistryURL is the synthetic registry every minted bundle speaks for.
const RegistryURL = "https://registry.eval.example/api/skills"

// seededReader is a deterministic byte stream for ed25519 key derivation. It is
// a counter-mode SHA-256 KDF over a 64-bit seed: never use for production keys —
// it exists only so the benchmark population is reproducible from a seed.
type seededReader struct {
	seed    uint64
	counter uint64
	buf     []byte
}

func newSeededReader(seed uint64) *seededReader { return &seededReader{seed: seed} }

func (r *seededReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(r.buf) == 0 {
			var block [16]byte
			binary.BigEndian.PutUint64(block[0:8], r.seed)
			binary.BigEndian.PutUint64(block[8:16], r.counter)
			r.counter++
			sum := sha256.Sum256(block[:])
			r.buf = sum[:]
		}
		c := copy(p[n:], r.buf)
		r.buf = r.buf[c:]
		n += c
	}
	return n, nil
}

// keypair derives a deterministic ed25519 keypair from a seed.
func keypair(seed uint64) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(newSeededReader(seed))
	if err != nil {
		// ed25519.GenerateKey only errors if the reader fails; ours never does.
		panic(fmt.Sprintf("synth: deterministic keygen failed: %v", err))
	}
	return pub, priv
}

// Bundle is one synthesized, signed bundle: the on-disk .skb plus the in-memory
// BundleMeta the verifier needs. The author identity is pinned in the population
// TrustRoot.
type Bundle struct {
	Path     string // absolute path to the written .skb
	Digest   string // "sha256:<hex>"
	AuthorID string
	Meta     *registry.BundleMeta
}

// Population is a deterministic set of N signed bundles sharing one registry key
// + trust root, with per-bundle author keys. Everything verifies offline.
type Population struct {
	Root    *verify.TrustRoot
	Bundles []*Bundle
	dir     string
}

// Dir is the temp directory the .skb blobs were written into.
func (p *Population) Dir() string { return p.dir }

// buildSKB returns the gzip(tar(SKILL.md, bundle.json)) bytes for bundle i.
// bundle.json carries a declared data-scope so the digest-verified-manifest path
// (SPEC-0196) exercises real work, matching a production bundle's shape.
func buildSKB(i int) []byte {
	skill := fmt.Sprintf("---\nname: eval-skill-%06d\nversion: 1.0.0\ngovernance_level: green\n---\n# eval-skill-%06d\nA synthetic skill for the SPEC-0280 evaluation harness.\n", i, i)
	manifest := fmt.Sprintf(`{"name":"eval-skill-%06d","version":"1.0.0","data_dependencies":[{"id":"local-read","kind":"local_fs","access":"read","scope":"./data/**"}]}`, i)

	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	files := []struct {
		name string
		body []byte
	}{
		{fmt.Sprintf("eval-skill-%06d/SKILL.md", i), []byte(skill)},
		{"bundle.json", []byte(manifest)},
	}
	for _, f := range files {
		_ = tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body))})
		_, _ = tw.Write(f.body)
	}
	_ = tw.Close()
	_ = gz.Close()
	return raw.Bytes()
}

// MintPopulation deterministically synthesizes n signed bundles from seed.
//
//   - The registry keypair is derived from seed (one per population).
//   - Each bundle's author keypair is derived from seed+1+i (one per bundle), so
//     every bundle has a distinct pinned author — the realistic case where the
//     trust root pins many authors.
//   - All n authors are pinned in the returned TrustRoot (pinned mode → offline).
//
// The .skb files are written under dir (use a t.TempDir()). The same (seed, n)
// always yields byte-identical bundles and digests.
func MintPopulation(dir string, n int, seed uint64) (*Population, error) {
	if n <= 0 {
		return nil, fmt.Errorf("synth: n must be > 0, got %d", n)
	}
	regPub, regPriv := keypair(seed)

	authors := make([]verify.AuthorKey, 0, n)
	bundles := make([]*Bundle, 0, n)

	for i := 0; i < n; i++ {
		aPub, aPriv := keypair(seed + 1 + uint64(i))
		authorID := fmt.Sprintf("id:author-%06d@eval", i)

		skb := buildSKB(i)
		path := filepath.Join(dir, fmt.Sprintf("eval-skill-%06d@1.0.0.skb", i))
		if err := os.WriteFile(path, skb, 0o644); err != nil {
			return nil, fmt.Errorf("synth: write %s: %w", path, err)
		}
		d := sha256.Sum256(skb)
		digest := "sha256:" + hex.EncodeToString(d[:])

		meta := &registry.BundleMeta{
			Bundle: map[string]any{
				"bundle_digest": digest,
				"name":          fmt.Sprintf("eval-skill-%06d", i),
				"version":       "1.0.0",
				"status":        "admitted",
			},
			Signatures: []registry.SignatureRow{
				{Role: "author", IdentityID: authorID, SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(aPriv, d[:])), Status: "active"},
				{Role: "registry", IdentityID: "id:registry@eval", SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(regPriv, d[:])), Status: "active"},
			},
			Manifest:          map[string]any{"depends_on": []any{}},
			CurrentGovernance: "green",
			Attestations: []registry.AttestationRow{
				{Level: "green", ReviewerID: "id:reviewer@eval", AttestedAt: "2026-06-22T09:00:00Z", Status: "active"},
			},
		}

		fp := sha256.Sum256(aPub)
		authors = append(authors, verify.AuthorKey{
			ID:          authorID,
			Pubkey:      []byte(aPub),
			PubkeyB64:   base64.StdEncoding.EncodeToString(aPub),
			Fingerprint: "sha256:" + hex.EncodeToString(fp[:]),
		})
		bundles = append(bundles, &Bundle{Path: path, Digest: digest, AuthorID: authorID, Meta: meta})
	}

	root := &verify.TrustRoot{
		RegistryURL: RegistryURL,
		RegistryKeys: []verify.RegistryKey{{
			ID:        "eval-registry-2026",
			Pubkey:    []byte(regPub),
			PubkeyB64: base64.StdEncoding.EncodeToString(regPub),
			Issued:    "2026-06-22",
		}},
		IdentityKeysAuthorized: "pinned",
		Authors:                authors,
		GovernanceMinimum:      "green",
	}

	return &Population{Root: root, Bundles: bundles, dir: dir}, nil
}

// RegistryPriv re-derives the registry private key for a given seed. Used by
// drivers that must sign a revocation list with the SAME key that admits the
// population (E3, E10), so the list verifies against the population's root.
func RegistryPriv(seed uint64) ed25519.PrivateKey {
	_, priv := keypair(seed)
	return priv
}

// LogKeypair derives a deterministic ed25519 keypair for a transparency-log,
// reused by the translog drivers (E7, E10) so their STHs verify reproducibly.
func LogKeypair(seed uint64) (ed25519.PublicKey, ed25519.PrivateKey) {
	return keypair(seed)
}

// SyntheticDigests deterministically produces n distinct, well-formed
// "sha256:<hex>" digests from seed. Used to populate revocation lists at scale
// (E3) without minting full bundles for each.
func SyntheticDigests(n int, seed uint64) []string {
	out := make([]string, n)
	for i := 0; i < n; i++ {
		var b [16]byte
		binary.BigEndian.PutUint64(b[0:8], seed)
		binary.BigEndian.PutUint64(b[8:16], uint64(i))
		d := sha256.Sum256(b[:])
		out[i] = "sha256:" + hex.EncodeToString(d[:])
	}
	return out
}

// Discard throws output away (silences verifier step-logging in benchmarks
// without importing io in every driver).
var Discard io.Writer = io.Discard
