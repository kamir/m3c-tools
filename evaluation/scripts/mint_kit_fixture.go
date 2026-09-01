//go:build ignore

// mint_kit_fixture.go — a standalone, deterministic issuer that writes a single
// signed bundle + its BundleMeta sidecar + a pinned trust-roots YAML into an
// output directory, exactly the inputs `skillctl export-verification-kit`
// consumes. It reuses the white-paper evidence/mint-evidence.go pattern but is
// DETERMINISTIC (seeded keys) so the air-gap (E2) and reproducibility (E9)
// drivers produce byte-identical fixtures on every run.
//
// Usage: go run scripts/mint_kit_fixture.go <out-dir>
//
// It is a `go:build ignore` program (not part of the package build) invoked by
// the E2 air-gap shell script.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

const seed uint64 = 0x52762E2 // fixed → reproducible fixture

type seededReader struct {
	seed, counter uint64
	buf           []byte
}

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

func keypair(s uint64) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(&seededReader{seed: s})
	if err != nil {
		panic(err)
	}
	return pub, priv
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: mint_kit_fixture <out-dir>")
		os.Exit(2)
	}
	dir := os.Args[1]
	if err := os.MkdirAll(dir, 0o755); err != nil {
		panic(err)
	}

	aPub, aPriv := keypair(seed + 1)
	rPub, rPriv := keypair(seed)

	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	skill := []byte("---\nname: eval-kit-skill\nversion: 1.0.0\ngovernance_level: green\n---\n# eval-kit-skill\nDeterministic fixture for the SPEC-0280 air-gap + reproducibility drivers.\n")
	manifest := []byte(`{"name":"eval-kit-skill","version":"1.0.0","data_dependencies":[{"id":"local-read","kind":"local_fs","access":"read","scope":"./data/**"}]}`)
	for _, f := range []struct {
		name string
		body []byte
	}{
		{"eval-kit-skill/SKILL.md", skill},
		{"bundle.json", manifest},
	} {
		_ = tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body))})
		_, _ = tw.Write(f.body)
	}
	_ = tw.Close()
	_ = gz.Close()

	skb := filepath.Join(dir, "eval-kit-skill@1.0.0.skb")
	if err := os.WriteFile(skb, raw.Bytes(), 0o644); err != nil {
		panic(err)
	}

	d := sha256.Sum256(raw.Bytes())
	digest := "sha256:" + hex.EncodeToString(d[:])
	authorID := "id:author@eval"
	regURL := "https://registry.eval.example/api/skills"

	meta := registry.BundleMeta{
		Bundle: map[string]any{"bundle_digest": digest, "name": "eval-kit-skill", "version": "1.0.0", "status": "admitted"},
		Signatures: []registry.SignatureRow{
			{Role: "author", IdentityID: authorID, SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(aPriv, d[:])), Status: "active"},
			{Role: "registry", IdentityID: "id:registry@eval", SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(rPriv, d[:])), Status: "active"},
		},
		Attestations:      []registry.AttestationRow{{Level: "green", ReviewerID: "id:reviewer@eval", AttestedAt: "2026-06-22T09:00:00Z", Status: "active"}},
		CurrentGovernance: "green",
	}
	mj, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "eval-kit-skill@1.0.0.skbmeta.json"), mj, 0o644); err != nil {
		panic(err)
	}

	fp := sha256.Sum256(aPub)
	tr := "trust_roots:\n" +
		"  - registry_url: " + regURL + "\n" +
		"    registry_keys:\n      - id: eval-registry-2026\n        pubkey: " + base64.StdEncoding.EncodeToString(rPub) + "\n" +
		"    identity_keys_authorized: pinned\n    governance_minimum: green\n" +
		"    authors:\n      - id: " + authorID + "\n        pubkey: " + base64.StdEncoding.EncodeToString(aPub) + "\n" +
		"        fingerprint: sha256:" + hex.EncodeToString(fp[:]) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "trust-roots.pinned.yaml"), []byte(tr), 0o600); err != nil {
		panic(err)
	}

	fmt.Printf("bundle=%s\ndigest=%s\n", skb, digest)
}
