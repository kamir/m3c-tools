// digest.go: the ONE bundle digest, formed BEFORE the compression (ADR-0047).
//
// Until v0.6.x there were two. `Pack` returned a sha256 over the GZIPPED
// pass-1 archive and wrote it into `bundle.json`, while every signature, the
// signature file name, `attest`, `publish --digest`, `revoke --digest` and the
// offline-stash comparison used a sha256 over the FINISHED FILE's bytes. Both
// hashed gzip output, so both moved when the Go toolchain's gzip changed:
// measured 2026-10-08, `TestDigestStability` was red with go1.27.1 and green
// with go1.26.6, on an unchanged tree.
//
// There is now one value, over the canonical tar. The compression carries no
// identity any more, which has two consequences worth stating plainly:
//
//   - `bundle.json` no longer carries `bundle_digest`. A digest inside the
//     bytes it covers can only be defined by blanking it first, and that forces
//     every verifier to REBUILD the canonical tar before it can check anything.
//     Dropping the self-reference is what lets a verifier do the simple thing:
//     decompress, hash, compare.
//   - the verifier therefore decompresses BEFORE it authenticates. That order
//     is the price of a toolchain-independent identity, and it is bounded, not
//     trusted: DigestBundleFile refuses anything above DefaultMaxExtractedBytes,
//     the same ceiling Unpack enforces (SPEC-0252).
package skillbundle

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// DigestDomain prefixes the hash input so a bundle digest can never collide
// with, or be replayed as, another sha256 in this tree. Same house rule as the
// trust-freeze signature domain. The `v2` names the digest FORMAT, not the
// product version: v1 was the digest over the gzip stream.
const DigestDomain = "m3c-tools/skillbundle/digest/v2\x00"

// CanonicalDigest hashes a canonical tar stream into the raw 32-byte bundle
// digest. This is the message author, registry and governance signatures sign.
func CanonicalDigest(canonicalTar []byte) [sha256.Size]byte {
	h := sha256.New()
	// Write to a hash never returns an error (documented on hash.Hash).
	h.Write([]byte(DigestDomain))
	h.Write(canonicalTar)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// FormatDigest renders a raw digest as "sha256:<lowercase-hex>", the form that
// goes into manifests, tags, CLI output and the registry.
func FormatDigest(sum [sha256.Size]byte) string {
	return "sha256:" + hex.EncodeToString(sum[:])
}

// DigestBundleFile recomputes the bundle digest of a packed `.skb` by
// streaming it through the gunzip reader into the hash. Nothing is kept in
// memory beyond the copy buffer, and nothing is trusted: the output is capped
// at DefaultMaxExtractedBytes, so a gzip bomb is refused rather than hashed.
//
// Empty files are refused: an empty bundle has no useful identity and is
// almost certainly a caller bug.
func DigestBundleFile(path string) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte

	f, err := os.Open(path)
	if err != nil {
		return zero, fmt.Errorf("digest: open %s: %w", path, err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return zero, fmt.Errorf("digest: stat %s: %w", path, err)
	}
	if st.Size() == 0 {
		return zero, fmt.Errorf("digest: refusing to hash empty bundle %s", path)
	}

	gz, err := gzip.NewReader(f)
	if err != nil {
		return zero, fmt.Errorf("digest: gzip reader %s: %w", path, err)
	}
	defer gz.Close()

	h := sha256.New()
	h.Write([]byte(DigestDomain))
	// LimitReader takes one byte MORE than the ceiling: reading it is how we
	// learn the stream was over the limit instead of silently truncating.
	n, err := io.Copy(h, io.LimitReader(gz, DefaultMaxExtractedBytes+1))
	if err != nil {
		return zero, fmt.Errorf("digest: decompress %s: %w", path, err)
	}
	if n > DefaultMaxExtractedBytes {
		return zero, fmt.Errorf("digest: %s decompresses past the %d-byte ceiling; refusing", path, DefaultMaxExtractedBytes)
	}

	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}
