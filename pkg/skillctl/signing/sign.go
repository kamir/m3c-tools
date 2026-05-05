package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// signatureSize is the exact length of an ed25519 detached signature.
// We assert this both on write and read so a partial file or unrelated
// blob can never silently pass through the verifier.
const signatureSize = ed25519.SignatureSize // 64

// authorSigSuffix is the suffix appended to bundle paths to derive the
// author signature filename. The full convention is
// "<bundle>.<digest_hex>.author.sig".
const authorSigSuffix = ".author.sig"

// digestReadBufferSize is the chunk size used when streaming a bundle
// through the SHA-256 hasher. 1 MiB is large enough to amortize syscall
// cost on big bundles and small enough to keep memory bounded.
const digestReadBufferSize = 1 << 20

// ComputeBundleDigest streams the bundle file at bundlePath through
// SHA-256 and returns the raw 32-byte digest.
//
// This is the canonical 32-byte message that author/registry/governance
// signatures all sign over. The brief is explicit: "32-byte SHA-256 of the
// gzipped tarball — recompute, do NOT trust manifest field."
//
// Empty files are refused: an empty bundle has no useful identity and is
// almost certainly a caller bug.
func ComputeBundleDigest(bundlePath string) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte

	f, err := os.Open(bundlePath)
	if err != nil {
		return zero, fmt.Errorf("digest: open %s: %w", bundlePath, err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return zero, fmt.Errorf("digest: stat %s: %w", bundlePath, err)
	}
	if st.Size() == 0 {
		return zero, fmt.Errorf("digest: refusing to hash empty bundle %s", bundlePath)
	}

	h := sha256.New()
	buf := make([]byte, digestReadBufferSize)
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return zero, fmt.Errorf("digest: read %s: %w", bundlePath, err)
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// SignBundle signs the bundle at bundlePath with the ed25519 private key
// at keyPath and writes a detached signature next to the bundle.
//
// Returns the full signature path, the lowercase hex digest, and any
// error. identityID is currently advisory metadata only — the signature
// file format does NOT embed it (the Phase-3 admission endpoint takes
// identity_id as a separate form field, so embedding it here would just
// invite drift). The parameter is preserved so callers can wire it
// through without an interface break later.
//
// Refuses to overwrite an existing signature file: regenerating signatures
// silently is exactly the kind of "looks like it worked" failure we want
// to catch loudly.
func SignBundle(bundlePath, keyPath, identityID string) (sigPath, digestHex string, err error) {
	if bundlePath == "" {
		return "", "", errors.New("sign: bundle path is required")
	}
	if keyPath == "" {
		return "", "", errors.New("sign: --key is required")
	}

	// Quick sanity check on the bundle. We don't validate it's actually
	// a gzipped tarball — that's not signing's job. We just refuse to
	// sign files that don't exist or are empty.
	st, err := os.Stat(bundlePath)
	if err != nil {
		return "", "", fmt.Errorf("sign: stat bundle %s: %w", bundlePath, err)
	}
	if st.Size() == 0 {
		return "", "", fmt.Errorf("sign: bundle %s is empty", bundlePath)
	}

	priv, err := LoadPrivateKey(keyPath)
	if err != nil {
		return "", "", err
	}
	// Best-effort scrub of the private key bytes after we're done.
	defer zeroize(priv)

	digest, err := ComputeBundleDigest(bundlePath)
	if err != nil {
		return "", "", err
	}
	digestHex = hex.EncodeToString(digest[:])

	// ed25519.Sign signs over an arbitrary-length message. Per
	// SPEC-0188 §4.1 we sign over the raw 32-byte digest, not the hex
	// string and not a "sha256:" prefix.
	sig := ed25519.Sign(priv, digest[:])
	if len(sig) != signatureSize {
		// stdlib invariant; defensive.
		return "", "", fmt.Errorf("sign: unexpected signature length %d (want %d)", len(sig), signatureSize)
	}

	sigPath = SignaturePath(bundlePath, digestHex)
	if _, err := os.Stat(sigPath); err == nil {
		return "", "", fmt.Errorf("sign: refuse to overwrite existing signature %s", sigPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", fmt.Errorf("sign: stat %s: %w", sigPath, err)
	}

	if err := writeExclusive(sigPath, sig, 0o644); err != nil {
		return "", "", fmt.Errorf("sign: write signature: %w", err)
	}

	_ = identityID // reserved for future use (see doc comment above)
	return sigPath, digestHex, nil
}

// SignaturePath returns the canonical detached-signature path for a
// bundle and its hex digest. Centralized here so sign and verify-sig
// agree on naming without duplicating the convention.
func SignaturePath(bundlePath, digestHex string) string {
	dir := filepath.Dir(bundlePath)
	base := filepath.Base(bundlePath)
	return filepath.Join(dir, base+"."+digestHex+authorSigSuffix)
}
