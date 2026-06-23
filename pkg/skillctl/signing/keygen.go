// Package signing implements the Phase-2 cryptographic primitives for
// SPEC-0188 (Signed Skill Bundles & Trusted Skill Graph).
//
// Three operations live here:
//
//	Generate      — produce an ed25519 keypair on disk (PEM-wrapped).
//	SignBundle    — sign the SHA-256 digest of a `.skb` file, write a
//	                detached signature next to it.
//	VerifyDetached — verify a detached signature locally against a public
//	                 key (no registry round-trip).
//
// Key file formats (interface contract owned by stream S1):
//
//	Private key: PEM block "PRIVATE KEY" wrapping a PKCS#8 ed25519 key.
//	             File mode 0600. Never logged. Refuses to overwrite.
//	Public key:  PEM block "PUBLIC KEY" wrapping a SPKI ed25519 key.
//	             File mode 0644.
//
// Signature file format:
//
//	Path:    <bundle.skb>.<digest_hex>.author.sig
//	Content: exactly 64 raw bytes (ed25519 detached signature).
//	         NOT base64. NOT hex. NOT PEM.
//	Signed:  the 32-byte raw SHA-256 of the bundle file bytes.
//
// SignBundle now depends on `pkg/skillbundle` to enforce the SPEC-0196
// declared-scope gate at the sign boundary (P2b re-challenge finding #2): the
// author signature covers the manifest's intent + data dependencies, so signing
// MUST refuse a scope the authoritative validator rejects — "no unvalidated scope
// is ever author-signed" has to hold at EVERY sign entrypoint, not only in Pack.
// This is safe: skillbundle does not import signing, so there is no cycle. (The
// rest of signing — keygen, digest, detached verify — still needs only the file
// bytes' SHA-256.)
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// pemTypePrivate is the PEM block type written for ed25519 private keys.
// PKCS#8 encodings standardize on "PRIVATE KEY" (without an algorithm
// prefix), so verifiers don't need to special-case ed25519 vs RSA vs ECDSA.
const pemTypePrivate = "PRIVATE KEY"

// pemTypePublic is the PEM block type for SubjectPublicKeyInfo (SPKI)
// public keys, again algorithm-agnostic.
const pemTypePublic = "PUBLIC KEY"

// privateKeyMode is the only mode under which we will read or write a
// private key file. Anything more permissive is refused.
const privateKeyMode os.FileMode = 0600

// publicKeyMode is the mode used when writing public keys.
const publicKeyMode os.FileMode = 0644

// Generate writes an ed25519 keypair to outPath.priv (mode 0600) and
// outPath.pub (mode 0644), both PEM-wrapped.
//
// The function refuses to clobber existing files at either path — losing a
// private key by overwrite is far worse than a noisy error. The caller must
// remove the old key explicitly if they intend to rotate.
//
// The private key never appears in error messages or logs; only file paths
// do, which are not secrets.
func Generate(outPath string) error {
	if outPath == "" {
		return errors.New("keygen: --out is required")
	}

	privPath := outPath + ".priv"
	pubPath := outPath + ".pub"

	// Refuse to overwrite. Matches the spec's security checklist:
	// "refuse to write if file exists".
	for _, p := range []string{privPath, pubPath} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("keygen: refuse to overwrite existing file %s (remove it first if you really mean to rotate)", p)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("keygen: stat %s: %w", p, err)
		}
	}

	// Make sure the parent directory exists. We only create it with 0700
	// because it is meant to hold private keys.
	if dir := filepath.Dir(outPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("keygen: create parent dir %s: %w", dir, err)
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("keygen: generate ed25519 key: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		// Should never happen for ed25519 with stdlib.
		return fmt.Errorf("keygen: marshal pkcs8: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("keygen: marshal spki: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{Type: pemTypePrivate, Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: pemTypePublic, Bytes: pubDER})

	// Write the private key first with the strict mode. Use O_EXCL as a
	// belt-and-braces against the stat-then-write race we already guarded
	// above: if anything created the file between the stat and now, we
	// fail rather than overwrite.
	if err := writeExclusive(privPath, privPEM, privateKeyMode); err != nil {
		// Wipe the in-memory PEM as best we can. (This doesn't
		// scrub the runtime's intermediate buffers; it's a hygiene
		// gesture, not a security guarantee.)
		zeroize(privPEM)
		zeroize(privDER)
		return fmt.Errorf("keygen: write private key: %w", err)
	}
	zeroize(privPEM)
	zeroize(privDER)

	if err := writeExclusive(pubPath, pubPEM, publicKeyMode); err != nil {
		// Roll back the private key file so we don't leave a
		// dangling half-keypair (which would deceive a later
		// `keygen` into thinking the pair already exists).
		_ = os.Remove(privPath)
		return fmt.Errorf("keygen: write public key: %w", err)
	}

	return nil
}

// LoadPrivateKey reads a PEM-wrapped PKCS#8 ed25519 private key from path.
//
// Security posture:
//   - Refuses to read if the file mode is broader than 0600 (rather than
//     silently chmod'ing — the user should fix it explicitly).
//   - Validates the PEM block type strictly.
//   - Rejects files with extra trailing PEM blocks (defense-in-depth
//     against ambiguity attacks).
//   - Type-asserts the parsed key to ed25519.PrivateKey; refuses other
//     algorithms.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("private key: stat %s: %w", path, err)
	}
	// POSIX permission bits are not meaningful on Windows: Go's os package
	// synthesizes a mode (typically 0666/0444 from the read-only attribute)
	// that does not reflect ACL-based access control, so a key written with
	// 0600 reads back as 0666 and would spuriously trip this check —
	// breaking publish/attest/revoke/pull --install. Skip the strict 0077
	// check there; on POSIX it stays fail-closed. Mask off the type bits; we
	// only care about the permission bits.
	if runtime.GOOS != "windows" {
		if mode := st.Mode().Perm(); mode&0o077 != 0 {
			return nil, fmt.Errorf("private key %s has insecure mode %#o; expected 0600 — fix with `chmod 600 %s`", path, mode, path)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("private key: read %s: %w", path, err)
	}
	defer zeroize(data)

	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("private key %s: no PEM block found", path)
	}
	if block.Type != pemTypePrivate {
		return nil, fmt.Errorf("private key %s: unexpected PEM type %q (want %q)", path, block.Type, pemTypePrivate)
	}
	if hasNonWhitespace(rest) {
		return nil, fmt.Errorf("private key %s: extra data after PEM block", path)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Don't leak the DER bytes; they're not the secret material
		// directly but conservatism is cheap.
		return nil, fmt.Errorf("private key %s: parse PKCS8: %w", path, err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key %s: not an ed25519 key (got %T)", path, parsed)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key %s: malformed ed25519 key (length %d, want %d)", path, len(priv), ed25519.PrivateKeySize)
	}
	return priv, nil
}

// LoadPublicKey reads a PEM-wrapped SPKI ed25519 public key from path.
//
// Public keys aren't secrets, but we still validate strictly so a
// corrupted or wrongly-typed file fails fast rather than silently being
// "verified" against nothing useful.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("public key: read %s: %w", path, err)
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("public key %s: no PEM block found", path)
	}
	if block.Type != pemTypePublic {
		return nil, fmt.Errorf("public key %s: unexpected PEM type %q (want %q)", path, block.Type, pemTypePublic)
	}
	if hasNonWhitespace(rest) {
		return nil, fmt.Errorf("public key %s: extra data after PEM block", path)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("public key %s: parse SPKI: %w", path, err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key %s: not an ed25519 key (got %T)", path, parsed)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key %s: malformed ed25519 key (length %d, want %d)", path, len(pub), ed25519.PublicKeySize)
	}
	return pub, nil
}

// writeExclusive writes data to path using O_EXCL so it fails rather than
// clobbers. It also sets the requested mode at create time (umask still
// applies but only to lower bits we don't care about for our targets).
func writeExclusive(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	// Belt and braces: also chmod, since umask may have stripped bits we
	// wanted (mostly defensive — for 0600 there's nothing to strip).
	if err := os.Chmod(path, mode); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

// zeroize overwrites a byte slice with zeroes. Best-effort hygiene; Go's
// GC doesn't guarantee the underlying memory is unreachable elsewhere, but
// for short-lived buffers this is the cheapest sane thing we can do.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// hasNonWhitespace reports whether b contains any byte other than ASCII
// whitespace. Used to reject PEM files that have extra blocks or junk
// after the first block.
func hasNonWhitespace(b []byte) bool {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		default:
			return true
		}
	}
	return false
}
