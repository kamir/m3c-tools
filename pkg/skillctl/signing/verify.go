package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ErrSignatureInvalid is returned by VerifyDetached when the cryptographic
// check itself fails (i.e. ed25519.Verify said "no"). It maps to exit
// code 11 in the CLI and is sentinel-comparable so tests and downstream
// callers can branch on it without parsing strings.
var ErrSignatureInvalid = errors.New("signature is invalid")

// ErrDigestChanged means the bundle carries a signature, but for DIFFERENT
// bytes than the ones on disk now. In other words: it was signed, and then it
// changed.
//
// It exists because the previous message for this case was actively misleading.
// The detached signature is stored under a filename that contains the digest it
// covers (SignaturePath). Tamper with a byte and the recomputed digest changes,
// so the lookup misses and the tool said "signature file not found". That is
// true and useless: it describes a consequence of the tampering, and it reads
// like a packaging mistake rather than a broken seal. An operator following it
// would go looking for a missing file.
//
// SPEC-0406 AC-08 asks that a refusal name the condition that was violated
// rather than its side effect, and this is the case that forced the rule.
var ErrDigestChanged = errors.New("bundle bytes changed after signing")

// VerifyDetached recomputes the bundle's SHA-256 digest, locates the
// matching `<bundle>.<digest_hex>.author.sig` file, and verifies it
// against the supplied public key.
//
// Returns nil on success, ErrSignatureInvalid wrapped with context on
// crypto failure, and a generic error wrapped with context on other
// failures (file missing, malformed sig, etc.). The caller is responsible
// for translating into exit codes: see the CLI wrapper.
//
// We intentionally do NOT trust any digest field embedded in the bundle
// manifest. The brief is unambiguous: "Recomputes digest, loads
// signature, verifies." Reading the digest from inside the bundle would
// let a malicious packer point our signature lookup at a forged sig file
// for a different content.
func VerifyDetached(bundlePath, pubkeyPath string) error {
	if bundlePath == "" {
		return errors.New("verify-sig: bundle path is required")
	}
	if pubkeyPath == "" {
		return errors.New("verify-sig: --pubkey is required")
	}

	pub, err := LoadPublicKey(pubkeyPath)
	if err != nil {
		return err
	}

	digest, err := ComputeBundleDigest(bundlePath)
	if err != nil {
		return err
	}
	digestHex := hex.EncodeToString(digest[:])

	sigPath := SignaturePath(bundlePath, digestHex)
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Two very different situations reach this line, and the whole point
			// of separating them is that they call for opposite actions.
			//
			// If signatures exist for this bundle under OTHER digests, the bundle
			// was signed and then its bytes changed. Say that, and say which
			// digest was signed, so the reader can see the two values differ.
			//
			// If there are none at all, it was simply never signed here. That is
			// a packaging step someone forgot, not a broken seal.
			if others := siblingSignatureDigests(bundlePath); len(others) > 0 {
				return fmt.Errorf(
					"verify-sig: %w: this file now hashes to %s, but the signature next to it covers %s. "+
						"The signature was not re-made, so the bytes were altered after signing: %w",
					ErrDigestChanged, digestHex, strings.Join(others, ", "), ErrSignatureInvalid)
			}
			return fmt.Errorf("verify-sig: no signature found for %s (looked for %s). It appears never to have been signed here", bundlePath, sigPath)
		}
		return fmt.Errorf("verify-sig: read signature %s: %w", sigPath, err)
	}
	if len(sig) != signatureSize {
		return fmt.Errorf("verify-sig: signature %s has wrong length %d (want %d)", sigPath, len(sig), signatureSize)
	}

	// ed25519.Verify is constant-time on the signature comparison
	// (per stdlib docs). Do not roll our own.
	if !ed25519.Verify(pub, digest[:], sig) {
		return fmt.Errorf("verify-sig: %w (digest=%s, sig=%s, pubkey=%s)", ErrSignatureInvalid, digestHex, sigPath, pubkeyPath)
	}
	return nil
}

// siblingSignatureDigests returns the digests of every detached author signature
// sitting next to bundlePath, whatever content they cover.
//
// It reads only file NAMES, never their contents, and it is used only to choose
// between two error messages. Nothing about a trust decision depends on it: a
// wrong answer here changes the wording of a refusal, never the refusal itself.
// That is deliberate, because the directory it scans is attacker-influenced in
// exactly the scenario this function exists for.
func siblingSignatureDigests(bundlePath string) []string {
	dir := filepath.Dir(bundlePath)
	prefix := filepath.Base(bundlePath) + "."
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasPrefix(n, prefix) || !strings.HasSuffix(n, authorSigSuffix) {
			continue
		}
		d := strings.TrimSuffix(strings.TrimPrefix(n, prefix), authorSigSuffix)
		// Only accept something that actually looks like a sha256 hex digest, so a
		// crafted filename cannot put arbitrary text into our error message.
		if len(d) != sha256.Size*2 {
			continue
		}
		if _, err := hex.DecodeString(d); err != nil {
			continue
		}
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}
