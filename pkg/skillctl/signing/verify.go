package signing

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// ErrSignatureInvalid is returned by VerifyDetached when the cryptographic
// check itself fails (i.e. ed25519.Verify said "no"). It maps to exit
// code 11 in the CLI and is sentinel-comparable so tests and downstream
// callers can branch on it without parsing strings.
var ErrSignatureInvalid = errors.New("signature is invalid")

// VerifyDetached recomputes the bundle's SHA-256 digest, locates the
// matching `<bundle>.<digest_hex>.author.sig` file, and verifies it
// against the supplied public key.
//
// Returns nil on success, ErrSignatureInvalid wrapped with context on
// crypto failure, and a generic error wrapped with context on other
// failures (file missing, malformed sig, etc.). The caller is responsible
// for translating into exit codes — see the CLI wrapper.
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
		// A missing sig file is the most common cause of "verify
		// fails" in practice — say so explicitly. Don't reveal
		// anything that wasn't already on the filesystem.
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("verify-sig: signature file not found at %s (digest %s)", sigPath, digestHex)
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
