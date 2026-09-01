// Package device manages the per-machine DEVICE KEY that signs SPEC-0202
// per-invocation runtime envelopes (the InvocationRecord in pkg/skillgate).
//
// Why a dedicated key (SPEC-0202 D1 — blast radius): the device key is
// SEPARATE from the author key (SPEC-0188) and the registry capability-token
// key. Compromise of the device key only lets an attacker forge LOCAL
// invocation records on THIS machine — it cannot admit fake bundles or issue
// capability tokens. Different blast radius → different key.
//
// The key is created LAZILY on first use (EnsureKey), stored at
// ~/.claude/skillctl/device-key.priv (+ .pub), PEM/PKCS#8, mode 0600 — exactly
// the format `signing.Generate` already writes, so there is NO new crypto here:
// we reuse Generate/LoadPrivateKey/LoadPublicKey verbatim and add only the
// lazy-create + KeyID derivation + a thin Sign wrapper.
//
// Signing is fully local and offline. Registry registration of the device
// public key is a follow-up (ADR §4.1) — P2 ships offline-complete.
//
// SPEC reference: SPEC-0202 §9 ("signed by the local skillgate's per-host
// key"), §15 D1 (separate keys / blast radius).
package device

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
)

// keyBasename is the on-disk base path (without the .priv/.pub suffix that
// signing.Generate appends). The directory mirrors the 0700 ~/.claude/skillctl
// convention used by the verdict cache and the gate-audit log.
const keyBasename = "device-key"

// keyIDPrefix tags a device-key fingerprint so a KeyID is self-describing and
// can never be confused with a registry key id (which uses other prefixes).
const keyIDPrefix = "device:"

// keyIDHexLen is how many hex chars of the SHA-256(pubkey) fingerprint we keep.
// 16 hex chars = 64 bits of the digest — ample to identify the local key in an
// audit line without bloating every record. The full pubkey is what actually
// verifies; the KeyID is only a human/index handle.
const keyIDHexLen = 16

// Key is a loaded device keypair plus its derived KeyID. The private key never
// leaves this struct; callers Sign through it rather than handling raw bytes.
type Key struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	keyID string
}

// dirFor returns the ~/.claude/skillctl directory for the given home. Centralised
// so the path convention is defined once.
func dirFor(home string) string {
	return filepath.Join(home, ".claude", "skillctl")
}

// privPath / pubPath return the on-disk key file paths for a home.
func privPath(home string) string { return filepath.Join(dirFor(home), keyBasename+".priv") }
func pubPath(home string) string  { return filepath.Join(dirFor(home), keyBasename+".pub") }

// PrivPath exposes the private-key path (for diagnostics / tests). Not a secret.
func PrivPath(home string) string { return privPath(home) }

// PubPath exposes the public-key path.
func PubPath(home string) string { return pubPath(home) }

// EnsureKey loads the device key, lazily generating it on first use.
//
// Behaviour:
//   - if both .priv and .pub exist → Load and return them;
//   - if NEITHER exists → generate via signing.Generate (which refuses to
//     overwrite, writes 0600 priv / 0644 pub, 0700 parent dir) then Load;
//   - if EXACTLY ONE exists → refuse (a half-keypair is corruption; generating
//     over it would risk clobbering a real private key, and signing.Generate
//     refuses to overwrite anyway). The operator must resolve it explicitly.
//
// home must be a real directory (the caller resolves it via the same userHome
// path the rest of skillctl uses). Returns a *Key ready to Sign.
func EnsureKey(home string) (*Key, error) {
	if home == "" {
		return nil, fmt.Errorf("device: empty home dir")
	}
	pp := privPath(home)
	pub := pubPath(home)
	privExists := fileExists(pp)
	pubExists := fileExists(pub)

	switch {
	case privExists && pubExists:
		return Load(home)
	case !privExists && !pubExists:
		// Lazy create. signing.Generate appends .priv/.pub to the base path.
		base := filepath.Join(dirFor(home), keyBasename)
		if err := signing.Generate(base); err != nil {
			return nil, fmt.Errorf("device: generate key: %w", err)
		}
		return Load(home)
	default:
		// Exactly one half present — corruption / partial rotation. Fail
		// closed rather than silently regenerate (which signing.Generate
		// would refuse anyway, but the error here is clearer).
		return nil, fmt.Errorf("device: half-keypair at %s — exactly one of {.priv,.pub} exists; remove both to regenerate", dirFor(home))
	}
}

// Load reads an EXISTING device key. Returns an error if it is absent — Load
// never creates (use EnsureKey for lazy creation). Reuses the strict
// signing.LoadPrivateKey / LoadPublicKey (mode + PEM-type validation).
func Load(home string) (*Key, error) {
	if home == "" {
		return nil, fmt.Errorf("device: empty home dir")
	}
	priv, err := signing.LoadPrivateKey(privPath(home))
	if err != nil {
		return nil, fmt.Errorf("device: load private key: %w", err)
	}
	pub, err := signing.LoadPublicKey(pubPath(home))
	if err != nil {
		return nil, fmt.Errorf("device: load public key: %w", err)
	}
	// Defence-in-depth: the .pub on disk MUST be the public half of the .priv.
	// If a tampered .pub were paired with a real .priv, an audit reader pinning
	// the .pub would reject signatures the .priv produced (fail-closed), but we
	// catch the mismatch here so the key is never returned in a confused state.
	derived := priv.Public().(ed25519.PublicKey)
	if !pubEqual(derived, pub) {
		return nil, fmt.Errorf("device: key mismatch — %s is not the public half of %s", pubPath(home), privPath(home))
	}
	return &Key{priv: priv, pub: derived, keyID: deriveKeyID(derived)}, nil
}

// KeyID returns the device key's fingerprint id ("device:<16-hex>"). Stable for
// the life of the key; recorded in every InvocationRecord so an auditor can
// correlate a trail to the machine that produced it.
func (k *Key) KeyID() string { return k.keyID }

// PublicKey returns a copy of the raw 32-byte ed25519 public key — the value an
// auditor pins to verify the trail. Public, not a secret.
func (k *Key) PublicKey() ed25519.PublicKey {
	out := make(ed25519.PublicKey, len(k.pub))
	copy(out, k.pub)
	return out
}

// Sign produces a 64-byte ed25519 detached signature over msg with the device
// private key. The caller is responsible for passing CANONICAL, domain-separated
// bytes (see pkg/skillgate CanonicalizeInvocationRecord) — Sign does not add a
// domain separator itself, mirroring signing.SignAttestation.
func (k *Key) Sign(msg []byte) []byte {
	sig := ed25519.Sign(k.priv, msg)
	if len(sig) != ed25519.SignatureSize {
		// stdlib invariant; a wrong-length signature would corrupt the trail.
		panic(fmt.Sprintf("device: ed25519.Sign returned %d bytes (want %d)", len(sig), ed25519.SignatureSize))
	}
	return sig
}

// Verify checks a detached signature against this key's public half. Provided
// for symmetry / local round-trip tests; the durable verification path pins the
// public key independently.
func (k *Key) Verify(msg, sig []byte) bool {
	return ed25519.Verify(k.pub, msg, sig)
}

// deriveKeyID computes "device:<first 16 hex of sha256(pubkey)>".
func deriveKeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return keyIDPrefix + hex.EncodeToString(sum[:])[:keyIDHexLen]
}

// fileExists reports whether path exists as a regular file (or any file). A
// stat error other than not-exist is treated as "exists" so EnsureKey refuses
// to generate over an unreadable file rather than masking the problem.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// pubEqual is a length-checked byte equality for two public keys.
func pubEqual(a, b ed25519.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
