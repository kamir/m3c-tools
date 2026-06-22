package verify

// SPEC-0276 R4.4 — signed, offline-distributable revocation list.
//
// A hosted CA enforces revocation by making every verifier call its OCSP/CRL
// endpoint. That re-introduces the network dependency we removed: "verify"
// becomes "ask the issuer". Instead we distribute a SIGNED list of revoked
// bundle digests that a third party can pin and check entirely offline — the
// signature is ed25519 over a canonical payload, verifiable against the same
// pinned registry keys that admit bundles. A forged or unsigned list cannot
// block (or silently fail-open) a bundle: it must verify against an active
// registry key or it is refused.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// RevocationList is the on-disk, signed revocation snapshot.
type RevocationList struct {
	// RegistryURL is the registry this list speaks for. Part of the signed
	// canonical payload, so it cannot be retargeted without re-signing.
	RegistryURL string `json:"registry_url"`

	// RevokedDigests is the set of revoked bundle digests, each "sha256:<hex>".
	RevokedDigests []string `json:"revoked_digests"`

	// IssuedAt is the RFC3339 timestamp the list was signed. Advisory for
	// humans (freshness); the security property is the signature, not the time.
	IssuedAt string `json:"issued_at"`

	// SignatureB64 is base64 of the raw 64-byte ed25519 signature over
	// CanonicalRevocationBytes(RegistryURL, IssuedAt, RevokedDigests).
	SignatureB64 string `json:"signature_b64"`
}

// revocationCanonicalV1 is the deterministic, signed payload. A struct (not a
// map) so json.Marshal field order is fixed; digests are sorted+normalized
// before marshalling so the same logical list always yields the same bytes.
type revocationCanonicalV1 struct {
	Type           string   `json:"type"`
	Version        int      `json:"version"`
	RegistryURL    string   `json:"registry_url"`
	IssuedAt       string   `json:"issued_at"`
	RevokedDigests []string `json:"revoked_digests"`
}

// CanonicalRevocationBytes returns the exact bytes that are signed/verified.
// Digests are validated (must be sha256:<64hex>), lowercased, de-duplicated and
// sorted, so signer and verifier agree regardless of input order or case.
func CanonicalRevocationBytes(registryURL, issuedAt string, digests []string) ([]byte, error) {
	norm, err := normalizeDigests(digests)
	if err != nil {
		return nil, err
	}
	payload := revocationCanonicalV1{
		Type:           "skillctl-revocation-list",
		Version:        1,
		RegistryURL:    strings.TrimRight(strings.TrimSpace(registryURL), "/"),
		IssuedAt:       strings.TrimSpace(issuedAt),
		RevokedDigests: norm,
	}
	return json.Marshal(payload)
}

// normalizeDigests validates, lowercases, de-dups and sorts a digest list.
func normalizeDigests(digests []string) ([]string, error) {
	seen := make(map[string]struct{}, len(digests))
	out := make([]string, 0, len(digests))
	for _, d := range digests {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if _, err := decodeShaHexDigest(d); err != nil {
			return nil, fmt.Errorf("revocation list: invalid digest %q: %w", d, err)
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}

// NewSignedRevocationList builds and signs a RevocationList with a registry
// private key. Used by tooling/tests; the production signer is the registry,
// but the format is symmetric so we can produce one locally for a kit.
func NewSignedRevocationList(registryURL, issuedAt string, digests []string, priv ed25519.PrivateKey) (*RevocationList, error) {
	canon, err := CanonicalRevocationBytes(registryURL, issuedAt, digests)
	if err != nil {
		return nil, err
	}
	norm, _ := normalizeDigests(digests) // already validated by CanonicalRevocationBytes
	sig := ed25519.Sign(priv, canon)
	return &RevocationList{
		RegistryURL:    strings.TrimRight(strings.TrimSpace(registryURL), "/"),
		RevokedDigests: norm,
		IssuedAt:       strings.TrimSpace(issuedAt),
		SignatureB64:   base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// VerifyRevocationList checks the list's signature against an active registry
// key in root and returns the set of revoked digests (lowercased). Fail-closed:
// a list whose signature matches no active key returns ErrRegistryNotTrusted —
// an attacker cannot drop a revocation by stripping its signature, nor forge
// one to block a healthy bundle.
func VerifyRevocationList(list *RevocationList, root *TrustRoot) (map[string]struct{}, error) {
	if list == nil {
		return nil, fmt.Errorf("revocation list: nil: %w", ErrRegistryNotTrusted)
	}
	if root == nil {
		return nil, errors.New("revocation list: nil trust root")
	}
	canon, err := CanonicalRevocationBytes(list.RegistryURL, list.IssuedAt, list.RevokedDigests)
	if err != nil {
		return nil, err
	}
	sig, err := decodeSignatureB64(list.SignatureB64)
	if err != nil {
		return nil, fmt.Errorf("revocation list: decode signature: %w", errors.Join(ErrRegistryNotTrusted, err))
	}
	active := root.ActiveKeys()
	if len(active) == 0 {
		return nil, fmt.Errorf("revocation list: trust root %s has no active registry keys: %w", root.RegistryURL, ErrRegistryNotTrusted)
	}
	matched := false
	for _, k := range active {
		if len(k.Pubkey) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(k.Pubkey), canon, sig) {
			matched = true
			break
		}
	}
	if !matched {
		return nil, fmt.Errorf("revocation list: signature did not match any active registry key in %s: %w", root.RegistryURL, ErrRegistryNotTrusted)
	}
	norm, err := normalizeDigests(list.RevokedDigests)
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(norm))
	for _, d := range norm {
		set[d] = struct{}{}
	}
	return set, nil
}
