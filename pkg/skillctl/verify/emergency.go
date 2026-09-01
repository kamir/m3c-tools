package verify

// SPEC-0279 R5 — the EMERGENCY DENY-LIST channel.
//
// The normal revocation snapshot is bounded by max_staleness + cache_ttl: a
// freshly-synced list (or a low-risk action under fail_policy=open) is trusted.
// But a COMPROMISE event ("this key/agent/bundle is burned, NOW") must deny
// IMMEDIATELY — it cannot wait for the next sweep, and it must override a fresh
// snapshot and a low-risk fail-open. The emergency channel is a SEPARATE,
// high-priority signed deny-list whose entries deny on sight, short-circuiting
// the staleness/cache cadence entirely.
//
// Shape reuse, distinct domain: same signed/epoch/ed25519 machinery as
// RevocationList, but a DISTINCT `type` ("skillctl-emergency-deny-list") so an
// emergency entry can never be confused with — or replayed as — a normal
// revocation list (and vice-versa). Entries are opaque deny tokens: a digest
// ("sha256:<hex>"), an agent ("agent:<id>"), or an identity ("id:<who>"); the
// channel does not validate the token SCHEME (a compromise list must be able to
// name ANY principal), only that the list is signed by a pinned registry key.
// The consumers consult this list FIRST, before staleness or risk are even
// considered.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// EmergencyDenyListType is the canonical type discriminator — the domain
// separator vs the revocation lists, the checkpoint, and the AgentID envelope.
const EmergencyDenyListType = "skillctl-emergency-deny-list"

// EmergencyDenyList is the on-disk, signed emergency deny-list.
type EmergencyDenyList struct {
	// RegistryURL is the registry this list speaks for (signed).
	RegistryURL string `json:"registry_url"`

	// DeniedTokens is the set of opaque deny tokens that deny IMMEDIATELY. Each is
	// a digest ("sha256:<hex>"), an agent ("agent:<id>"), or an identity
	// ("id:<who>"). Normalized (trim+lower+dedup+sort) for a stable signature.
	DeniedTokens []string `json:"denied_tokens"`

	// IssuedAt is the RFC3339 instant the list was signed (advisory).
	IssuedAt string `json:"issued_at"`

	// Epoch is the monotonic generation (rollback floor, shared with R1).
	Epoch int `json:"epoch,omitempty"`

	// SignatureB64 is base64 of the raw 64-byte ed25519 signature over
	// CanonicalEmergencyDenyBytes(...).
	SignatureB64 string `json:"signature_b64"`
}

// emergencyDenyCanonicalV1 is the deterministic, signed payload. The `type`
// differs from every other signed object (domain separation).
type emergencyDenyCanonicalV1 struct {
	Type         string   `json:"type"`
	Version      int      `json:"version"`
	RegistryURL  string   `json:"registry_url"`
	IssuedAt     string   `json:"issued_at"`
	Epoch        int      `json:"epoch"`
	DeniedTokens []string `json:"denied_tokens"`
}

// CanonicalEmergencyDenyBytes returns the EXACT bytes signed/verified. Tokens are
// trimmed, lowercased, de-duplicated and sorted so signer and verifier agree
// regardless of input order/case. An empty token is dropped; a token with a
// newline is refused (it could forge a framing boundary).
func CanonicalEmergencyDenyBytes(registryURL, issuedAt string, epoch int, tokens []string) ([]byte, error) {
	norm, err := normalizeEmergencyTokens(tokens)
	if err != nil {
		return nil, err
	}
	payload := emergencyDenyCanonicalV1{
		Type:         EmergencyDenyListType,
		Version:      1,
		RegistryURL:  strings.TrimRight(strings.TrimSpace(registryURL), "/"),
		IssuedAt:     strings.TrimSpace(issuedAt),
		Epoch:        epoch,
		DeniedTokens: norm,
	}
	return json.Marshal(payload)
}

// normalizeEmergencyTokens trims, lowercases, de-dups and sorts the token list.
// Unlike the revocation/agent normalizers it does NOT enforce a scheme — a
// compromise list must be able to name a digest, an agent, OR an identity.
func normalizeEmergencyTokens(tokens []string) ([]string, error) {
	seen := make(map[string]struct{}, len(tokens))
	out := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		tok = strings.ToLower(strings.TrimSpace(tok))
		if tok == "" {
			continue
		}
		if strings.ContainsAny(tok, "\n\r") {
			return nil, fmt.Errorf("emergency deny-list: token %q contains a newline", tok)
		}
		if _, dup := seen[tok]; dup {
			continue
		}
		seen[tok] = struct{}{}
		out = append(out, tok)
	}
	sort.Strings(out)
	return out, nil
}

// NewSignedEmergencyDenyList builds + signs an emergency deny-list with a
// registry private key. Mirrors NewSignedRevocationList.
func NewSignedEmergencyDenyList(registryURL, issuedAt string, epoch int, tokens []string, priv ed25519.PrivateKey) (*EmergencyDenyList, error) {
	canon, err := CanonicalEmergencyDenyBytes(registryURL, issuedAt, epoch, tokens)
	if err != nil {
		return nil, err
	}
	norm, _ := normalizeEmergencyTokens(tokens) // already validated above
	sig := ed25519.Sign(priv, canon)
	return &EmergencyDenyList{
		RegistryURL:  strings.TrimRight(strings.TrimSpace(registryURL), "/"),
		DeniedTokens: norm,
		IssuedAt:     strings.TrimSpace(issuedAt),
		Epoch:        epoch,
		SignatureB64: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// VerifyEmergencyDenyList checks the list's signature against an active registry
// key in root and enforces the rollback floor. Fail-closed (mirrors
// VerifyRevocationList): a signature matching no active key → ErrRegistryNotTrusted;
// an epoch below minEpoch → ErrRegistryNotTrusted. Returns the normalized denied
// token set (lowercased) on success.
//
// NOTE: the emergency channel is NOT subject to max_staleness — a compromise
// deny must apply even if the operator has not re-synced; an old-but-valid
// emergency list still denies the tokens it names. The epoch floor still guards
// against an attacker REPLACING a newer emergency list with an older one.
func VerifyEmergencyDenyList(list *EmergencyDenyList, root *TrustRoot, minEpoch int) (map[string]struct{}, error) {
	if list == nil {
		return nil, fmt.Errorf("emergency deny-list: nil: %w", ErrRegistryNotTrusted)
	}
	if root == nil {
		return nil, errors.New("emergency deny-list: nil trust root")
	}
	canon, err := CanonicalEmergencyDenyBytes(list.RegistryURL, list.IssuedAt, list.Epoch, list.DeniedTokens)
	if err != nil {
		return nil, err
	}
	sig, err := decodeSignatureB64(list.SignatureB64)
	if err != nil {
		return nil, fmt.Errorf("emergency deny-list: decode signature: %w", errors.Join(ErrRegistryNotTrusted, err))
	}
	active := root.ActiveKeys()
	if len(active) == 0 {
		return nil, fmt.Errorf("emergency deny-list: trust root %s has no active registry keys: %w", root.RegistryURL, ErrRegistryNotTrusted)
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
		return nil, fmt.Errorf("emergency deny-list: signature did not match any active registry key in %s: %w", root.RegistryURL, ErrRegistryNotTrusted)
	}
	if list.Epoch < minEpoch {
		return nil, fmt.Errorf("emergency deny-list: epoch %d is below the pinned floor %d (rollback): %w", list.Epoch, minEpoch, ErrRegistryNotTrusted)
	}
	norm, err := normalizeEmergencyTokens(list.DeniedTokens)
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(norm))
	for _, tok := range norm {
		set[tok] = struct{}{}
	}
	return set, nil
}

// LoadVerifiedEmergencyDenyList reads a signed EmergencyDenyList JSON file,
// verifies its signature against the pinned root (with the root's rollback
// floor), and returns the denied-token set. The single read-+-verify entry point
// the CLI verify path and the runtime gate both use. A MISSING file is NOT an
// error (returns an empty set) — the emergency channel is opt-in per machine;
// only a PRESENT-but-untrusted file is fail-closed (the operator placed it).
func LoadVerifiedEmergencyDenyList(path string, root *TrustRoot) (map[string]struct{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]struct{}{}, nil
		}
		return nil, fmt.Errorf("read emergency deny-list %s: %w", path, err)
	}
	var list EmergencyDenyList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parse emergency deny-list %s: %w", path, err)
	}
	floor := 0
	if root != nil {
		floor = root.MinRevocationEpoch
	}
	return VerifyEmergencyDenyList(&list, root, floor)
}

// EmergencyDenies reports whether ANY of the supplied tokens is in the verified
// emergency deny set. The consumers call this FIRST — before staleness, before
// risk, before the normal revocation set — so a compromise event denies on sight
// regardless of snapshot freshness or action risk. Tokens are normalized to
// match the set's keying (trim+lower).
func EmergencyDenies(set map[string]struct{}, tokens ...string) (string, bool) {
	if len(set) == 0 {
		return "", false
	}
	for _, tok := range tokens {
		key := strings.ToLower(strings.TrimSpace(tok))
		if key == "" {
			continue
		}
		if _, bad := set[key]; bad {
			return key, true
		}
	}
	return "", false
}
