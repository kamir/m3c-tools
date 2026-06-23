package verify

// SPEC-0277 P1 — signed, offline-distributable AGENT revocation list.
//
// This is the agent-instance analogue of the SPEC-0276 bundle RevocationList in
// revocation.go. It REUSES that exact pattern — a struct-marshalled canonical
// payload, an ed25519 signature verified against the SAME pinned registry keys
// that admit bundles, a monotonic Epoch rollback floor, and fail-closed
// semantics (a forged/unsigned list cannot block or silently fail-open) — but
// keys the revoked set by `agent:<id>` instead of `sha256:<hex>`.
//
// Why a sibling type rather than reusing RevocationList verbatim: the bundle
// list's normalizeDigests enforces sha256:<64hex> entries (correct for bundle
// digests). Agent ids are an opaque `agent:<id>` scheme, so reusing that
// validator would either reject agent ids or require weakening the digest check
// for bundles. A 30-line sibling that shares the canonical+signature SHAPE is the
// faithful "reuse the pattern, don't weaken the bundle validator" choice.

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

// AgentRevocationList is the on-disk, signed agent-revocation snapshot. Same
// field layout as RevocationList so the JSON is familiar; RevokedAgents carries
// `agent:<id>` entries.
type AgentRevocationList struct {
	// RegistryURL is the registry this list speaks for. Signed, so it cannot be
	// retargeted without re-signing.
	RegistryURL string `json:"registry_url"`

	// RevokedAgents is the set of revoked agent ids, each "agent:<id>".
	RevokedAgents []string `json:"revoked_agents"`

	// IssuedAt is the RFC3339 timestamp the list was signed (advisory).
	IssuedAt string `json:"issued_at"`

	// Epoch is a monotonic revocation generation (rollback floor, SPEC-0279 R1).
	Epoch int `json:"epoch,omitempty"`

	// SignatureB64 is base64 of the raw 64-byte ed25519 signature over
	// CanonicalAgentRevocationBytes(...).
	SignatureB64 string `json:"signature_b64"`
}

// agentRevocationCanonicalV1 is the deterministic, signed payload. A struct (not
// a map) so json.Marshal field order is fixed; agents are sorted+normalized
// before marshalling so the same logical list always yields the same bytes.
// The `type` differs from the bundle list ("skillctl-agent-revocation-list" vs
// "skillctl-revocation-list") so a bundle-list signature can never be replayed
// as an agent-list signature, and vice-versa (domain separation).
type agentRevocationCanonicalV1 struct {
	Type          string   `json:"type"`
	Version       int      `json:"version"`
	RegistryURL   string   `json:"registry_url"`
	IssuedAt      string   `json:"issued_at"`
	Epoch         int      `json:"epoch"`
	RevokedAgents []string `json:"revoked_agents"`
}

// AgentRevocationType is the canonical type discriminator (the domain separator
// vs the bundle revocation list).
const AgentRevocationType = "skillctl-agent-revocation-list"

// CanonicalAgentRevocationBytes returns the exact bytes that are signed/verified.
// Agent ids are trimmed, lowercased, de-duplicated and sorted so signer and
// verifier agree regardless of input order or case. Each must be a non-empty
// `agent:<id>` (the scheme guard) so a bundle digest cannot accidentally land in
// an agent list.
func CanonicalAgentRevocationBytes(registryURL, issuedAt string, epoch int, agents []string) ([]byte, error) {
	norm, err := normalizeAgentIDs(agents)
	if err != nil {
		return nil, err
	}
	payload := agentRevocationCanonicalV1{
		Type:          AgentRevocationType,
		Version:       1,
		RegistryURL:   strings.TrimRight(strings.TrimSpace(registryURL), "/"),
		IssuedAt:      strings.TrimSpace(issuedAt),
		Epoch:         epoch,
		RevokedAgents: norm,
	}
	return json.Marshal(payload)
}

// normalizeAgentIDs validates (each must start with "agent:"), lowercases,
// de-dups and sorts an agent-id list.
func normalizeAgentIDs(agents []string) ([]string, error) {
	seen := make(map[string]struct{}, len(agents))
	out := make([]string, 0, len(agents))
	for _, a := range agents {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" {
			continue
		}
		if !strings.HasPrefix(a, "agent:") || len(a) <= len("agent:") {
			return nil, fmt.Errorf("agent revocation list: invalid agent id %q (want agent:<id>)", a)
		}
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	sort.Strings(out)
	return out, nil
}

// NewSignedAgentRevocationList builds and signs an AgentRevocationList with a
// registry private key. Mirrors NewSignedRevocationList exactly.
func NewSignedAgentRevocationList(registryURL, issuedAt string, epoch int, agents []string, priv ed25519.PrivateKey) (*AgentRevocationList, error) {
	canon, err := CanonicalAgentRevocationBytes(registryURL, issuedAt, epoch, agents)
	if err != nil {
		return nil, err
	}
	norm, _ := normalizeAgentIDs(agents) // already validated above
	sig := ed25519.Sign(priv, canon)
	return &AgentRevocationList{
		RegistryURL:   strings.TrimRight(strings.TrimSpace(registryURL), "/"),
		RevokedAgents: norm,
		IssuedAt:      strings.TrimSpace(issuedAt),
		Epoch:         epoch,
		SignatureB64:  base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// VerifyAgentRevocationList checks the list's signature against an active
// registry key in root and returns the set of revoked agent ids (lowercased).
// Fail-closed (mirrors VerifyRevocationList): a list whose signature matches no
// active key returns ErrRegistryNotTrusted; a list whose epoch is below the
// pinned floor is refused even if its signature is valid (rollback protection).
func VerifyAgentRevocationList(list *AgentRevocationList, root *TrustRoot, minEpoch int) (map[string]struct{}, error) {
	if list == nil {
		return nil, fmt.Errorf("agent revocation list: nil: %w", ErrRegistryNotTrusted)
	}
	if root == nil {
		return nil, errors.New("agent revocation list: nil trust root")
	}
	canon, err := CanonicalAgentRevocationBytes(list.RegistryURL, list.IssuedAt, list.Epoch, list.RevokedAgents)
	if err != nil {
		return nil, err
	}
	sig, err := decodeSignatureB64(list.SignatureB64)
	if err != nil {
		return nil, fmt.Errorf("agent revocation list: decode signature: %w", errors.Join(ErrRegistryNotTrusted, err))
	}
	active := root.ActiveKeys()
	if len(active) == 0 {
		return nil, fmt.Errorf("agent revocation list: trust root %s has no active registry keys: %w", root.RegistryURL, ErrRegistryNotTrusted)
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
		return nil, fmt.Errorf("agent revocation list: signature did not match any active registry key in %s: %w", root.RegistryURL, ErrRegistryNotTrusted)
	}
	if list.Epoch < minEpoch {
		return nil, fmt.Errorf("agent revocation list: epoch %d is below the pinned floor %d (rollback): %w", list.Epoch, minEpoch, ErrRegistryNotTrusted)
	}
	norm, err := normalizeAgentIDs(list.RevokedAgents)
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(norm))
	for _, a := range norm {
		set[a] = struct{}{}
	}
	return set, nil
}

// LoadVerifiedAgentRevocations reads a signed AgentRevocationList JSON file,
// verifies its signature against the pinned root (with the root's rollback
// floor), and returns the revoked agent-id set. The single read-+-verify entry
// point both the CLI verify path and the runtime gate use.
func LoadVerifiedAgentRevocations(path string, root *TrustRoot) (map[string]struct{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read agent revocations %s: %w", path, err)
	}
	var list AgentRevocationList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parse agent revocations %s: %w", path, err)
	}
	floor := 0
	if root != nil {
		floor = root.MinRevocationEpoch
	}
	return VerifyAgentRevocationList(&list, root, floor)
}
