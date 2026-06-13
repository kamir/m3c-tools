package registry

// attestation_stash.go — SPEC-0266 F2/F19: re-anchor the self/ER1 sidecar gate
// to the PINNED key by stashing the SIGNED attestation context at install and
// replaying the pull gates at runtime.
//
// The provenance sidecar (.m3c-provenance.json) records only fingerprints +
// governance, with NO signature bytes — so the runtime gate could prove the
// on-disk body matched the stashed .skb (content-binding) but NOT that the
// stashed .skb was the one a pinned key signed. A local-write attacker who
// repacks a self-consistent .skb + sidecar (and flips governance) therefore
// passed. This stash carries the actual SIGNED events so the gate re-verifies
// against the pinned key — exactly the pull-time gates, minus the network.
//
// VerifyEnvelopeSignature verifies over CanonicalEventBytes(map), not raw JSON,
// so storing the parsed event and re-parsing after a JSON round-trip is safe.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// AttestationStashName is the per-skill signed-context stash filename.
const AttestationStashName = ".skillctl-attest.json"

// ErrNoAttestationStash means the install predates the F2 re-anchor (or the
// stash was removed): the caller falls back to content-binding + a WARN.
var ErrNoAttestationStash = errors.New("no stashed attestation context (.skillctl-attest.json)")

// ErrAttestationReanchor is the umbrella error for a failed runtime re-anchor;
// it wraps the specific gate failure. Maps to a verify digest/signature error
// at the gate (deny).
var ErrAttestationReanchor = errors.New("attestation re-anchor failed")

// AttestationContext is the SIGNED context stashed at install so the runtime
// gate can re-verify against the pinned key with no network.
type AttestationContext struct {
	// AdmitEvent is the bundle admit event: envelope_signature + bundle
	// signatures[] (author + registry), all over the bundle_digest.
	AdmitEvent map[string]any `json:"admit_event"`
	// GovernanceAttestation is the latest envelope-signed attestation event for
	// the SAME digest; its governance_level is the authentic, non-forgeable
	// governance verdict (replaces the unsigned sidecar field — F19).
	GovernanceAttestation map[string]any `json:"governance_attestation"`
}

// WriteAttestationStash writes the signed context into the installed dir.
func WriteAttestationStash(dir string, ctx *AttestationContext) error {
	if ctx == nil {
		return errors.New("attestation stash: nil context")
	}
	b, err := json.MarshalIndent(ctx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, AttestationStashName), b, 0o644)
}

// ReadAttestationStash reads the signed context back. Returns
// ErrNoAttestationStash when absent (legacy install).
func ReadAttestationStash(dir string) (*AttestationContext, error) {
	b, err := os.ReadFile(filepath.Join(dir, AttestationStashName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoAttestationStash
	}
	if err != nil {
		return nil, err
	}
	var ctx AttestationContext
	if err := json.Unmarshal(b, &ctx); err != nil {
		return nil, fmt.Errorf("attestation stash parse: %w", err)
	}
	if ctx.AdmitEvent == nil {
		return nil, ErrNoAttestationStash
	}
	return &ctx, nil
}

// Reverify replays the pull gates against the PINNED public key, with no
// network, and returns the cryptographically-verified governance level.
//
//   - G1: the admit event's envelope_signature verifies against `pub`.
//   - G2: sha256(stashedSkb) equals the signed bundle_digest.
//   - G3: the admit event's author+registry signatures verify against `pub`.
//   - G4: the governance attestation's envelope verifies against `pub`, it is
//     bound to the SAME digest, and we return its governance_level.
//
// Any failure wraps ErrAttestationReanchor. The caller checks the returned
// level against the governance floor (it already owns that logic) and fails
// closed on a low level. A repacked .skb fails G1/G2/G3 (no valid signature
// over the new bytes); a flipped governance level in the sidecar is irrelevant
// because the level comes from the SIGNED attestation here.
func (c *AttestationContext) Reverify(pub ed25519.PublicKey, stashedSkb []byte) (string, error) {
	if c == nil || c.AdmitEvent == nil {
		return "", fmt.Errorf("%w: missing admit event", ErrAttestationReanchor)
	}
	// G1: admit envelope signature.
	if err := VerifyEnvelopeSignature(pub, c.AdmitEvent); err != nil {
		return "", fmt.Errorf("%w: admit envelope: %v", ErrAttestationReanchor, err)
	}
	signedDigest, _ := c.AdmitEvent["bundle_digest"].(string)
	if signedDigest == "" {
		return "", fmt.Errorf("%w: admit event has no bundle_digest", ErrAttestationReanchor)
	}
	// G2: the stashed .skb must hash to the signed digest.
	got := "sha256:" + hex.EncodeToString(sha256Sum(stashedSkb))
	if got != signedDigest {
		return "", fmt.Errorf("%w: stashed .skb digest %s != signed %s (repacked bundle)", ErrAttestationReanchor, got, signedDigest)
	}
	// G3: author + registry signatures over the RECOMPUTED digest (F4/F9 — `got`
	// is sha256(stashedSkb), already asserted == signedDigest at G2).
	if err := verifyBundleSignatures(c.AdmitEvent, pub, got); err != nil {
		return "", fmt.Errorf("%w: bundle signatures: %v", ErrAttestationReanchor, err)
	}
	// G4: governance from the SIGNED attestation (F19) — never the sidecar.
	if c.GovernanceAttestation == nil {
		return "", fmt.Errorf("%w: missing governance attestation", ErrAttestationReanchor)
	}
	if err := VerifyEnvelopeSignature(pub, c.GovernanceAttestation); err != nil {
		return "", fmt.Errorf("%w: governance envelope: %v", ErrAttestationReanchor, err)
	}
	govDigest, _ := c.GovernanceAttestation["bundle_digest"].(string)
	if govDigest != signedDigest {
		return "", fmt.Errorf("%w: governance attestation bound to %s, not %s", ErrAttestationReanchor, govDigest, signedDigest)
	}
	level, _ := c.GovernanceAttestation["governance_level"].(string)
	if level == "" {
		return "", fmt.Errorf("%w: governance attestation has no governance_level", ErrAttestationReanchor)
	}
	return level, nil
}
