package verify

// SPEC-0279 R4 — the signed FRESHNESS CHECKPOINT.
//
// A full revocation list can be large; re-downloading it just to PROVE the set
// is still current is wasteful, and an air-gapped verifier may not be able to at
// all. A FreshnessCheckpoint is a SHORT signed assertion — "the revocation set
// for registry R is current as of epoch E at time T" — signed by the SAME pinned
// registry key the revocation list uses. A verifier can pin/refresh a checkpoint
// INDEPENDENTLY of a full re-sync: a valid, fresh checkpoint whose epoch is ≥ the
// synced list's epoch RESETS THE STALENESS CLOCK (the snapshot is proven current
// as of the checkpoint's T) without re-downloading the whole list.
//
// Reuse, not new crypto: this mirrors RevocationList exactly — a struct-marshalled
// canonical payload, an ed25519 signature against the active pinned registry
// keys, the monotonic-epoch rollback floor — but with a DISTINCT domain-separator
// `type` ("skillctl-freshness-checkpoint") and a distinct first-line so a
// checkpoint signature can never be replayed as a revocation-list (or agent-list,
// or AgentID) signature, and vice-versa.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// FreshnessCheckpointType is the canonical type discriminator — the domain
// separator vs the revocation lists and the AgentID envelope. A signature over
// this type cannot be cross-replayed onto any other signed object in the stack.
const FreshnessCheckpointType = "skillctl-freshness-checkpoint"

// FreshnessCheckpoint is the on-disk, signed freshness assertion.
type FreshnessCheckpoint struct {
	// RegistryURL is the registry this checkpoint speaks for (signed; cannot be
	// retargeted without re-signing). Must match the revocation list's registry.
	RegistryURL string `json:"registry_url"`

	// Epoch is the revocation-set generation this checkpoint vouches for. A
	// checkpoint resets the staleness clock ONLY when its epoch ≥ the synced
	// list's epoch (it cannot vouch for a newer set than the verifier holds, and
	// the rollback floor still applies).
	Epoch int `json:"epoch"`

	// IssuedAt is the RFC3339 instant the checkpoint was signed. This is the NEW
	// staleness anchor: a fresh checkpoint moves the "current as of" time forward
	// without a list re-download.
	IssuedAt string `json:"issued_at"`

	// SignatureB64 is base64 of the raw 64-byte ed25519 signature over
	// CanonicalFreshnessCheckpointBytes(RegistryURL, Epoch, IssuedAt).
	SignatureB64 string `json:"signature_b64"`
}

// freshnessCheckpointCanonicalV1 is the deterministic, signed payload. A struct
// (not a map) so json.Marshal field order is fixed. The `type` differs from every
// other signed object so a signature is bound to THIS domain.
type freshnessCheckpointCanonicalV1 struct {
	Type        string `json:"type"`
	Version     int    `json:"version"`
	RegistryURL string `json:"registry_url"`
	Epoch       int    `json:"epoch"`
	IssuedAt    string `json:"issued_at"`
}

// CanonicalFreshnessCheckpointBytes returns the EXACT bytes signed/verified. The
// registry URL is trailing-slash-trimmed and the issued_at trimmed so signer and
// verifier agree byte-for-byte. A newline in a signed field is refused (it could
// forge a boundary in a future multi-line framing).
func CanonicalFreshnessCheckpointBytes(registryURL string, epoch int, issuedAt string) ([]byte, error) {
	registryURL = strings.TrimRight(strings.TrimSpace(registryURL), "/")
	issuedAt = strings.TrimSpace(issuedAt)
	if registryURL == "" {
		return nil, errors.New("freshness checkpoint: registry_url is required")
	}
	if issuedAt == "" {
		return nil, errors.New("freshness checkpoint: issued_at is required")
	}
	if strings.ContainsAny(registryURL+issuedAt, "\n\r") {
		return nil, errors.New("freshness checkpoint: field contains a newline; refusing to sign ambiguous bytes")
	}
	payload := freshnessCheckpointCanonicalV1{
		Type:        FreshnessCheckpointType,
		Version:     1,
		RegistryURL: registryURL,
		Epoch:       epoch,
		IssuedAt:    issuedAt,
	}
	return json.Marshal(payload)
}

// NewSignedFreshnessCheckpoint builds + signs a checkpoint with a registry
// private key. Mirrors NewSignedRevocationList exactly (no new crypto).
func NewSignedFreshnessCheckpoint(registryURL string, epoch int, issuedAt string, priv ed25519.PrivateKey) (*FreshnessCheckpoint, error) {
	canon, err := CanonicalFreshnessCheckpointBytes(registryURL, epoch, issuedAt)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, canon)
	return &FreshnessCheckpoint{
		RegistryURL:  strings.TrimRight(strings.TrimSpace(registryURL), "/"),
		Epoch:        epoch,
		IssuedAt:     strings.TrimSpace(issuedAt),
		SignatureB64: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// VerifyFreshnessCheckpoint checks the checkpoint's signature against an active
// registry key in root and enforces the rollback floor. Fail-closed (mirrors
// VerifyRevocationList): a signature matching no active key → ErrRegistryNotTrusted;
// an epoch below minEpoch → ErrRegistryNotTrusted (a forged/old checkpoint cannot
// reset the clock). Returns the checkpoint's IssuedAt (the new staleness anchor)
// on success.
func VerifyFreshnessCheckpoint(cp *FreshnessCheckpoint, root *TrustRoot, minEpoch int) (string, error) {
	if cp == nil {
		return "", fmt.Errorf("freshness checkpoint: nil: %w", ErrRegistryNotTrusted)
	}
	if root == nil {
		return "", errors.New("freshness checkpoint: nil trust root")
	}
	// The checkpoint must speak for the SAME registry as the pinned root —
	// otherwise a checkpoint for registry B (signed by B's key, which the operator
	// also pinned) could reset the clock for registry A's list.
	if strings.TrimRight(strings.TrimSpace(cp.RegistryURL), "/") != strings.TrimRight(strings.TrimSpace(root.RegistryURL), "/") {
		return "", fmt.Errorf("freshness checkpoint: registry %q != pinned root %q: %w", cp.RegistryURL, root.RegistryURL, ErrRegistryNotTrusted)
	}
	canon, err := CanonicalFreshnessCheckpointBytes(cp.RegistryURL, cp.Epoch, cp.IssuedAt)
	if err != nil {
		return "", err
	}
	sig, err := decodeSignatureB64(cp.SignatureB64)
	if err != nil {
		return "", fmt.Errorf("freshness checkpoint: decode signature: %w", errors.Join(ErrRegistryNotTrusted, err))
	}
	active := root.ActiveKeys()
	if len(active) == 0 {
		return "", fmt.Errorf("freshness checkpoint: trust root %s has no active registry keys: %w", root.RegistryURL, ErrRegistryNotTrusted)
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
		return "", fmt.Errorf("freshness checkpoint: signature did not match any active registry key in %s: %w", root.RegistryURL, ErrRegistryNotTrusted)
	}
	// Rollback floor (SPEC-0279 R1, shared with the lists): a checkpoint whose
	// epoch is below the pinned floor cannot reset the clock — an attacker cannot
	// replay an OLD signed checkpoint to vouch for a superseded epoch.
	if cp.Epoch < minEpoch {
		return "", fmt.Errorf("freshness checkpoint: epoch %d is below the pinned floor %d (rollback): %w", cp.Epoch, minEpoch, ErrRegistryNotTrusted)
	}
	return strings.TrimSpace(cp.IssuedAt), nil
}

// ApplyCheckpoint resolves the EFFECTIVE staleness anchor for a synced revocation
// list given an OPTIONAL signed checkpoint. This is the R4 "reset the staleness
// clock" rule, fail-closed by construction:
//
//   - no checkpoint                       → the list's own issued_at (unchanged).
//   - checkpoint present, but it fails to
//     verify / epoch < floor              → ERROR (caller fails closed; a forged or
//     rolled-back checkpoint must NOT silently
//     fall back to the list's older anchor —
//     that would let an attacker who plants a
//     bad checkpoint avoid detection).
//   - checkpoint valid but epoch <
//     syncedEpoch                         → list's issued_at (the checkpoint vouches
//     for an OLDER set than we hold; it cannot
//     move the clock forward, but it is not an
//     attack — just stale, so we ignore it).
//   - checkpoint valid AND epoch ≥
//     syncedEpoch                         → the checkpoint's issued_at, and the later
//     of (checkpoint, list) wins so a checkpoint
//     never moves the anchor BACKWARD.
//
// Returns (effectiveIssuedAt, checkpointApplied, error). checkpointApplied is
// true only when the checkpoint actually advanced the anchor (for the audit
// record). minEpoch is the rollback floor.
func ApplyCheckpoint(listIssuedAt string, syncedEpoch int, cp *FreshnessCheckpoint, root *TrustRoot, minEpoch int) (string, bool, error) {
	if cp == nil {
		return strings.TrimSpace(listIssuedAt), false, nil
	}
	cpIssuedAt, err := VerifyFreshnessCheckpoint(cp, root, minEpoch)
	if err != nil {
		// A present-but-bad checkpoint is fail-closed: the operator placed it
		// deliberately, so a forged/rolled-back/wrong-registry checkpoint is an
		// ERROR, not a silent fallback to the (older) list anchor.
		return "", false, err
	}
	if cp.Epoch < syncedEpoch {
		// Valid, but vouches for an older set than we hold — cannot advance.
		return strings.TrimSpace(listIssuedAt), false, nil
	}
	// Valid + epoch ≥ synced: use the LATER of (checkpoint, list) so the anchor
	// only ever moves forward (a checkpoint cannot age the snapshot artificially).
	listT, listOK := parseRFC3339OrZero(listIssuedAt)
	cpT, cpOK := parseRFC3339OrZero(cpIssuedAt)
	switch {
	case cpOK && listOK:
		if cpT.After(listT) {
			return cpIssuedAt, true, nil
		}
		return strings.TrimSpace(listIssuedAt), false, nil
	case cpOK:
		// List anchor unparseable; the checkpoint provides the only honest time.
		return cpIssuedAt, true, nil
	default:
		return strings.TrimSpace(listIssuedAt), false, nil
	}
}

// parseRFC3339OrZero parses an RFC3339 timestamp, reporting ok=false on failure.
func parseRFC3339OrZero(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
