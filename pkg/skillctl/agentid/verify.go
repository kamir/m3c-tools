package agentid

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Sentinel errors so callers can errors.Is() and the CLI can map to the
// SPEC-0188 §11 numeric exit codes. The mapping is deliberately the SAME family
// the bundle verifier uses (so `agentid verify` mirrors `verify --bundle`):
//
//	ErrOwnerSigInvalid     → exit 11 (ExitAuthorSigInvalid) — owner sig failed
//	                          OR owner identity not pinned (AC-P0: exit 11).
//	ErrApproverFloor       → exit 20 (ExitSelfAttested theme) — the
//	                          require_agent_approver floor is unmet (no approver,
//	                          or approver == owner). Reuses the reviewer≠author
//	                          family so the "two-person admit" gate reads the same.
//	ErrExpired             → a DISTINCT code (ExitAgentIDExpired, 21) so the
//	                          operator can tell "expired" from "bad signature".
//	ErrRevoked             → exit 17 (the SPEC-0198 revoke theme; same as a
//	                          revoked bundle).
//	ErrNotYetValid         → ErrExpired's sibling (created_at in the future) —
//	                          also mapped to ExitAgentIDExpired (a clock/validity
//	                          problem, not a signature problem).
var (
	// ErrOwnerSigInvalid — the owner ed25519 signature did not verify against
	// the PINNED owner key, OR the owner identity is not pinned at all. Both are
	// "this mandate is not authorized by a key I trust" → exit 11.
	ErrOwnerSigInvalid = errors.New("agentid: owner signature invalid or owner not pinned")

	// ErrApproverFloor — a require_agent_approver policy floor is set but the
	// AgentID lacks a valid, independent (approver != owner) approver signature.
	ErrApproverFloor = errors.New("agentid: approver floor unmet (require owner+approver, approver != owner, both pinned)")

	// ErrExpired — not_after is in the past (or created_at is in the future). A
	// DISTINCT error from a signature failure (AC-P0).
	ErrExpired = errors.New("agentid: expired (not_after is in the past)")

	// ErrNotYetValid — created_at is in the future relative to now. Same code
	// family as ErrExpired (a validity-window problem).
	ErrNotYetValid = errors.New("agentid: not yet valid (created_at is in the future)")

	// ErrRevoked — the agent id is present in the signed revocation list.
	ErrRevoked = errors.New("agentid: revoked")

	// ErrMalformed — the envelope is structurally broken (missing required
	// signature row, malformed base64, etc.).
	ErrMalformed = errors.New("agentid: malformed envelope")
)

// PinnedKey is one pinned principal: an identity id bound to a raw ed25519
// pubkey. The CLI adapts verify.TrustRoot's Authors/Reviewers lists into these
// (the SAME pins that admit bundles) — this package never reaches for a registry
// or a network, so the owner key is pinned, not fetched (SPEC-0277 §3 reuse map).
type PinnedKey struct {
	// ID is the principal identity id, e.g. "id:kamir@m3c". Matched case-
	// normalized (NormalizeID) so a re-cased id cannot dodge or impersonate a pin.
	ID string

	// Pubkey is the raw 32-byte ed25519 public key.
	Pubkey []byte
}

// PinnedKeys resolves a principal id to its pinned ed25519 key for a given role.
// FindOwner / FindApprover GENERALIZE the verified role from `author` (the only
// role the bundle verifier knew) to the AgentID roles — without forking the
// verifier: the CLI's adapter simply maps `owner` → the pinned authors list and
// `approver` → the pinned reviewers list, reusing FindAuthor/FindReviewer.
type PinnedKeys interface {
	// FindOwner returns the active pinned key for an owner principal, or nil if
	// not pinned (or retired). NEVER returns a key resolved from a network.
	FindOwner(id string) *PinnedKey

	// FindApprover returns the active pinned key for an approver principal, or
	// nil. Used only when the approver floor is engaged.
	FindApprover(id string) *PinnedKey
}

// VerifyOpts is the input bag for Verify. Keeping it a struct keeps the call
// sites readable and lets new policy knobs (P2 issuer countersign, etc.) land
// without breaking the signature.
type VerifyOpts struct {
	// Pins resolves pinned owner/approver keys. Required.
	Pins PinnedKeys

	// Now is the verification instant for the expiry/validity check. Zero means
	// "use the package clock" (time.Now); tests pin it.
	Now time.Time

	// RequireApprover engages the SPEC-0277 §11.2/§11.5 sign-off floor: the
	// AgentID MUST carry an owner signature AND an approver signature, with
	// approver != owner (separation of duty), BOTH pinned and BOTH cryptographically
	// verified. An owner-only AgentID is refused with ErrApproverFloor. This is
	// the trust-roots `require_agent_approver: true` floor.
	RequireApprover bool

	// RevokedAgentIDs, if non-nil, is the set of revoked agent ids (already
	// verified against a signed revocation list by the caller, keyed agent:<id>,
	// lowercased). A hit → ErrRevoked. Enforced OFFLINE.
	RevokedAgentIDs map[string]struct{}
}

// Result is the successful-verification summary (the material `agentid verify`
// prints and the gate consults).
type Result struct {
	// AgentID is the verified agent id (the value stamped into invocation events).
	AgentID string

	// Owner is the verified owner principal id.
	Owner string

	// ApproverVerified reports whether an independent approver signature was
	// cryptographically verified (true when the floor was met, or when an
	// approver signature was present and valid even without the floor).
	ApproverVerified bool

	// Approver is the verified approver principal id ("" when none).
	Approver string

	// Grant is the attenuated capability grant the gate authorizes against.
	Grant Grant

	// NotAfter is the parsed expiry (zero = no expiry), for the summary.
	NotAfter time.Time
}

// Verify runs the offline AgentID verification algorithm against PINNED keys,
// short-circuiting on the first failure so the highest-priority sentinel
// surfaces. Fixed order:
//
//  1. structural: exactly one owner signature row, non-empty id/owner.
//  2. owner signature: recompute canonical bytes, ed25519.Verify against the
//     PINNED owner key (NOT a fetched key). Owner-not-pinned OR bad sig →
//     ErrOwnerSigInvalid (exit 11).
//  3. approver floor (when RequireApprover): an approver signature must exist,
//     verify against the PINNED approver key, and approver != owner (normalized).
//     The unsigned `identity_id` is NEVER trusted to satisfy the floor — the
//     approver key must be pinned AND verify, exactly like the SPEC-0246/0281
//     reviewer≠author machinery. Unmet → ErrApproverFloor (exit 20).
//  4. validity window: created_at not in the future, not_after not in the past.
//     A clock failure → ErrExpired / ErrNotYetValid (distinct code).
//  5. revocation: id present in RevokedAgentIDs → ErrRevoked (exit 17).
//
// Steps 2/3 reuse stdlib ed25519 + the pinned-identity lookup — NO new crypto,
// NO network. The role is parameterized (owner / approver) so the same verifier
// covers both without forking.
func Verify(a *AgentID, opts VerifyOpts) (*Result, error) {
	if a == nil {
		return nil, fmt.Errorf("%w: nil AgentID", ErrMalformed)
	}
	if opts.Pins == nil {
		return nil, errors.New("agentid: Verify requires pinned keys")
	}

	// Step 1 — structure. Exactly one owner row; payload id/owner present.
	canon, err := CanonicalAgentIDBytes(a.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	ownerRow := a.FindSignature(RoleOwner)
	if ownerRow == nil {
		return nil, fmt.Errorf("%w: want exactly one owner signature row", ErrOwnerSigInvalid)
	}
	if !strings.EqualFold(strings.TrimSpace(ownerRow.IdentityID), strings.TrimSpace(a.Payload.Owner)) {
		// The owner SIGNATURE row's identity must be the payload owner — otherwise
		// a valid signature by some other pinned principal could masquerade as the
		// owner's authorization.
		return nil, fmt.Errorf("%w: owner signature identity %q != payload owner %q",
			ErrOwnerSigInvalid, ownerRow.IdentityID, a.Payload.Owner)
	}

	// Step 2 — owner signature vs PINNED owner key (offline, no fetch).
	ownerPin := opts.Pins.FindOwner(ownerRow.IdentityID)
	if ownerPin == nil {
		return nil, fmt.Errorf("%w: owner %q is not pinned", ErrOwnerSigInvalid, ownerRow.IdentityID)
	}
	if !verifyRow(canon, ownerRow, ownerPin) {
		return nil, fmt.Errorf("%w: ed25519 owner signature failed for pinned %q", ErrOwnerSigInvalid, ownerRow.IdentityID)
	}

	res := &Result{
		AgentID: strings.TrimSpace(a.Payload.ID),
		Owner:   strings.TrimSpace(a.Payload.Owner),
		Grant:   a.Payload.Grant,
	}

	// Step 3 — approver. Verify any present approver signature; ENFORCE the floor
	// when RequireApprover. Independence (approver != owner) is established
	// CRYPTOGRAPHICALLY: the approver key is pinned to its id AND verifies, so a
	// forged approver `identity_id` with no pinned key / valid signature cannot
	// satisfy the floor (the SPEC-0246/0281 fail-closed pattern).
	approverRow := a.FindSignature(RoleApprover)
	if approverRow != nil {
		approverPin := opts.Pins.FindApprover(approverRow.IdentityID)
		if approverPin != nil && verifyRow(canon, approverRow, approverPin) &&
			NormalizeID(approverRow.IdentityID) != NormalizeID(a.Payload.Owner) {
			res.ApproverVerified = true
			res.Approver = strings.TrimSpace(approverRow.IdentityID)
		}
	}
	if opts.RequireApprover && !res.ApproverVerified {
		// Distinguish the failure modes in the message so the operator can act.
		switch {
		case approverRow == nil:
			return nil, fmt.Errorf("%w: no approver signature (owner-only AgentID refused under require_agent_approver)", ErrApproverFloor)
		case NormalizeID(approverRow.IdentityID) == NormalizeID(a.Payload.Owner):
			return nil, fmt.Errorf("%w: approver %q == owner (separation of duty requires approver != owner)", ErrApproverFloor, approverRow.IdentityID)
		default:
			return nil, fmt.Errorf("%w: approver %q is not pinned or its signature failed", ErrApproverFloor, approverRow.IdentityID)
		}
	}

	// Step 4 — validity window.
	now := opts.Now
	if now.IsZero() {
		now = nowFn()
	}
	now = now.UTC()
	createdAt, err := ParseRFC3339UTC(a.Payload.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if !createdAt.IsZero() && createdAt.After(now) {
		return nil, fmt.Errorf("%w: created_at=%s now=%s", ErrNotYetValid, a.Payload.CreatedAt, now.Format(time.RFC3339))
	}
	notAfter, err := ParseRFC3339UTC(a.Payload.NotAfter)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if !notAfter.IsZero() {
		res.NotAfter = notAfter
		if now.After(notAfter) {
			return nil, fmt.Errorf("%w: not_after=%s now=%s", ErrExpired, a.Payload.NotAfter, now.Format(time.RFC3339))
		}
	}

	// Step 5 — revocation (offline).
	if opts.RevokedAgentIDs != nil {
		if _, bad := opts.RevokedAgentIDs[NormalizeID(a.Payload.ID)]; bad {
			return nil, fmt.Errorf("%w: %s is in the signed revocation list", ErrRevoked, a.Payload.ID)
		}
	}

	return res, nil
}

// verifyRow decodes a signature row's base64 signature and ed25519-verifies it
// against a pinned key over canon. Fail-closed: any decode/length problem is a
// non-verify, never a partial accept.
func verifyRow(canon []byte, row *Signature, pin *PinnedKey) bool {
	if row == nil || pin == nil || len(pin.Pubkey) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(row.SignatureB64))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pin.Pubkey), canon, sig)
}

// NormalizeID canonicalizes a principal/agent id for comparison (trim +
// lowercase), so a re-cased id cannot dodge the approver != owner check or the
// revocation lookup. Matches verify.normalizeIdentityID.
func NormalizeID(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}

// fingerprint returns "sha256:<hex>" over raw pubkey bytes. Same derivation as
// verify.authorFingerprint so an operator can cross-check across tools.
func fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, len("sha256:")+len(sum)*2)
	out = append(out, "sha256:"...)
	for _, b := range sum {
		out = append(out, hexd[b>>4], hexd[b&0x0f])
	}
	return string(out)
}
