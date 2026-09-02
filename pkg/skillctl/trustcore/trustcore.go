// Package trustcore holds the SIGNED-envelope trust primitives shared by every
// artifact backend and by the pull / gossip / gauntlet paths (FR-0090).
//
// THE PRINCIPLE (reference_git_event_signed_identity): a trust decision may only
// read a lifecycle event's KIND and DIGEST from fields INSIDE the signed SPEC-0190
// envelope — never from an unsigned carrier projection (a git filename/dirname, an
// OCI referrer annotation, an ER1 skill-event tag). A hostile carrier can relabel
// those projections at will without breaking the ed25519 signature the §7 verifier
// re-checks; the signed discriminator fields (`revoked_by`, `reviewer_id`,
// `installed_on_host`, `admitted_by_identity`, `bundle_digest`) it CANNOT forge.
// Sourcing kind/digest from a projection would let a registry relabel a signed
// revoke ("revoked"→"installed") to SUPPRESS it, or rebind its digest to revoke an
// innocent skill. Centralising the derivation here means one audited definition,
// used identically by the OCI, git, and ER1 backends, the gossip union, and the
// pull gauntlet — so the carriers cannot drift.
//
// This package imports ONLY pkg/skillctl/artifact (itself a leaf), so it is safe
// for every backend and the registry/gossip layers to import without a cycle.
package trustcore

import (
	"regexp"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
)

// digestRe pins the canonical bundle-digest shape: "sha256:" + 64 lowercase hex.
// It matches the per-backend validators (backend/git, backend/oci, registry/event)
// so a trust decision keys only on a well-formed digest.
var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// KindFromSignedEnvelope classifies a lifecycle event purely from the SIGNED
// discriminator fields SPEC-0190's event builders set (event.go). The builders are
// mutually exclusive — an admit carries `admitted_by_identity`, an attestation
// `reviewer_id`(+`governance_level`), a revoke `revoked_by`, an install
// `installed_on_host` — so field presence is an unambiguous discriminator on any
// well-formed envelope.
//
// `revoked_by` is checked FIRST deliberately: a revoke takes precedence, so a
// degenerate/adversarial envelope that somehow carries a revoke field alongside
// another is treated as a revocation (fail-safe toward DENY, never toward trust).
// An envelope with NONE of the discriminators is unclassifiable and returns ""
// (the caller drops it — it never influences a verdict).
func KindFromSignedEnvelope(env map[string]any) artifact.EventKind {
	switch {
	case envHas(env, "revoked_by"):
		return artifact.KindRevoke
	case envHas(env, "reviewer_id"):
		return artifact.KindAttest
	case envHas(env, "installed_on_host"):
		return artifact.KindInstall
	case envHas(env, "admitted_by_identity"):
		return artifact.KindAdmit
	}
	return ""
}

// SignedDigest returns the `bundle_digest` carried INSIDE the signed envelope, or
// "" when absent/blank/non-string. This is the ONLY digest a trust decision may
// key on — never a carrier-supplied dir/tag/annotation digest. Callers that gate
// on it should additionally require ValidDigest.
func SignedDigest(env map[string]any) string {
	if env == nil {
		return ""
	}
	s, _ := env["bundle_digest"].(string)
	return s
}

// ValidDigest reports whether s is a well-formed sha256:<64 lowercase hex> digest.
func ValidDigest(s string) bool { return digestRe.MatchString(s) }

// envHas reports whether m carries a present, non-nil key k whose value — when it
// is a string — is non-empty. A present non-string value counts as present (the
// discriminators are always strings in practice; this only guards the empty-string
// carrier case so `{"revoked_by": ""}` is treated as ABSENT, not a revoke).
func envHas(m map[string]any, k string) bool {
	if m == nil {
		return false
	}
	v, ok := m[k]
	if !ok || v == nil {
		return false
	}
	s, isStr := v.(string)
	return !isStr || s != ""
}
