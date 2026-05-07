package signing

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
)

// SPEC-0188 §4.5 revocation signing primitives.
//
// Three actor roles produce ONE signed message shape:
//
//     revoke\n
//     <bundle_digest>\n
//     <revocation_timestamp_iso>\n
//     <actor_role>\n
//
// `revoke` is the domain separator (prevents a captured attestation /
// admit signature being replayed as a revoke). `<actor_role>` is bound
// INTO the message so a captured author signature cannot be replayed
// as a registry-operator revocation.
//
// MUST stay byte-identical to the Python `canonicalize_revocation_message`
// in aims-core skill_service.py (S3.6 closure 2026-05-06). Drift here =
// silent verification failure on the server. The cross-language test
// vector lives in revoke_test.go (mirroring the attest_test.go pattern).

// RevokeDomain is the first line of the canonical revocation message.
const RevokeDomain = "revoke"

// validRevocationActorRoles enumerates the SPEC-0188 §4.5 actor role
// strings that the canonical message accepts.
var validRevocationActorRoles = map[string]struct{}{
	"registry_operator":   {},
	"governance_reviewer": {},
	"original_author":     {},
}

// CanonicalizeRevocationMessage returns the exact bytes that will be
// signed for a bundle-revocation request. Strict input validation BEFORE
// assembly: a malformed CLI invocation must never produce an ed25519
// signature over malformed bytes.
//
// On any validation failure the returned []byte is nil and err is set.
func CanonicalizeRevocationMessage(bundleDigest, revocationTimestampISO, actorRole string) ([]byte, error) {
	if !digestPattern.MatchString(bundleDigest) {
		return nil, fmt.Errorf("revoke: invalid bundle digest %q (want sha256:<64 lowercase hex>)", bundleDigest)
	}
	if !timestampPattern.MatchString(revocationTimestampISO) {
		return nil, fmt.Errorf("revoke: invalid revocation_timestamp %q (want RFC3339 UTC seconds, e.g. 2026-05-06T15:04:13Z)", revocationTimestampISO)
	}
	if _, ok := validRevocationActorRoles[actorRole]; !ok {
		return nil, fmt.Errorf("revoke: invalid actor_role %q (want registry_operator|governance_reviewer|original_author)", actorRole)
	}
	if strings.ContainsAny(actorRole, "\n\r") {
		return nil, errors.New("revoke: actor_role must not contain newline characters")
	}

	var b strings.Builder
	b.Grow(len(RevokeDomain) + 4 + len(bundleDigest) + len(revocationTimestampISO) + len(actorRole))
	b.WriteString(RevokeDomain)
	b.WriteByte('\n')
	b.WriteString(bundleDigest)
	b.WriteByte('\n')
	b.WriteString(revocationTimestampISO)
	b.WriteByte('\n')
	b.WriteString(actorRole)
	b.WriteByte('\n')
	return []byte(b.String()), nil
}

// SignRevocation produces a 64-byte ed25519 detached signature over msg.
//
// Thin wrapper for cmd/skillctl callers; mirrors SignAttestation in
// shape. Stdlib ed25519 runs in constant time; we add only a length
// assertion to surface stdlib invariant violations loudly.
func SignRevocation(privKey ed25519.PrivateKey, msg []byte) []byte {
	sig := ed25519.Sign(privKey, msg)
	if len(sig) != ed25519.SignatureSize {
		panic(fmt.Sprintf("revoke: ed25519.Sign returned %d bytes (want %d)", len(sig), ed25519.SignatureSize))
	}
	return sig
}
