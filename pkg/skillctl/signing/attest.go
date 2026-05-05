package signing

// Stream S9-cli (SPEC-0188 Phase 5). Governance attestation primitives:
// canonicalize a (bundle_digest, governance_level, attested_at, reviewer_id)
// tuple into the exact bytes that get signed, and run the ed25519 sign step.
//
// The canonical message format MUST stay byte-for-byte identical with the
// Python S9-aims half. Anything that changes the on-the-wire bytes (added
// fields, alternative whitespace, different timestamp precision) is a
// breaking change and must be coordinated across both repos.
//
// Format (UTF-8):
//
//	attestation\n
//	<bundle_digest>\n            sha256:<64 lowercase hex>
//	<governance_level>\n         green | yellow | red
//	<attested_at>\n              RFC 3339 UTC seconds: 2026-05-05T19:30:00Z
//	<reviewer_id>\n              non-empty, no embedded LF
//
// Notes:
//   - First line is the literal domain separator "attestation". This stops
//     a future signer from accidentally producing a tuple that matches a
//     different-purpose message format under the same key.
//   - Rationale is intentionally NOT folded in. It's audit metadata only;
//     mirroring SPEC §4.3 "(bundle_digest, governance_level, review_timestamp,
//     reviewer_identity)". A reviewer can edit a typo in their rationale
//     post-hoc without invalidating the cryptographic verdict.
//   - Final byte is \n. No trailing field after reviewer_id; no terminator
//     separator beyond it.

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// AttestationDomain is the literal first line of the canonical message.
// Acts as a domain separator so an ed25519 key used for attestations can
// never produce bytes that overlap with a different message family that
// happens to start with a digest.
const AttestationDomain = "attestation"

// AttestationTimestampLayout is the exact format we write attested_at in.
// RFC 3339, UTC, second precision, "Z" suffix. No fractional seconds, no
// numeric offset — those would change the byte length and break parity
// with the Python serializer.
const AttestationTimestampLayout = "2006-01-02T15:04:05Z"

// digestPattern matches the canonical bundle digest form.
//
// Lowercase hex only — Go's hex.EncodeToString already returns lowercase,
// but a caller could feed us any string. Reject mixed-case to keep the
// canonical bytes deterministic.
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// timestampPattern matches the wire form of attested_at exactly. We keep
// it tighter than what time.Parse would accept: no fractional seconds, no
// offset besides Z.
var timestampPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)

// validGovernanceLevels is the closed set of Ampel verdicts. Any string
// outside this set is rejected before we sign anything.
var validGovernanceLevels = map[string]struct{}{
	"green":  {},
	"yellow": {},
	"red":    {},
}

// FormatAttestationTimestamp renders t as the canonical attested_at string.
// Truncates to seconds (fractional seconds would break byte equality with
// the Python serializer, which has no sub-second component) and forces UTC.
func FormatAttestationTimestamp(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format(AttestationTimestampLayout)
}

// CanonicalizeAttestationMessage returns the exact bytes that will be
// signed for a governance attestation. Performs strict input validation
// BEFORE assembling — a malformed CLI invocation should never produce a
// signature over malformed bytes.
//
// On any validation failure the returned []byte is nil and err is set.
func CanonicalizeAttestationMessage(bundleDigest, governanceLevel, attestedAtISO, reviewerID string) ([]byte, error) {
	if !digestPattern.MatchString(bundleDigest) {
		return nil, fmt.Errorf("attestation: invalid bundle digest %q (want sha256:<64 lowercase hex>)", bundleDigest)
	}
	if _, ok := validGovernanceLevels[governanceLevel]; !ok {
		return nil, fmt.Errorf("attestation: invalid governance level %q (want green|yellow|red)", governanceLevel)
	}
	if !timestampPattern.MatchString(attestedAtISO) {
		return nil, fmt.Errorf("attestation: invalid attested_at %q (want RFC3339 UTC seconds, e.g. 2026-05-05T19:30:00Z)", attestedAtISO)
	}
	if reviewerID == "" {
		return nil, errors.New("attestation: reviewer_id must not be empty")
	}
	if strings.ContainsAny(reviewerID, "\n\r") {
		// CR is rejected too — even though our format uses LF only, a
		// stray CR would corrupt cross-platform byte equality.
		return nil, errors.New("attestation: reviewer_id must not contain newline characters")
	}

	// Assemble. We build via a byte slice rather than fmt.Sprintf to
	// keep the format obviously trivial — there are no escape sequences,
	// no width specifiers, just literal concatenation with single \n.
	var b strings.Builder
	// Pre-size: 11 + 1 + len(digest) + 1 + len(level) + 1 + len(ts) + 1 + len(rid) + 1.
	b.Grow(len(AttestationDomain) + 4 + len(bundleDigest) + len(governanceLevel) + len(attestedAtISO) + len(reviewerID))
	b.WriteString(AttestationDomain)
	b.WriteByte('\n')
	b.WriteString(bundleDigest)
	b.WriteByte('\n')
	b.WriteString(governanceLevel)
	b.WriteByte('\n')
	b.WriteString(attestedAtISO)
	b.WriteByte('\n')
	b.WriteString(reviewerID)
	b.WriteByte('\n')
	return []byte(b.String()), nil
}

// SignAttestation produces a 64-byte ed25519 detached signature over msg.
//
// Thin wrapper over crypto/ed25519.Sign so callers in cmd/skillctl don't
// need to import crypto/ed25519 directly. Stdlib ed25519 already runs in
// constant time; we don't add anything but a length assertion.
func SignAttestation(privKey ed25519.PrivateKey, msg []byte) []byte {
	sig := ed25519.Sign(privKey, msg)
	if len(sig) != ed25519.SignatureSize {
		// stdlib invariant; panicking here is correct — a wrong-length
		// signature returned silently would corrupt the registry.
		panic(fmt.Sprintf("attestation: ed25519.Sign returned %d bytes (want %d)", len(sig), ed25519.SignatureSize))
	}
	return sig
}
