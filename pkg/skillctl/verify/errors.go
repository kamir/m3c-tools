// Package verify implements the SPEC-0188 client-side verifier algorithm
// and its supporting primitives.
//
// Stream S7 (this commit) ships ONLY the scaffolding pieces that S8 will
// compose into the full Verify algorithm:
//
//	errors.go      — numbered exit-code sentinels (per SPEC §11)
//	trustroots.go  — ~/.claude/skill-trust-roots.yaml loader + writer
//
// The Verify algorithm itself (verify.go) and the install pipeline
// (../install/install.go) are deliberately NOT in this commit — those are
// owned by stream S8. S7's contract is "the parts S8 will reach for."
package verify

import "errors"

// Exit codes reserved by SPEC-0188 §11.
//
// These constants are also documented in `skillctl --help` (cmd/skillctl)
// so CI consumers can branch deterministically on a numeric code without
// parsing stderr. Adding a new failure mode means adding both a sentinel
// here AND a numeric mapping in ExitCode below — keep them in sync.
//
// Generic codes 0/1/2 already live in cmd/skillctl/signing_cmds.go and are
// re-stated here for completeness; we intentionally do NOT redefine them
// in this package to avoid a duplicate-symbol drift across packages. (See
// ExitCode for how nil and unknown errors map.)
const (
	// ExitDigestMismatch — recomputed bundle digest did not match the
	// digest the registry signed.
	ExitDigestMismatch = 10
	// ExitAuthorSigInvalid — the author's ed25519 signature did not
	// verify against the identity's public key.
	ExitAuthorSigInvalid = 11
	// ExitRegistryNotTrusted — the bundle came from a registry whose
	// public key isn't in ~/.claude/skill-trust-roots.yaml (or the key
	// that signed is retired).
	ExitRegistryNotTrusted = 12
	// ExitGovernanceBelowMin — the bundle's current governance level
	// is below trust-roots.yaml's `governance_minimum`.
	ExitGovernanceBelowMin = 13
	// ExitDepsUnsatisfied — depends_on resolution failed (missing
	// Python wheel, system tool, or a depended-on skill version).
	ExitDepsUnsatisfied = 14
	// ExitBlobMissing — the registry has metadata for a digest but
	// the actual blob is unreachable.
	ExitBlobMissing = 15
)

// Sentinel errors so callers can `errors.Is(err, verify.ErrDigestMismatch)`
// without parsing strings. Each sentinel maps 1:1 to a numbered exit code
// (see ExitCode).
//
// Wrap them with `fmt.Errorf("…: %w", verify.ErrXxx)` to add context — the
// CLI translates to the numeric exit code via errors.Is so wrapped errors
// continue to work.
var (
	// ErrDigestMismatch — the bundle's recomputed digest doesn't match
	// what the signature was over. Exit code 10.
	ErrDigestMismatch = errors.New("digest mismatch")

	// ErrAuthorSigInvalid — ed25519 author signature failed crypto
	// verification. Exit code 11.
	//
	// Note: the lower-level `signing.ErrSignatureInvalid` (owned by S1)
	// is the authoritative crypto-level sentinel. Verify-layer code
	// SHOULD wrap that into ErrAuthorSigInvalid when the signature being
	// checked is the author's so the higher-level role context survives.
	ErrAuthorSigInvalid = errors.New("author signature invalid")

	// ErrRegistryNotTrusted — bundle came from a registry whose key
	// isn't pinned (or whose key is retired). Exit code 12.
	ErrRegistryNotTrusted = errors.New("registry not in trust roots")

	// ErrGovernanceBelowMin — bundle's governance level is below the
	// configured minimum. Exit code 13.
	ErrGovernanceBelowMin = errors.New("governance below minimum")

	// ErrDepsUnsatisfied — `depends_on` resolution failed. Exit code 14.
	ErrDepsUnsatisfied = errors.New("depends_on unsatisfied")

	// ErrBlobMissing — registry metadata exists but the blob storage
	// returned 404 / unreachable. Exit code 15.
	ErrBlobMissing = errors.New("blob missing")
)

// ExitCode maps a verifier error to its numeric process exit code.
//
//	nil                                  → 0
//	wrapped ErrDigestMismatch            → 10
//	wrapped ErrAuthorSigInvalid          → 11
//	wrapped ErrRegistryNotTrusted        → 12
//	wrapped ErrGovernanceBelowMin        → 13
//	wrapped ErrDepsUnsatisfied           → 14
//	wrapped ErrBlobMissing               → 15
//	any other non-nil error              → 1 (generic)
//
// We deliberately do NOT return 2 (usage) here — that's the CLI's concern,
// dispatched by flag parsing, not by error-typing.
//
// Order of checks matters only when sentinels are wrapped together (which
// they shouldn't be — one sentinel per failure). The order below follows
// the §7 verifier algorithm: digest before signature, signature before
// trust roots, trust roots before governance, governance before deps,
// deps before blob.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	switch {
	case errors.Is(err, ErrDigestMismatch):
		return ExitDigestMismatch
	case errors.Is(err, ErrAuthorSigInvalid):
		return ExitAuthorSigInvalid
	case errors.Is(err, ErrRegistryNotTrusted):
		return ExitRegistryNotTrusted
	case errors.Is(err, ErrGovernanceBelowMin):
		return ExitGovernanceBelowMin
	case errors.Is(err, ErrDepsUnsatisfied):
		return ExitDepsUnsatisfied
	case errors.Is(err, ErrBlobMissing):
		return ExitBlobMissing
	default:
		return 1
	}
}
