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
	// ExitDigestMismatch (10) — "Bundle modified after signing."
	// (SPEC-0188 §11 row 1)
	//
	// Returned when the recomputed bundle digest does not match the
	// digest the registry signed. UX: show expected vs actual digest;
	// refuse install. User remediation: re-fetch the bundle; do not
	// install a tampered artefact.
	ExitDigestMismatch = 10
	// ExitAuthorSigInvalid (11) — "Wrong public key, or modified after
	// signing." (SPEC-0188 §11 row 2)
	//
	// Returned when the author's ed25519 signature did not verify
	// against the identity's public key. UX: show author identity from
	// manifest vs registry; refuse. User remediation: confirm with the
	// author that their identity_id + pubkey on the registry are correct
	// and current; refuse install.
	ExitAuthorSigInvalid = 11
	// ExitRegistryNotTrusted (12) — "Bundle came from an unknown
	// registry." (SPEC-0188 §11 row 3)
	//
	// Returned when the bundle came from a registry whose public key
	// isn't in ~/.claude/skill-trust-roots.yaml (or the key that signed
	// is retired). UX: show registry key fingerprint; suggest
	// `skillctl trust add`.
	ExitRegistryNotTrusted = 12
	// ExitGovernanceBelowMin (13) — "Skill is 🟡 but trust-roots
	// requires 🟢." (SPEC-0188 §11 row 4)
	//
	// Returned when the bundle's current governance level is below
	// trust-roots.yaml's `governance_minimum`. UX: show current
	// attestations; suggest `skillctl install --allow-yellow` for an
	// explicit (audited) override.
	ExitGovernanceBelowMin = 13
	// ExitDepsUnsatisfied (14) — "Missing Python pkg or version
	// mismatch." (SPEC-0188 §11 row 5)
	//
	// Returned when depends_on resolution failed (missing Python wheel,
	// system tool, or a depended-on skill version). UX: show resolution
	// failure; suggest `pip install` or `--ignore-deps` for an explicit
	// (audited) override.
	ExitDepsUnsatisfied = 14
	// ExitBlobMissing (15) — registry advertised metadata for a digest
	// but the actual blob is unreachable, or the bundle's status is no
	// longer "admitted". (SPEC-0188 §11 — extension of the §11 table
	// for the §7 step-7 status check; covers blob 404, meta 404, and
	// status=revoked.)
	//
	// User remediation: refresh the registry view; if the bundle was
	// revoked the operator must contact the publisher.
	ExitBlobMissing = 15
	// ExitTenantBlocked (16) — at least one tenant-scoped governance
	// attestation (SPEC-0188 §7 step 5.5, G-18 closure 2026-05-06)
	// carries governance_level=red for the consumer's pinned tenant.
	//
	// The bundle is admitted globally but the tenant CISO has blocked
	// it; the verifier fails closed. UX: surface attestation_id +
	// reviewer_id so the operator can trace the block back to the
	// SPEC-0192 CISO console verdict.
	ExitTenantBlocked = 16

	// ExitIntentInconsistent (18) — SPEC-0196 §3.3 cross-rule fired
	// during a `skillctl intent declare` PATCH (S2.4).
	//
	// The PATCH endpoint validates the proposed `intent` block against
	// the bundle's existing `data_dependencies` using the same three
	// rules as the awareness admission path:
	//
	//   - destructive_green
	//   - network_false_http_dep
	//   - write_access_non_destructive
	//
	// On failure the registry returns HTTP 400 with
	//   {"reason": "intent_data_inconsistent", "failed_rule": "..."}.
	// The CLI surfaces this verbatim and exits 18 so CI can branch on
	// "the declaration was rejected by policy" without parsing stderr.
	//
	// Distinct from generic 1 (network/parse) and 2 (usage) — 18 means
	// "the SERVER said the declaration is internally inconsistent."
	ExitIntentInconsistent = 18

	// ExitIdentityMismatch (19) — `skillctl awareness reset` refused
	// because the calling client's identity does not match the identity
	// that admitted the session-tagged docs (SPEC-0195 §7, S2.2 Q3).
	//
	// The registry returns HTTP 403 with
	//   {"reason": "identity_mismatch", ...}
	// when `client_identity != admitted_by_identity`. The CLI surfaces
	// the conflict and exits 19. Operators with that need use the
	// standalone procedure (SKILLOR-WORK/s1) which is explicit about
	// the broader destructive intent.
	ExitIdentityMismatch = 19

	// ExitDataSourceDenied (17) — `skillctl install` refused because at
	// least one of the bundle's data_dependencies[].id is in the
	// `denied_skills[]` list of its `_data_sources` registry record for
	// the consumer's pinned tenant. SPEC-0196 §10 AC#5 (S5.3 closure
	// 2026-05-07).
	//
	// The CISO console (SPEC-0192 §5.2) writes the deny via
	// POST /api/skills/data-sources/<id>/authorize ; the verifier reads
	// it on every install. Distinct from ExitTenantBlocked (16, whole
	// bundle blocked) — 17 is per-data-source granularity.
	ExitDataSourceDenied = 17
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

	// ErrTenantBlocked — a tenant-scoped governance attestation set
	// governance_level=red for this bundle in the consumer's pinned
	// tenant. SPEC-0188 §7 step 5.5 (G-18 closure, 2026-05-06).
	// Exit code 16. The verifier MUST refuse the install/verify even
	// when the global chain validates; the tenant CISO's block decision
	// supersedes for THIS tenant only.
	ErrTenantBlocked = errors.New("tenant blocked by tenant-scoped attestation")

	// ErrIntentInconsistent — `skillctl intent declare` PATCH failed
	// SPEC-0196 §3.3 cross-rule validation server-side. Exit code 18.
	//
	// The wrapped error message MUST include the `failed_rule` token
	// returned by the registry (one of "destructive_green",
	// "network_false_http_dep", "write_access_non_destructive") so the
	// operator can correlate the rejection with the canonical rule
	// catalogue.
	ErrIntentInconsistent = errors.New("intent declaration inconsistent with data_dependencies")

	// ErrIdentityMismatch — `skillctl awareness reset` refused because
	// the registry detected `client_identity != admitted_by_identity`
	// for the targeted session_tag. Exit code 19. SPEC-0195 §7 (S2.2 Q3
	// closure 2026-05-06): cross-identity reset is forbidden on shared
	// registries; use the standalone broader-destructive procedure if
	// you really mean it.
	ErrIdentityMismatch = errors.New("identity mismatch on awareness reset")

	// ErrDataSourceDenied — at least one declared data_dependency was
	// denied for this skill in the consumer's pinned tenant. Exit code
	// 17. SPEC-0196 §10 AC#5 (S5.3 closure 2026-05-07). Wrap with the
	// offending `ds:...` id so the operator can correlate with the
	// CISO console chip:
	//
	//   fmt.Errorf("data_source %s denied for this tenant: %w",
	//       dsID, verify.ErrDataSourceDenied)
	ErrDataSourceDenied = errors.New("data_source denied for this tenant")
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
//	wrapped ErrTenantBlocked             → 16
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
	case errors.Is(err, ErrTenantBlocked):
		return ExitTenantBlocked
	case errors.Is(err, ErrIntentInconsistent):
		return ExitIntentInconsistent
	case errors.Is(err, ErrIdentityMismatch):
		return ExitIdentityMismatch
	case errors.Is(err, ErrDataSourceDenied):
		return ExitDataSourceDenied
	default:
		return 1
	}
}
