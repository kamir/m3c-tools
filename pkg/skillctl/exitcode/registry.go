// Package exitcode is the canonical registry of skillctl process exit codes.
//
// FR-0023 (2026-05-11): exit codes 17/18/19 are intentionally numerically
// shared across four skillctl surfaces (install/verify, pack, awareness
// reset, import-public) because their THEMES align. The pre-FR-0023
// world had each surface defining its own const with the same numeric
// value but different mnemonic names, and the cross-reference lived
// only in SKILLCTL-MANUAL.md.
//
// The CI test in this package (TestCodes_NumberTheme) asserts the
// invariant: any two Codes that share a Number MUST share a Theme.
// A new surface trying to land `= 17` for a non-data-source theme
// breaks `go test ./pkg/skillctl/exitcode/`.
//
// Migration strategy:
//   - Phase 1 (this commit): registry + invariant test. Existing
//     constants in pkg/skillctl/verify/errors.go and
//     cmd/skillctl/import_public_cmds.go reference the registry's
//     Number field via short type aliases. No call-site changes yet.
//   - Phase 2 (later): go:generate the SKILLCTL-MANUAL.md exit-code
//     table from this file.
//   - Phase 3 (later): migrate all `os.Exit(<int>)` call sites to
//     `os.Exit(exitcode.X.Number)` so the registry is the only source
//     of truth.
package exitcode

// Code carries a numeric exit code with the per-surface metadata that
// SKILLCTL-MANUAL.md's exit-code table documents.
type Code struct {
	// Number is the numeric exit value passed to os.Exit / process exit.
	Number int
	// Theme is the cross-surface category. Codes sharing a Number MUST
	// share a Theme. Operators rely on the theme being a stable
	// "what kind of failure is this" signal across surfaces.
	Theme string
	// Family is the skillctl surface emitting the code
	// ("verify", "install", "pack", "import-public", "awareness-reset",
	// "audit", "propose", "revoke", ...).
	Family string
	// Label is the surface-specific mnemonic the operator sees
	// (e.g. "data_source_denied" vs "no_source_policy" — same Number,
	// same Theme, different per-surface label).
	Label string
}

// ---------------------------------------------------------------------------
// Tier 1 — verifier exit codes (pkg/skillctl/verify/errors.go).
// SPEC-0188 §11. These are the canonical "trust chain failed at step N"
// signals that propagate up from install/verify.
// ---------------------------------------------------------------------------

var (
	VerifyDigestMismatch     = Code{10, "trust-chain digest", "verify", "digest_mismatch"}
	VerifyAuthorSigInvalid   = Code{11, "trust-chain signature", "verify", "author_sig_invalid"}
	VerifyRegistryNotTrusted = Code{12, "trust-chain registry-root", "verify", "registry_not_trusted"}
	VerifyGovernanceBelowMin = Code{13, "policy governance", "verify", "governance_below_min"}
	VerifyDepsUnsatisfied    = Code{14, "policy dependency", "verify", "deps_unsatisfied"}
	VerifyBlobMissing        = Code{15, "trust-chain blob", "verify", "blob_missing"}
	VerifyTenantBlocked      = Code{16, "policy tenant", "verify", "tenant_blocked"}
	VerifyDataSourceDenied   = Code{17, "data-source / source-policy", "verify", "data_source_denied"}
	VerifyIntentInconsistent = Code{18, "intent contradiction", "verify", "intent_inconsistent"}
	VerifyIdentityMismatch   = Code{19, "identity / source-block", "verify", "identity_mismatch"}
)

// ---------------------------------------------------------------------------
// Tier 2 — import-public surface (SPEC-0201 §11; cmd/skillctl/import_public_cmds.go).
// Numerically shares 17/18/19 with verify; theme intentionally identical.
// ---------------------------------------------------------------------------

var (
	ImportPinRequired    = Code{4, "input validation", "import-public", "pin_required"}
	ImportScannerRefuse  = Code{5, "scanner / policy", "import-public", "scanner_refuse"}
	ImportNoSourcePolicy = Code{17, "data-source / source-policy", "import-public", "no_source_policy"}
	ImportIntentCapped   = Code{18, "intent contradiction", "import-public", "intent_capped"}
	ImportSourceBlocked  = Code{19, "identity / source-block", "import-public", "source_blocked"}
)

// ---------------------------------------------------------------------------
// Tier 3 — signing surface (cmd/skillctl/signing_cmds.go).
// ---------------------------------------------------------------------------

var (
	SignInvalid = Code{11, "trust-chain signature", "signing", "sig_invalid"}
)

// ---------------------------------------------------------------------------
// Tier 4 — revoke surface (SPEC-0198).
// SPEC-0198 §11 reserves exit 17 for the verifier's "author key revoked"
// signal. The theme is intentionally "data-source / source-policy" because
// a revoked author identity behaves at the trust boundary the same way as
// a denied data source — the verifier refuses to trust the bundle's
// provenance chain.
// ---------------------------------------------------------------------------

var (
	RevokeIdentityRevoked = Code{17, "data-source / source-policy", "revoke", "identity_revoked"}
)

// ---------------------------------------------------------------------------
// Tier 5 — sync agent / KafShield ingest surface (SPEC-0317 R-5, P1).
// 29 is a fresh, uniquely-themed egress code; it does not share a Number with
// any existing surface, so the Number↔Theme invariant holds trivially.
// ---------------------------------------------------------------------------

var (
	SyncIngestRejected = Code{29, "egress / ingest", "sync", "ingest_rejected"}
)

// ---------------------------------------------------------------------------
// Tier 6 — side-channel path guard (SPEC-0317 R-6, P2; cmd/skillctl/guardpath_cmds.go).
// 27 is a fresh, uniquely-themed code carried in the signed refusal_code of a
// `skillctl guard-path` opt-in deny (the PROCESS still exits 2 to block the
// PreToolUse call, mirroring verify-hook's exitBundleRevoked/exitRevocationStale
// convention). It does not share a Number with any other surface, so the
// Number↔Theme invariant holds trivially.
// ---------------------------------------------------------------------------

var (
	GuardPathSidechannelDenied = Code{27, "side-channel / path-guard", "guard-path", "sidechannel_denied"}
)

// ---------------------------------------------------------------------------
// Tier 7 — offline state machine (SPEC-0317 R-7.2, P2; the runtime gate).
// 28 is a fresh, uniquely-themed code carried in the signed refusal_code when the
// `locked` state (enterprise opt-in via managed settings + NO trust basis at all)
// denies a MANAGED skill. The PROCESS still exits 2 to block the PreToolUse call,
// mirroring the guard-path/verify-hook convention. Reserved-but-not-yet-emitted:
// 26 (local_audit_unavailable, R-8 require_local_audit) — registered when that
// carve-out is wired, so it is NOT in AllCodes yet.
// ---------------------------------------------------------------------------

var (
	OfflineLocked = Code{28, "offline / no-policy-basis", "state-machine", "offline_locked"}
)

// AllCodes returns every Code currently registered. Used by the
// CI invariant test (TestCodes_NumberTheme) and by the generator
// that emits the SKILLCTL-MANUAL.md exit-code table.
func AllCodes() []Code {
	return []Code{
		// Tier 1 — verify
		VerifyDigestMismatch, VerifyAuthorSigInvalid, VerifyRegistryNotTrusted,
		VerifyGovernanceBelowMin, VerifyDepsUnsatisfied, VerifyBlobMissing,
		VerifyTenantBlocked, VerifyDataSourceDenied, VerifyIntentInconsistent,
		VerifyIdentityMismatch,
		// Tier 2 — import-public
		ImportPinRequired, ImportScannerRefuse, ImportNoSourcePolicy,
		ImportIntentCapped, ImportSourceBlocked,
		// Tier 3 — signing
		SignInvalid,
		// Tier 4 — revoke
		RevokeIdentityRevoked,
		// Tier 5 — sync / ingest
		SyncIngestRejected,
		// Tier 6 — guard-path side channel
		GuardPathSidechannelDenied,
		// Tier 7 — offline state machine (locked)
		OfflineLocked,
	}
}
