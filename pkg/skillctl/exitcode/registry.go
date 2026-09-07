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
//   - Phase 2 (DONE 2026-09-07, AUDIT-0001 Befund 2.1): the manual's
//     exit-code table is generated from AllCodes() and checked against it.
//     cmd/exitaudit renders the delimited block in docs/manual-skillctl.md
//     (`go run ./cmd/exitaudit -write`), fails on any documented number that
//     neither this register nor the manual's "outside the register" table
//     accounts for, and fails when the manual and docs/CLI-VERBS.md claim
//     different exit spaces for the same verb. It is wired blocking into
//     scripts/check-docs.sh. Adding a Code here without running -write turns
//     the docs gate red, which is the point.
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
	// (e.g. "data_source_denied" vs "no_source_policy": same Number,
	// same Theme, different per-surface label).
	Label string
}

// ---------------------------------------------------------------------------
// Tier 1: verifier exit codes (pkg/skillctl/verify/errors.go).
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

	// RevokedBundle is the code SPEC-0188 §7 describes and the register did not
	// have (BUG-0216). The specification named 15 for it, but 15 has meant
	// blob_missing in shipped builds since the ladder existed, and a number whose
	// meaning changes silently is worse than a number that was never allocated:
	// a caller that reads 15 as "revoked" would treat a transport failure as a
	// security verdict, and one that reads it as "blob missing" would retry a
	// revocation. Decided 2026-09-06: bundle_revoked gets its own number, the
	// specification is corrected, and 15 keeps the meaning every existing caller
	// already has.
	//
	// It sits outside the 10-19 verify ladder deliberately, and its family is
	// "pull", not "verify". TestExitCode_VerifyFamilyCompleteness pins the verify
	// family to exactly those ten numbers, and that pin is worth more than the
	// convenience of reusing the name: the code is emitted by `pull --trust-mode`,
	// which is the surface FR-0122 is about, so "pull" is also simply what is
	// true.
	//
	// NUMBER: 6, the lowest number no exit surface claims (census 2026-09-07:
	// 0-2 generic, 3 pin, 4-5 import-public, 10-29 the ladders and their chain
	// extensions, 30-39 the skillgate band). The first FR-0122 cut took 20 on
	// the claim "20 is free"; that claim was measured against this register
	// only, not against the exit surfaces outside it, and verify.ExitSelfAttested
	// (SPEC-0246 §5.2) had been shipping 20 for weeks, documented in the manual
	// and CLI-VERBS. The one-day-old, unreleased side yields (Befund 1.4).
	// Tier 8 below registers the out-of-register numbers so the next "N is
	// free" claim collides in TestCodes_NumberTheme instead of in the field.
	//
	// Its theme is its own because a revocation is not a failed check. The chain
	// verified. Someone withdrew the bundle afterwards, and a caller has to be
	// able to tell those two apart: one is retried, the other never is.
	RevokedBundle = Code{6, "trust-chain revocation", "pull", "bundle_revoked"}
)

// ---------------------------------------------------------------------------
// Tier 2: import-public surface (SPEC-0201 §11). The numbers are ALLOCATED, the
// command is not built in this tree (census 2026-09-07: no import_public_cmds.go,
// only the demo's scenario text refers to it), which is why SPEC-0201's sixth
// number could quietly be taken by RevokedBundle above. Numerically shares
// 17/18/19 with verify; theme intentionally identical.
// ---------------------------------------------------------------------------

var (
	ImportPinRequired    = Code{4, "input validation", "import-public", "pin_required"}
	ImportScannerRefuse  = Code{5, "scanner / policy", "import-public", "scanner_refuse"}
	ImportNoSourcePolicy = Code{17, "data-source / source-policy", "import-public", "no_source_policy"}
	ImportIntentCapped   = Code{18, "intent contradiction", "import-public", "intent_capped"}
	ImportSourceBlocked  = Code{19, "identity / source-block", "import-public", "source_blocked"}
)

// ---------------------------------------------------------------------------
// Tier 3: signing surface (cmd/skillctl/signing_cmds.go).
// ---------------------------------------------------------------------------

var (
	SignInvalid = Code{11, "trust-chain signature", "signing", "sig_invalid"}
)

// ---------------------------------------------------------------------------
// Tier 4: revoke surface (SPEC-0198).
// SPEC-0198 §11 reserves exit 17 for the verifier's "author key revoked"
// signal. The theme is intentionally "data-source / source-policy" because
// a revoked author identity behaves at the trust boundary the same way as
// a denied data source. The verifier refuses to trust the bundle's
// provenance chain.
// ---------------------------------------------------------------------------

var (
	RevokeIdentityRevoked = Code{17, "data-source / source-policy", "revoke", "identity_revoked"}
)

// ---------------------------------------------------------------------------
// Tier 5: sync agent / KafShield ingest surface (SPEC-0317 R-5, P1).
// 29 is a fresh, uniquely-themed egress code; it does not share a Number with
// any existing surface, so the Number↔Theme invariant holds trivially.
// ---------------------------------------------------------------------------

var (
	SyncIngestRejected = Code{29, "egress / ingest", "sync", "ingest_rejected"}
)

// ---------------------------------------------------------------------------
// Tier 6: side-channel path guard (SPEC-0317 R-6, P2; cmd/skillctl/guardpath_cmds.go).
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
// Tier 7: offline state machine + audit-durability (SPEC-0317 R-7.2 / R-8.2 /
// R-1.4 P2, P2). 28 `offline_locked`: the `locked` state (enterprise opt-in via
// managed settings + NO trust basis) denies a managed skill. 26
// `local_audit_unavailable`: require_local_audit is set and an ALLOW's evidence
// could not be durably recorded (outbox+spool both failed) → fail closed,
// inverting the SPEC-0255 fire-and-forget default. 25 `offline_unverifiable_managed`:
// state-gate-fallback is set and a LEGACY managed install with no offline metadata
// would otherwise reach the online §7 chain → fail closed, keeping the hot path
// strictly local (shares theme 28, a different number).
//
// NUMBER CHOICE: 25 is deliberately BELOW the 30–39 band that pkg/skillgate
// (SPEC-0202 §8.2) owns for LIVE process-exit refusals (ExitCapabilityMissing=30 …
// ExitEgressByteQuota=39). These semantic codes ride the message + refusal_code
// only (the PROCESS still exits 2), but keeping their numbers out of the live band
// avoids any collision if the registry's Phase-3 migration ever makes a number a
// real os.Exit. TestCodes_NoSkillgateBandIntrusion pins this. All three ride the
// message + refusal_code; the PROCESS still exits 2 to block the PreToolUse call,
// mirroring the guard-path/verify-hook convention.
// ---------------------------------------------------------------------------

var (
	OfflineLocked         = Code{28, "offline / no-policy-basis", "state-machine", "offline_locked"}
	LocalAuditUnavailable = Code{26, "evidence / audit-durability", "enforce", "local_audit_unavailable"}
	OfflineUnverifiable   = Code{25, "offline / no-policy-basis", "state-machine", "offline_unverifiable_managed"}
)

// ---------------------------------------------------------------------------
// Tier 8: out-of-register exit surfaces (census 2026-09-07, Befund 1.4).
// These numbers were allocated in pkg/skillctl/verify/errors.go (SPEC-0246
// §5.2, SPEC-0279 R3, SPEC-0278 L1), cmd/skillctl/agentid_cmds.go,
// cmd/skillctl/translog_cmds.go and cmd/skillctl/pin_cmds.go, but never
// entered here, so TestCodes_NumberTheme could not see them. That blindness
// is how bundle_revoked briefly claimed 20: "20 is free" was measured
// against this register only, while verify.ExitSelfAttested had been
// shipping 20 for weeks. Registered so that every number an exit surface
// holds is visible to the invariant, and the next "N is free" claim
// collides in CI instead of in the field.
//
// FAMILY NOTE: 20/22/23 are emitted by the §7 verifier (verify.ExitCode),
// but their Family is NOT "verify": TestExitCode_VerifyFamilyCompleteness
// pins Family=="verify" to exactly the 10-19 ladder, and that pin is
// load-bearing. The checks that SPEC-0246, SPEC-0277, SPEC-0278 and
// SPEC-0279 layer on the chain
// therefore carry the family "verify-chain"; agentid, translog and pin are
// named after the subcommand surfaces that actually exit with them.
//
// KNOWN LEGACY COLLISION ON 25: TranslogRewrite (a real process exit of
// `skillctl translog`, shipped since v0.3.0) and OfflineUnverifiable (a
// message-borne refusal_code, shipped since v0.3.1) both hold 25 with
// different themes. Both sides are in releases, so neither can yield the
// way the unreleased bundle_revoked-20 did. The pair is pinned as the ONLY
// tolerated violation in TestCodes_KnownLegacyCollision25 and excluded from
// TestCodes_NumberTheme; resolving it needs a release-level decision.
// ---------------------------------------------------------------------------

var (
	PinNeedPrivMsg        = Code{3, "privileged write required", "pin", "need_priv_msg"}
	ChainSelfAttested     = Code{20, "attestation reviewer-independence", "verify-chain", "self_attested"}
	AgentIDExpired        = Code{21, "agent-identity expiry", "agentid", "agentid_expired"}
	ChainRevocationStale  = Code{22, "revocation freshness", "verify-chain", "revocation_stale"}
	ChainInclusionMissing = Code{23, "log inclusion", "verify-chain", "inclusion_missing"}
	TranslogNotIncluded   = Code{23, "log inclusion", "translog", "not_included"}
	TranslogSplitView     = Code{24, "log equivocation", "translog", "split_view"}
	TranslogRewrite       = Code{25, "log rewrite", "translog", "translog_rewrite"}
)

// AllCodes returns every Code currently registered. Used by the
// CI invariant test (TestCodes_NumberTheme) and by the generator
// that emits the SKILLCTL-MANUAL.md exit-code table.
func AllCodes() []Code {
	return []Code{
		// Tier 1: verify
		VerifyDigestMismatch, VerifyAuthorSigInvalid, VerifyRegistryNotTrusted,
		VerifyGovernanceBelowMin, VerifyDepsUnsatisfied, VerifyBlobMissing,
		VerifyTenantBlocked, VerifyDataSourceDenied, VerifyIntentInconsistent,
		VerifyIdentityMismatch, RevokedBundle,
		// Tier 2 (import-public
		ImportPinRequired, ImportScannerRefuse, ImportNoSourcePolicy,
		ImportIntentCapped, ImportSourceBlocked,
		// Tier 3) signing
		SignInvalid,
		// Tier 4 (revoke
		RevokeIdentityRevoked,
		// Tier 5) sync / ingest
		SyncIngestRejected,
		// Tier 6 (guard-path side channel
		GuardPathSidechannelDenied,
		// Tier 7) offline state machine (locked + unverifiable) + audit-durability
		OfflineLocked, LocalAuditUnavailable, OfflineUnverifiable,
		// Tier 8: out-of-register surfaces (pin, verify-chain, agentid, translog)
		PinNeedPrivMsg, ChainSelfAttested, AgentIDExpired, ChainRevocationStale,
		ChainInclusionMissing, TranslogNotIncluded, TranslogSplitView, TranslogRewrite,
	}
}
