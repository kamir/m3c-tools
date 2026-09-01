package evaluation

// E6 — OIDC/JWKS offline verify (SPEC-0280 §2).
//
// NOT MEASURABLE. The OIDC/Keycloak owner/sign-off binding is SPEC-0277 P2,
// which is DEFERRED / not built (the shipped agentid path is pinned-key only;
// there is no JWKS verification path to measure). Per SPEC-0280 §2 and the
// honesty contract, E6 is recorded as `N/A — deferred (gated P3-P2)`. We do NOT
// fabricate a number and do NOT stub a fake JWKS path.
//
// This driver asserts that intent in code: it documents the deferral and emits
// the N/A row in a measured run, so the CSV/paper carry the honest marker rather
// than a silent omission. If/when SPEC-0277 P2 ships a JWKS-offline verifier,
// this file is where the real measurement lands (replacing the N/A row).

import "testing"

// TestE6OIDCDeferred records E6 as N/A — deferred. It never fabricates a number.
func TestE6OIDCDeferred(t *testing.T) {
	requireEval(t)
	recordPop(t, "E6", "oidc-jwks-offline", "status", "N/A — deferred (gated P3-P2)", "n/a",
		"the OIDC/Keycloak owner/sign-off binding is SPEC-0277 P2, not built; no JWKS verify path exists to measure (no number fabricated)")
}
