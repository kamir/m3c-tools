package exitcode_test

// SPEC-0251 §5 — exit-code single source of truth (guard, not refactor).
//
// pkg/skillctl/exitcode is the registry of every skillctl exit number. The
// numbers are ALSO declared as consts in pkg/skillctl/verify (the §7 verifier)
// and in cmd/skillctl. Rather than refactor the security-sensitive verifier to
// import the registry (which would force the untyped exit consts to become
// typed vars — a real regression surface), this guard fails CI the moment the
// two sides drift. The 10–19 ladder that SPEC-0188 §11 and the SPEC-0254
// operator docs depend on therefore cannot silently diverge: drift == red CI.
//
// This test is also the registry's first real consumer — exitcode is no longer
// a dead package.

import (
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/exitcode"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// Every verify-family registry Number must equal its verify.Exit* const.
func TestExitCode_VerifyRegistryParity(t *testing.T) {
	cases := []struct {
		name string
		reg  int // exitcode registry Number
		got  int // verify package const
	}{
		{"digest_mismatch", exitcode.VerifyDigestMismatch.Number, verify.ExitDigestMismatch},
		{"author_sig_invalid", exitcode.VerifyAuthorSigInvalid.Number, verify.ExitAuthorSigInvalid},
		{"registry_not_trusted", exitcode.VerifyRegistryNotTrusted.Number, verify.ExitRegistryNotTrusted},
		{"governance_below_min", exitcode.VerifyGovernanceBelowMin.Number, verify.ExitGovernanceBelowMin},
		{"deps_unsatisfied", exitcode.VerifyDepsUnsatisfied.Number, verify.ExitDepsUnsatisfied},
		{"blob_missing", exitcode.VerifyBlobMissing.Number, verify.ExitBlobMissing},
		{"tenant_blocked", exitcode.VerifyTenantBlocked.Number, verify.ExitTenantBlocked},
		{"data_source_denied", exitcode.VerifyDataSourceDenied.Number, verify.ExitDataSourceDenied},
		{"intent_inconsistent", exitcode.VerifyIntentInconsistent.Number, verify.ExitIntentInconsistent},
		{"identity_mismatch", exitcode.VerifyIdentityMismatch.Number, verify.ExitIdentityMismatch},
	}
	for _, c := range cases {
		if c.reg != c.got {
			t.Errorf("exit-code drift for %q: exitcode registry=%d, verify const=%d — update both", c.name, c.reg, c.got)
		}
	}
}

// SPEC-0198 / BUG-0144: an explicitly revoked author identity maps to 17 — the
// SAME number + theme as data-source-denied — and ExitCode checks revoke FIRST
// so it wins. Pin both the value and the deliberate overload so a future edit
// can't quietly split or renumber them.
func TestExitCode_IdentityRevokedMapsTo17(t *testing.T) {
	if got := verify.ExitCode(verify.ErrIdentityRevoked); got != exitcode.RevokeIdentityRevoked.Number {
		t.Errorf("ErrIdentityRevoked → exit %d, want %d (exitcode.RevokeIdentityRevoked)", got, exitcode.RevokeIdentityRevoked.Number)
	}
	if exitcode.RevokeIdentityRevoked.Number != 17 || exitcode.VerifyDataSourceDenied.Number != 17 {
		t.Errorf("17 must be shared by identity-revoked + data-source-denied; got revoke=%d dsd=%d",
			exitcode.RevokeIdentityRevoked.Number, exitcode.VerifyDataSourceDenied.Number)
	}
	if exitcode.RevokeIdentityRevoked.Theme != exitcode.VerifyDataSourceDenied.Theme {
		t.Errorf("codes sharing number 17 must share a Theme: revoke=%q dsd=%q",
			exitcode.RevokeIdentityRevoked.Theme, exitcode.VerifyDataSourceDenied.Theme)
	}
}

// Completeness: every Family=="verify" registry Code must land on a pinned
// 10–19 number, and all ten must be present — so a new verify row can't be
// added (or one dropped) without this guard noticing.
func TestExitCode_VerifyFamilyCompleteness(t *testing.T) {
	want := map[int]bool{10: true, 11: true, 12: true, 13: true, 14: true, 15: true, 16: true, 17: true, 18: true, 19: true}
	for _, c := range exitcode.AllCodes() {
		if c.Family != "verify" {
			continue
		}
		if !want[c.Number] {
			t.Errorf("registry has Family==verify Code %+v outside the pinned 10–19 set — wire verify + extend this guard", c)
			continue
		}
		delete(want, c.Number)
	}
	for n := range want {
		t.Errorf("no Family==verify registry Code for pinned verify number %d", n)
	}
}
