// SPEC-0201 §11 / SPEC-0188 §11 — exit-19 source-block invariants.
//
// The "source-block" theme is shared across surfaces (verify, import-public)
// at the SAME numeric code (19). This test enforces:
//
//   1. Every Code with Number==19 carries the same Theme.
//   2. ImportSourceBlocked and VerifyIdentityMismatch share the 19 slot,
//      under the canonical theme "identity / source-block".
//   3. A new surface trying to claim 19 with a different theme breaks CI.
//
// Pairs with the existing import-public CLI test
// (cmd/skillctl/import_public_cmds_test.go:129,149) that exercises the
// numeric path end-to-end via the CLI binary.
//
// Refs: SPEC-0201 §11 (airlock), SPEC-0188 §11 (verifier exit codes),
// FR-0023 registry, TEST-COVERAGE-MATRIX.md Top-5 risk #4.

package exitcode

import "testing"

func TestExit19_SourceBlockInvariant(t *testing.T) {
	const wantNumber = 19
	const wantTheme = "identity / source-block"

	matchingCodes := []Code{}
	for _, c := range AllCodes() {
		if c.Number == wantNumber {
			matchingCodes = append(matchingCodes, c)
		}
	}

	if len(matchingCodes) < 2 {
		t.Fatalf("expected at least 2 Codes claiming exit 19 (verify + import-public); got %d",
			len(matchingCodes))
	}

	// Themes must match — codes sharing a number share a theme is already
	// enforced by TestCodes_NumberTheme, but this test pins THE specific
	// theme expected for 19 so a rename anywhere else (e.g. someone changes
	// VerifyIdentityMismatch.Theme) breaks this test loudly.
	for _, c := range matchingCodes {
		if c.Theme != wantTheme {
			t.Errorf("code 19 in family %s has theme %q, want %q",
				c.Family, c.Theme, wantTheme)
		}
	}

	// The two canonical surfaces must both register a 19. Identity-mismatch
	// (verify side) and source-blocked (import-public side) are the
	// SPEC-0188 §11 + SPEC-0201 §11 anchor labels.
	haveImport := false
	haveVerify := false
	for _, c := range matchingCodes {
		switch c.Family {
		case "import-public":
			if c.Label == "source_blocked" {
				haveImport = true
			}
		case "verify":
			if c.Label == "identity_mismatch" {
				haveVerify = true
			}
		}
	}
	if !haveImport {
		t.Error("expected import-public 'source_blocked' Code at exit 19")
	}
	if !haveVerify {
		t.Error("expected verify 'identity_mismatch' Code at exit 19")
	}
}

// TestExit19_DistinctFrom17 — sanity: a regression that collapses 17 and 19
// into one numeric slot would silently break operator triage.
func TestExit19_DistinctFrom17(t *testing.T) {
	for _, c := range AllCodes() {
		if c.Number == 17 && c.Theme == "identity / source-block" {
			t.Errorf("code 17 (%s/%s) carries the SPEC-0201 source-block theme that belongs to 19",
				c.Family, c.Label)
		}
		if c.Number == 19 && c.Theme == "data-source / source-policy" {
			t.Errorf("code 19 (%s/%s) carries the SPEC-0196/0198 data-source theme that belongs to 17",
				c.Family, c.Label)
		}
	}
}
