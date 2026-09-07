package exitcode

import "testing"

// TestCodes_NumberTheme: the CI invariant FR-0023 buys us.
//
// Codes sharing a Number MUST share a Theme. Operators rely on the
// theme being stable across surfaces (a "data-source / source-policy"
// failure means the same thing whether install or import-public
// emitted it). A new surface trying to use code 17 for an unrelated
// theme will fail this test.
func TestCodes_NumberTheme(t *testing.T) {
	themeByNum := make(map[int]string)
	originByNum := make(map[int]Code)
	for _, c := range AllCodes() {
		if c.Number == 0 {
			continue // 0 is "success": codes don't claim 0
		}
		if c.Number == 25 {
			// The ONE tolerated legacy collision: translog rewrite (real
			// process exit, shipped since v0.3.0) vs offline_unverifiable
			// (message-borne refusal_code, shipped since v0.3.1). Both are
			// released, so neither side can yield without breaking a shipped
			// contract. TestCodes_KnownLegacyCollision25 pins the pair
			// exactly; a third claimant of 25 (or a resolution of the pair)
			// fails there, so nothing NEW hides behind this skip.
			continue
		}
		if prev, ok := themeByNum[c.Number]; ok {
			if prev != c.Theme {
				t.Errorf("exit code %d theme collision: %q (%s/%s) vs %q (%s/%s)",
					c.Number,
					originByNum[c.Number].Theme, originByNum[c.Number].Family, originByNum[c.Number].Label,
					c.Theme, c.Family, c.Label,
				)
			}
		} else {
			themeByNum[c.Number] = c.Theme
			originByNum[c.Number] = c
		}
	}
}

// TestCodes_KnownLegacyCollision25 pins the one tolerated Number-Theme
// violation that TestCodes_NumberTheme skips. Exactly TWO codes may hold 25,
// with exactly these families, labels and (differing) themes; both were in
// releases before the register saw them (census 2026-09-07, Befund 1.4), so
// unlike the unreleased bundle_revoked-20 neither side can be renumbered
// without a release-level decision. If that decision is ever taken and one
// side moves, this test fails, which forces the exemption in
// TestCodes_NumberTheme to be deleted along with it. A third surface trying
// to claim 25 fails here too.
func TestCodes_KnownLegacyCollision25(t *testing.T) {
	want := map[string]Code{
		"state-machine/offline_unverifiable_managed": {25, "offline / no-policy-basis", "state-machine", "offline_unverifiable_managed"},
		"translog/translog_rewrite":                  {25, "log rewrite", "translog", "translog_rewrite"},
	}
	got := map[string]Code{}
	for _, c := range AllCodes() {
		if c.Number == 25 {
			got[c.Family+"/"+c.Label] = c
		}
	}
	if len(got) != len(want) {
		t.Errorf("exit code 25 is held by %d codes, the pinned legacy pair allows exactly %d: %v", len(got), len(want), got)
	}
	for k, w := range want {
		g, ok := got[k]
		if !ok {
			t.Errorf("pinned legacy holder %q no longer holds 25: delete this exemption AND the Number==25 skip in TestCodes_NumberTheme", k)
			continue
		}
		if g != w {
			t.Errorf("pinned legacy holder %q drifted: got %+v want %+v", k, g, w)
		}
	}
}

// TestCodes_LabelUniquePerFamily: within a single Family the Labels
// must be unique. Two surfaces can share a label (verify and import-public
// both have "intent_*"-themed entries) but no surface should have two
// codes with the same label.
func TestCodes_LabelUniquePerFamily(t *testing.T) {
	type famLabel struct{ family, label string }
	seen := make(map[famLabel]Code)
	for _, c := range AllCodes() {
		k := famLabel{c.Family, c.Label}
		if prev, ok := seen[k]; ok {
			t.Errorf("duplicate (%s, %s): code %d and code %d",
				c.Family, c.Label, prev.Number, c.Number)
		} else {
			seen[k] = c
		}
	}
}

// TestCodes_NumberRange: sanity. Exit codes should fit in the
// conventional 1..127 process-exit range. Anything outside is a
// programmer error.
func TestCodes_NumberRange(t *testing.T) {
	for _, c := range AllCodes() {
		if c.Number < 1 || c.Number > 127 {
			t.Errorf("exit code %d (%s/%s) outside 1..127 range",
				c.Number, c.Family, c.Label)
		}
	}
}

// TestCodes_NoSkillgateBandIntrusion keeps this (semantic, message-borne) registry
// disjoint from the 30–39 band that pkg/skillgate owns for LIVE process-exit
// refusals (SPEC-0202 §8.2: ExitCapabilityMissing=30 … ExitEgressByteQuota=39).
// These codes ride the refusal_code/message while the process exits 2, but reusing
// a number from the live band would become a real ambiguity if the registry's
// Phase-3 migration ever turns a Number into an os.Exit. The band is hard-coded (no
// skillgate import) to keep the two registries structurally independent.
func TestCodes_NoSkillgateBandIntrusion(t *testing.T) {
	for _, c := range AllCodes() {
		if c.Number >= 30 && c.Number <= 39 {
			t.Errorf("exit code %d (%s/%s) intrudes on the skillgate SPEC-0202 §8.2 live process-exit band 30–39; pick a number outside it",
				c.Number, c.Family, c.Label)
		}
	}
}
