package exitcode

import "testing"

// TestCodes_NumberTheme — the CI invariant FR-0023 buys us.
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
			continue // 0 is "success" — codes don't claim 0
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

// TestCodes_LabelUniquePerFamily — within a single Family the Labels
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

// TestCodes_NumberRange — sanity. Exit codes should fit in the
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
