package pocket

import "testing"

// TestMode covers the SPEC-0174 §3.1 auto-detect rule.
// USB presence is mocked via a closure so tests don't depend on
// /Volumes/Pocket/RECORD existing on the test host.
func TestMode(t *testing.T) {
	cases := []struct {
		name     string
		apiKey   string
		usbThere bool
		syncMode string // value of POCKET_SYNC_MODE
		want     SyncModeKind
	}{
		{"nothing", "", false, "", ModeOff},
		{"api only", "pk_x", false, "", ModeAPI},
		{"usb only", "", true, "", ModeUSB},
		{"both prefers both", "pk_x", true, "", ModeBoth},
		{"explicit usb opt-out hides api", "pk_x", true, "usb", ModeUSB},
		{"explicit usb without device", "pk_x", false, "usb", ModeOff},
		{"api env value is ignored (auto-detect rules)", "", false, "api", ModeOff},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{APIKey: tc.apiKey, SyncMode: tc.syncMode, RecordPath: "/this/path/does/not/exist"}
			// Override IsDeviceConnected behaviour by using a path that exists/doesn't:
			if tc.usbThere {
				c.RecordPath = "."
			}
			got := c.Mode()
			if got != tc.want {
				t.Fatalf("Mode() = %q, want %q (apiKey=%q, usbThere=%v, syncMode=%q)",
					got, tc.want, tc.apiKey, tc.usbThere, tc.syncMode)
			}
		})
	}
}

func TestIsAPIModeFollowsMode(t *testing.T) {
	// Sanity: IsAPIMode() should be true exactly when Mode() resolves to api or both.
	cases := []struct {
		c      Config
		wantIs bool
	}{
		{Config{APIKey: "k", RecordPath: "/no/such"}, true}, // api
		{Config{APIKey: "", RecordPath: "."}, false},        // usb-only
		{Config{APIKey: "k", RecordPath: "."}, true},        // both
		{Config{APIKey: "", RecordPath: "/no/such"}, false}, // off
	}
	for i, tc := range cases {
		if got := tc.c.IsAPIMode(); got != tc.wantIs {
			t.Errorf("case %d: IsAPIMode() = %v, want %v (mode=%q)",
				i, got, tc.wantIs, tc.c.Mode())
		}
	}
}
