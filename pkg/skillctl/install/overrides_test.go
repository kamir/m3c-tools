package install

import (
	"encoding/json"
	"testing"
)

func TestOverrideAction(t *testing.T) {
	cases := []struct {
		name    string
		opts    Opts
		want    string
	}{
		{"no flags", Opts{}, "install"},
		{"allow-yellow only", Opts{AllowYellow: true}, "install.allow-yellow"},
		{"ignore-deps only", Opts{IgnoreDeps: true}, "install.ignore-deps"},
		{"both", Opts{AllowYellow: true, IgnoreDeps: true}, "install.allow-yellow,install.ignore-deps"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := overrideAction(c.opts); got != c.want {
				t.Errorf("overrideAction(%+v) = %q, want %q", c.opts, got, c.want)
			}
		})
	}
}

func TestAuditEntry_JSONShape(t *testing.T) {
	// Lock the wire-shape: the audit endpoint sees these field names
	// verbatim. If a change to AuditEntry rips through here, that's a
	// signal to coordinate with the server-side audit row schema.
	entry := AuditEntry{
		Action:      "install.allow-yellow",
		Name:        "fetch-contract",
		Version:     "1.0.0",
		AllowYellow: true,
		IgnoreDeps:  false,
		RecordedAt:  "2026-05-05T20:00:00Z",
		Origin:      "skillctl",
		RegistryURL: "https://reg.example/api/skills",
	}
	want := []string{
		`"action":"install.allow-yellow"`,
		`"name":"fetch-contract"`,
		`"version":"1.0.0"`,
		`"allow_yellow":true`,
		`"recorded_at":"2026-05-05T20:00:00Z"`,
		`"origin":"skillctl"`,
		`"registry_url":"https://reg.example/api/skills"`,
	}
	gotBytes := mustMarshal(t, entry)
	got := string(gotBytes)
	for _, w := range want {
		if !contains(got, w) {
			t.Errorf("JSON missing %q\nfull: %s", w, got)
		}
	}
}

// ----- tiny test helpers -----

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
