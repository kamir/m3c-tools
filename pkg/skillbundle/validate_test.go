package skillbundle

import "testing"

// boolPtr is a one-line helper for *bool literals in test cases.
func boolPtr(b bool) *bool { return &b }

func TestValidateIntentDataCrossRules(t *testing.T) {
	cases := []struct {
		name             string
		intent           *Intent
		governanceIntent string
		deps             []DataDependency
		want             CrossRuleViolation
	}{
		// --- sentinel + nil paths ---
		{
			name:             "nil intent returns RuleNone",
			intent:           nil,
			governanceIntent: "green",
			deps:             nil,
			want:             RuleNone,
		},
		{
			name:             "awareness sentinel side_effects=[UNKNOWN] returns RuleNone",
			intent:           &Intent{SideEffects: []string{"UNKNOWN"}, Destructive: true},
			governanceIntent: "green", // would normally fire Rule 1, but sentinel skips
			deps:             nil,
			want:             RuleNone,
		},
		{
			name:             "empty side_effects but otherwise consistent",
			intent:           &Intent{SideEffects: []string{}},
			governanceIntent: "yellow",
			deps:             nil,
			want:             RuleNone,
		},

		// --- Rule 1: destructive_green ---
		{
			name:             "Rule 1 — destructive=true + green fires",
			intent:           &Intent{Destructive: true, SideEffects: []string{"fs:write"}},
			governanceIntent: "green",
			deps:             nil,
			want:             RuleDestructiveGreen,
		},
		{
			name:             "Rule 1 — destructive=true + yellow does NOT fire",
			intent:           &Intent{Destructive: true, SideEffects: []string{"fs:write"}},
			governanceIntent: "yellow",
			deps:             nil,
			want:             RuleNone,
		},
		{
			name:             "Rule 1 — destructive=true + red does NOT fire",
			intent:           &Intent{Destructive: true, SideEffects: []string{"fs:write"}},
			governanceIntent: "red",
			deps:             nil,
			want:             RuleNone,
		},
		{
			name:             "Rule 1 — destructive=false + green is fine",
			intent:           &Intent{Destructive: false, SideEffects: []string{"fs:read"}},
			governanceIntent: "green",
			deps:             nil,
			want:             RuleNone,
		},

		// --- Rule 2: network_false_http_dep ---
		{
			name:             "Rule 2 — network=false + http_endpoint dep fires",
			intent:           &Intent{Network: boolPtr(false), SideEffects: []string{"net:none"}, Destructive: true},
			governanceIntent: "yellow",
			deps:             []DataDependency{{Kind: "http_endpoint", Ref: "https://api.anthropic.com", Access: "read"}},
			want:             RuleNetworkFalseHttpDep,
		},
		{
			name:             "Rule 2 — network=false + non-http deps does NOT fire",
			intent:           &Intent{Network: boolPtr(false), SideEffects: []string{"fs:read"}},
			governanceIntent: "yellow",
			deps: []DataDependency{
				{Kind: "filesystem", Ref: "/tmp/x", Access: "read"},
				{Kind: "er1", Ref: "ctx-123", Access: "read"},
			},
			want: RuleNone,
		},
		{
			name:             "Rule 2 — network=true + http_endpoint dep is fine",
			intent:           &Intent{Network: boolPtr(true), SideEffects: []string{"net:http"}},
			governanceIntent: "yellow",
			deps:             []DataDependency{{Kind: "http_endpoint", Ref: "https://api.anthropic.com", Access: "read"}},
			want:             RuleNone,
		},
		{
			name:             "Rule 2 — network unset (nil) + http_endpoint dep does NOT fire",
			intent:           &Intent{Network: nil, SideEffects: []string{"net:http"}},
			governanceIntent: "yellow",
			deps:             []DataDependency{{Kind: "http_endpoint", Ref: "https://api.anthropic.com", Access: "read"}},
			want:             RuleNone,
		},

		// --- Rule 3: write_access_non_destructive ---
		{
			name:             "Rule 3 — destructive=false + write access fires",
			intent:           &Intent{Destructive: false, SideEffects: []string{"fs:write"}},
			governanceIntent: "yellow",
			deps:             []DataDependency{{Kind: "filesystem", Ref: "/tmp/x", Access: "write"}},
			want:             RuleWriteAccessNonDestructive,
		},
		{
			name:             "Rule 3 — destructive=true + write access is fine",
			intent:           &Intent{Destructive: true, SideEffects: []string{"fs:write"}, Network: boolPtr(true)},
			governanceIntent: "yellow",
			deps:             []DataDependency{{Kind: "filesystem", Ref: "/tmp/x", Access: "write"}},
			want:             RuleNone,
		},
		{
			name:             "Rule 3 — destructive=false + read access is fine",
			intent:           &Intent{Destructive: false, SideEffects: []string{"fs:read"}},
			governanceIntent: "yellow",
			deps:             []DataDependency{{Kind: "filesystem", Ref: "/tmp/x", Access: "read"}},
			want:             RuleNone,
		},
		{
			name:             "Rule 3 — destructive=false + passthrough access is fine",
			intent:           &Intent{Destructive: false, SideEffects: []string{"net:passthrough"}, Network: boolPtr(true)},
			governanceIntent: "yellow",
			deps:             []DataDependency{{Kind: "http_endpoint", Ref: "https://api.anthropic.com", Access: "passthrough"}},
			want:             RuleNone,
		},

		// --- ordering: rule 1 trumps rule 2 trumps rule 3 ---
		{
			name:             "ordering — rule 1 fires before rule 2",
			intent:           &Intent{Destructive: true, Network: boolPtr(false), SideEffects: []string{"all"}},
			governanceIntent: "green",
			deps:             []DataDependency{{Kind: "http_endpoint", Access: "read"}},
			want:             RuleDestructiveGreen,
		},
		{
			name:             "ordering — rule 2 fires before rule 3 when rule 1 doesn't apply",
			intent:           &Intent{Destructive: false, Network: boolPtr(false), SideEffects: []string{"all"}},
			governanceIntent: "yellow",
			deps:             []DataDependency{{Kind: "http_endpoint", Access: "write"}},
			want:             RuleNetworkFalseHttpDep,
		},

		// --- consistent control case ---
		{
			name:             "fully-consistent destructive yellow with declared http+write",
			intent:           &Intent{Destructive: true, Network: boolPtr(true), SideEffects: []string{"net:http", "fs:write"}},
			governanceIntent: "yellow",
			deps: []DataDependency{
				{Kind: "http_endpoint", Ref: "https://api.anthropic.com", Access: "read"},
				{Kind: "filesystem", Ref: "/tmp/x", Access: "write"},
			},
			want: RuleNone,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateIntentDataCrossRules(tc.intent, tc.governanceIntent, tc.deps)
			if got != tc.want {
				t.Errorf("ValidateIntentDataCrossRules = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidateManifestCrossRules(t *testing.T) {
	// Smoke test the bundle-shaped wrapper. The detailed rule coverage
	// lives in TestValidateIntentDataCrossRules; this confirms the
	// wrapper just unpacks the manifest correctly.
	m := BundleManifest{
		Schema:                 Schema,
		Name:                   "didactic-session",
		Version:                "1.0.0",
		AuthorGovernanceIntent: "green",
		Intent: &Intent{
			Destructive: true,
			SideEffects: []string{"fs:write"},
		},
	}
	got := ValidateManifestCrossRules(m)
	if got != RuleDestructiveGreen {
		t.Errorf("ValidateManifestCrossRules = %q, want RuleDestructiveGreen", got)
	}

	m2 := BundleManifest{Schema: Schema, Name: "x", Version: "0.1.0"}
	got2 := ValidateManifestCrossRules(m2)
	if got2 != RuleNone {
		t.Errorf("ValidateManifestCrossRules on nil-intent manifest = %q, want RuleNone", got2)
	}
}

func TestExitCodeForViolation(t *testing.T) {
	cases := []struct {
		v    CrossRuleViolation
		want int
	}{
		{RuleNone, 0},
		{RuleDestructiveGreen, 11},
		{RuleNetworkFalseHttpDep, 12},
		{RuleWriteAccessNonDestructive, 12},
		{CrossRuleViolation("future_rule_xyz"), 12}, // forward-compat
	}
	for _, tc := range cases {
		t.Run(string(tc.v), func(t *testing.T) {
			got := ExitCodeForViolation(tc.v)
			if got != tc.want {
				t.Errorf("ExitCodeForViolation(%q) = %d, want %d", tc.v, got, tc.want)
			}
		})
	}
}
