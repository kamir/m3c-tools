package datascope

import (
	"errors"
	"testing"
)

func ptrBool(b bool) *bool { return &b }

// failedRule extracts the §3.3 rule name from an error, "" if not a
// ValidationError or no rule fired.
func failedRule(err error) string {
	var ve *ValidationError
	if errors.As(err, &ve) {
		return ve.FailedRule
	}
	return ""
}

func TestDataScope_Validate_OK(t *testing.T) {
	cases := []DataScope{
		{ID: "ds:er1/plm/skill-creations", Kind: KindER1Collection, Access: AccessRead, Reason: "seed"},
		{ID: "ds:filesystem/cwd", Kind: KindLocalFS, Access: AccessWrite, Scope: "<cwd>/decks/**", Reason: "write decks"},
		{ID: "ds:http/anthropic", Kind: KindHTTPEndpoint, Access: AccessPassthrough, Scope: "https://api.anthropic.com/*", Reason: "llm"},
		{ID: "ds:gcs/bucket", Kind: KindGCSBucket, Access: AccessRead, Reason: "read blobs"},
		{ID: "ds:secret/keychain", Kind: KindSecretsStore, Access: AccessRead, Reason: "read api key"},
		{ID: "ds:fs/transform", Kind: KindLocalFS, Access: AccessTransform, Scope: "<cwd>/out/**", Reason: "transform"},
		{ID: "ds:fs/readall", Kind: KindLocalFS, Access: AccessRead, Reason: "read broadly (no scope ok for read)"},
	}
	for _, c := range cases {
		if err := c.Validate(); err != nil {
			t.Errorf("Validate(%+v) = %v, want nil", c, err)
		}
	}
}

func TestDataScope_Validate_Rejects(t *testing.T) {
	cases := []struct {
		name string
		d    DataScope
	}{
		{"empty id", DataScope{Kind: KindLocalFS, Access: AccessRead, Scope: "x/**"}},
		{"id not ds-prefixed", DataScope{ID: "er1/x", Kind: KindER1Collection, Access: AccessRead}},
		{"unknown kind", DataScope{ID: "ds:x", Kind: "kafka_topic", Access: AccessRead}},
		{"unknown access", DataScope{ID: "ds:x", Kind: KindLocalFS, Access: "delete", Scope: "a/**"}},
		{"local_fs without scope", DataScope{ID: "ds:x", Kind: KindLocalFS, Access: AccessWrite}},
		{"local_fs unbounded scope", DataScope{ID: "ds:x", Kind: KindLocalFS, Access: AccessWrite, Scope: "**"}},
		{"http without scope", DataScope{ID: "ds:x", Kind: KindHTTPEndpoint, Access: AccessRead}},
		{"http non-https", DataScope{ID: "ds:x", Kind: KindHTTPEndpoint, Access: AccessRead, Scope: "http://api.example.com/*"}},
		{"http no host", DataScope{ID: "ds:x", Kind: KindHTTPEndpoint, Access: AccessRead, Scope: "https://*"}},
		{"gcs write without scope", DataScope{ID: "ds:x", Kind: KindGCSBucket, Access: AccessWrite}},
		{"er1 scope with scheme", DataScope{ID: "ds:x", Kind: KindER1Collection, Access: AccessRead, Scope: "https://x"}},
		{"secrets write", DataScope{ID: "ds:x", Kind: KindSecretsStore, Access: AccessWrite}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.d.Validate(); err == nil {
				t.Errorf("Validate(%+v) = nil, want error", c.d)
			}
		})
	}
}

func TestValidateSideEffects(t *testing.T) {
	if err := ValidateSideEffects([]string{"fs:write", "llm:call", "secrets:read"}); err != nil {
		t.Errorf("valid side effects rejected: %v", err)
	}
	if err := ValidateSideEffects([]string{"UNKNOWN"}); err != nil {
		t.Errorf("awareness sentinel UNKNOWN must be tolerated: %v", err)
	}
	if err := ValidateSideEffects([]string{"fs:write", "fs:nuke"}); err == nil {
		t.Errorf("out-of-vocabulary side effect accepted, want error")
	}
}

func TestCrossRule_DestructiveGreen(t *testing.T) {
	in := Intent{Destructive: ptrBool(true), SideEffects: []string{"fs:delete"}}
	err := Validate(in, nil, "green")
	if got := failedRule(err); got != RuleDestructiveGreen {
		t.Fatalf("failed_rule = %q, want %q (err=%v)", got, RuleDestructiveGreen, err)
	}
	// destructive + yellow is fine.
	if err := Validate(in, nil, "yellow"); err != nil {
		t.Errorf("destructive+yellow rejected: %v", err)
	}
}

func TestCrossRule_NetworkFalseHTTPDep(t *testing.T) {
	in := Intent{Network: ptrBool(true), SideEffects: []string{"network:outbound"}}
	// network=true but no http dep.
	err := Validate(in, []DataScope{{ID: "ds:fs", Kind: KindLocalFS, Access: AccessRead, Scope: "a/**"}}, "yellow")
	if got := failedRule(err); got != RuleNetworkFalseHTTPDep {
		t.Fatalf("failed_rule = %q, want %q (err=%v)", got, RuleNetworkFalseHTTPDep, err)
	}
	// network=true WITH an http dep is fine.
	ok := []DataScope{{ID: "ds:http", Kind: KindHTTPEndpoint, Access: AccessPassthrough, Scope: "https://api.anthropic.com/*"}}
	if err := Validate(in, ok, "yellow"); err != nil {
		t.Errorf("network+http dep rejected: %v", err)
	}
}

func TestCrossRule_WriteAccessNonDestructive(t *testing.T) {
	in := Intent{Destructive: ptrBool(false), SideEffects: []string{"fs:write"}}
	scopes := []DataScope{{ID: "ds:fs", Kind: KindLocalFS, Access: AccessWrite, Scope: "<cwd>/out/**"}}
	err := Validate(in, scopes, "yellow")
	if got := failedRule(err); got != RuleWriteAccessNonDestr {
		t.Fatalf("failed_rule = %q, want %q (err=%v)", got, RuleWriteAccessNonDestr, err)
	}
	// transform also trips it.
	scopes[0].Access = AccessTransform
	if got := failedRule(Validate(in, scopes, "yellow")); got != RuleWriteAccessNonDestr {
		t.Errorf("transform did not trip write rule")
	}
	// write + destructive=true is consistent.
	in.Destructive = ptrBool(true)
	scopes[0].Access = AccessWrite
	if err := Validate(in, scopes, "yellow"); err != nil {
		t.Errorf("write+destructive=true rejected: %v", err)
	}
}

func TestCrossRule_MissingDestructiveDoesNotTripWriteRule(t *testing.T) {
	// destructive absent (nil) + a write dep: rule 3 must NOT fire (only fires
	// on an explicit false). pack-time requires destructive, not this validator.
	in := Intent{SideEffects: []string{"fs:write"}}
	scopes := []DataScope{{ID: "ds:fs", Kind: KindLocalFS, Access: AccessWrite, Scope: "<cwd>/out/**"}}
	if err := Validate(in, scopes, "yellow"); err != nil {
		t.Errorf("absent destructive + write tripped a rule: %v", err)
	}
}

func TestValidate_HappyPath(t *testing.T) {
	in := Intent{
		SideEffects: []string{"fs:write", "llm:call"},
		Destructive: ptrBool(false),
		Network:     ptrBool(true),
	}
	scopes := []DataScope{
		{ID: "ds:er1/plm", Kind: KindER1Collection, Access: AccessRead, Reason: "seed"},
		{ID: "ds:http/anthropic", Kind: KindHTTPEndpoint, Access: AccessPassthrough, Scope: "https://api.anthropic.com/*", Reason: "llm"},
	}
	if err := Validate(in, scopes, "yellow"); err != nil {
		t.Fatalf("happy path rejected: %v", err)
	}
}

func TestFromMap_RoundTrip(t *testing.T) {
	raw := map[string]any{
		"id":     "ds:filesystem/cwd",
		"kind":   "local_fs",
		"access": "write",
		"scope":  "<cwd>/decks/**",
		"reason": "write decks",
		"extra":  "ignored", // forward-compat unknown key
	}
	d, err := FromMap(raw)
	if err != nil {
		t.Fatalf("FromMap: %v", err)
	}
	if d.ID != "ds:filesystem/cwd" || d.Kind != KindLocalFS || d.Access != AccessWrite || d.Scope != "<cwd>/decks/**" {
		t.Fatalf("decoded wrong: %+v", d)
	}
	if err := d.Validate(); err != nil {
		t.Errorf("decoded scope failed validation: %v", err)
	}
}

func TestIntentFromMap(t *testing.T) {
	m := map[string]any{
		"side_effects": []any{"fs:write", "llm:call"},
		"destructive":  false,
		"network":      true,
	}
	in := IntentFromMap(m)
	if len(in.SideEffects) != 2 {
		t.Fatalf("side_effects len = %d", len(in.SideEffects))
	}
	if in.Destructive == nil || *in.Destructive {
		t.Errorf("destructive not decoded as false")
	}
	if in.Network == nil || !*in.Network {
		t.Errorf("network not decoded as true")
	}
	// absent fields stay nil
	in2 := IntentFromMap(map[string]any{})
	if in2.Destructive != nil || in2.Network != nil {
		t.Errorf("absent fields should be nil pointers")
	}
}
