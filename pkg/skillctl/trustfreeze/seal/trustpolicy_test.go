package seal

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

func samePolicy(t *testing.T, a, b TrustPolicy) {
	t.Helper()
	if a.SelfApproval != b.SelfApproval || a.RejectAdditions != b.RejectAdditions || len(a.TrustedKeys) != len(b.TrustedKeys) {
		t.Fatalf("policies differ: %+v vs %+v", a, b)
	}
	for i := range a.TrustedKeys {
		if a.TrustedKeys[i].KeyID != b.TrustedKeys[i].KeyID || !bytes.Equal(a.TrustedKeys[i].PublicKey, b.TrustedKeys[i].PublicKey) {
			t.Fatalf("trusted key %d differs", i)
		}
	}
}

// SPEC-0470 section 4.6: JSON and YAML trust policies with schema
// trust-freeze/trust-policy/v1 load to the same policy.
func TestParseTrustPolicyJSONAndYAML(t *testing.T) {
	s1, s2 := seedSigner(t, seedTrusted), seedSigner(t, seedSecond)
	k1 := base64.StdEncoding.EncodeToString(s1.PublicKey())
	k2 := base64.StdEncoding.EncodeToString(s2.PublicKey())
	jsonDoc := `{"schema_version":"trust-freeze/trust-policy/v1","self_approval":"block","reject_additions":true,` +
		`"trusted_keys":[{"key_id":"` + s1.KeyID() + `","public_key":"` + k1 + `"},{"public_key":"` + k2 + `"}]}`
	yamlDoc := "schema_version: trust-freeze/trust-policy/v1\r\nself_approval: block\r\nreject_additions: true\r\n" +
		"trusted_keys:\r\n  - key_id: " + s1.KeyID() + "\r\n    public_key: " + k1 + "\r\n  - public_key: \"" + k2 + "\"\r\n"
	pj, err := ParseTrustPolicy([]byte(jsonDoc))
	if err != nil {
		t.Fatal(err)
	}
	py, err := ParseTrustPolicy([]byte(yamlDoc))
	if err != nil {
		t.Fatal(err)
	}
	samePolicy(t, pj, py)
	if pj.SelfApproval != SelfApprovalBlock || !pj.RejectAdditions || !pj.Trusts(s1.PublicKey()) || !pj.Trusts(s2.PublicKey()) {
		t.Fatalf("policy %+v", pj)
	}
	if _, ok := pj.Now.(trustfreeze.SystemClock); !ok {
		t.Fatalf("parsed policy clock %T, want SystemClock", pj.Now)
	}

	bom, err := ParseTrustPolicy(append([]byte("\xef\xbb\xbf\n"), jsonDoc...))
	if err != nil {
		t.Fatal(err)
	}
	samePolicy(t, pj, bom)

	minimal, err := ParseTrustPolicy([]byte("schema_version: trust-freeze/trust-policy/v1\ntrusted_keys: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if minimal.SelfApproval != SelfApprovalWarn || !minimal.RejectAdditions || len(minimal.TrustedKeys) != 0 {
		t.Fatalf("defaults: %+v", minimal)
	}

	round, err := MarshalTrustPolicy(pj)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseTrustPolicy(round)
	if err != nil {
		t.Fatal(err)
	}
	pjWithIDs := pj
	pjWithIDs.TrustedKeys = []TrustedKey{{KeyID: s1.KeyID(), PublicKey: s1.PublicKey()}, {KeyID: s2.KeyID(), PublicKey: s2.PublicKey()}}
	samePolicy(t, pjWithIDs, back)
}

func TestParseTrustPolicyRejects(t *testing.T) {
	s := seedSigner(t, seedTrusted)
	k := base64.StdEncoding.EncodeToString(s.PublicKey())
	other := seedSigner(t, seedAttacker).KeyID()
	head := "schema_version: trust-freeze/trust-policy/v1\n"
	cases := map[string]string{
		"empty":                   "",
		"whitespace":              " \n\t",
		"missing-schema":          "trusted_keys: []\n",
		"wrong-schema":            "schema_version: trust-freeze/policy/v1\ntrusted_keys: []\n",
		"unknown-yaml-field":      head + "trusted_keys: []\nallow_everything: true\n",
		"unknown-json-field":      `{"schema_version":"trust-freeze/trust-policy/v1","trusted_keys":[],"x":1}`,
		"trailing-json":           `{"schema_version":"trust-freeze/trust-policy/v1","trusted_keys":[]} {}`,
		"two-yaml-documents":      head + "trusted_keys: []\n---\n" + head,
		"unknown-key-field":       head + "trusted_keys:\n  - public_key: " + k + "\n    note: x\n",
		"bad-base64":              head + "trusted_keys:\n  - public_key: not*base64\n",
		"short-key":               head + "trusted_keys:\n  - public_key: " + base64.StdEncoding.EncodeToString(make([]byte, 31)) + "\n",
		"key-id-of-other-key":     head + "trusted_keys:\n  - key_id: " + other + "\n    public_key: " + k + "\n",
		"duplicate-key":           head + "trusted_keys:\n  - public_key: " + k + "\n  - public_key: " + k + "\n",
		"reject-additions-false":  head + "reject_additions: false\ntrusted_keys: []\n",
		"invalid-self-approval":   head + "self_approval: sometimes\ntrusted_keys: []\n",
		"yaml-bool-self-approval": head + "self_approval: no\ntrusted_keys: []\n",
		"not-a-mapping":           "- a\n- b\n",
		// SPEC-0470 section 4.6: the JSON form parses exactly like the YAML
		// form: a duplicate key (encoding/json keeps the last) and a key that
		// matches a field only case-insensitively are errors, so one file cannot
		// read as block to a reviewer and act as allow.
		"json-duplicate-self-approval": `{"schema_version":"trust-freeze/trust-policy/v1","self_approval":"block","trusted_keys":[],"self_approval":"allow"}`,
		"json-duplicate-schema":        `{"schema_version":"trust-freeze/trust-policy/v1","schema_version":"trust-freeze/trust-policy/v1","trusted_keys":[]}`,
		"json-case-variant-key":        `{"schema_version":"trust-freeze/trust-policy/v1","SELF_APPROVAL":"allow","trusted_keys":[]}`,
		"json-case-variant-list":       `{"schema_version":"trust-freeze/trust-policy/v1","Trusted_Keys":[{"public_key":"` + k + `"}]}`,
		"json-case-variant-nested":     `{"schema_version":"trust-freeze/trust-policy/v1","trusted_keys":[{"PUBLIC_KEY":"` + k + `"}]}`,
		"json-duplicate-nested":        `{"schema_version":"trust-freeze/trust-policy/v1","trusted_keys":[{"public_key":"` + k + `","public_key":"` + k + `"}]}`,
		"yaml-duplicate-self-approval": head + "self_approval: block\ntrusted_keys: []\nself_approval: allow\n",
		"yaml-case-variant-key":        head + "SELF_APPROVAL: allow\ntrusted_keys: []\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseTrustPolicy([]byte(doc)); !errors.Is(err, ErrTrustPolicyInvalid) {
				t.Fatalf("err = %v, want ErrTrustPolicyInvalid", err)
			}
		})
	}
}

func TestLoadTrustPolicyAndKeys(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath := writeKeyFiles(t, dir, "reviewer", seedTrusted)
	tk, err := LoadTrustedKeyPEM(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	s := seedSigner(t, seedTrusted)
	if tk.KeyID != s.KeyID() || !bytes.Equal(tk.PublicKey, s.PublicKey()) {
		t.Fatalf("trusted key %+v", tk)
	}
	if _, err := LoadTrustedKeyPEM(privPath); !errors.Is(err, ErrTrustPolicyInvalid) {
		t.Fatalf("private key accepted as trusted key: %v", err)
	}
	if _, err := LoadTrustedKeyPEM(filepath.Join(dir, "missing.pub")); !errors.Is(err, ErrTrustPolicyInvalid) {
		t.Fatalf("missing file: %v", err)
	}
	if _, err := NewTrustedKey(make([]byte, 16)); !errors.Is(err, ErrTrustPolicyInvalid) {
		t.Fatalf("short key: %v", err)
	}

	big := filepath.Join(dir, "big.yaml")
	if err := os.WriteFile(big, []byte("# "+strings.Repeat("x", maxTrustPolicyBytes)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTrustPolicy(big); !errors.Is(err, ErrTrustPolicyInvalid) {
		t.Fatalf("oversized policy: %v", err)
	}
	if _, err := LoadTrustPolicy(filepath.Join(dir, "missing.yaml")); !errors.Is(err, ErrTrustPolicyInvalid) {
		t.Fatalf("missing policy: %v", err)
	}
}

func TestTrustPolicyTrustsFullKeyOnly(t *testing.T) {
	s, attacker := seedSigner(t, seedTrusted), seedSigner(t, seedAttacker)
	p := TrustPolicy{TrustedKeys: []TrustedKey{{PublicKey: s.PublicKey()}}}
	if err := p.Validate(); err != nil {
		t.Fatalf("key without key id: %v", err)
	}
	if !p.Trusts(s.PublicKey()) || p.Trusts(attacker.PublicKey()) || p.Trusts(nil) {
		t.Fatal("Trusts decided wrongly")
	}
	lying := TrustPolicy{TrustedKeys: []TrustedKey{{KeyID: s.KeyID(), PublicKey: attacker.PublicKey()}}}
	if err := lying.Validate(); !errors.Is(err, ErrTrustPolicyInvalid) {
		t.Fatalf("key id of another key accepted: %v", err)
	}
	d := DefaultTrustPolicy()
	if d.SelfApproval != SelfApprovalWarn || !d.RejectAdditions || d.Now == nil || len(d.TrustedKeys) != 0 {
		t.Fatalf("default policy %+v", d)
	}
	for _, m := range []string{"allow", "warn", "block"} {
		if _, err := ParseSelfApprovalMode(m); err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range []string{"", "Block", "deny"} {
		if _, err := ParseSelfApprovalMode(m); !errors.Is(err, ErrTrustPolicyInvalid) {
			t.Fatalf("mode %q accepted", m)
		}
	}
}
