package skillgate

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// BUG-0143: Attenuation.Value was map[string]any, so a wire token whose
// attenuation value is a scalar (`"value": 60`) or a list
// (`"value": ["a.example"]`) could not even be decoded, and Verify refused
// it. The canonical-parity vectors for both shapes already exist
// (testdata/canonical-vectors.jsonl); this test drives the same wire tokens
// through json.Unmarshal AND Verify, which is the acceptance the report names.
//
// The vectors are canonicalization fixtures, not valid chains (the list
// vector's envelope is wider than its own shrink), and they carry no
// signature. So each test edits the RAW wire JSON into a consistent chain,
// decodes it the way the gateway does, signs it with a throwaway key over
// CanonicalizeToken, and verifies at a clock inside its validity window.
// Editing the raw JSON, not the struct, keeps this file compiling against the
// old map[string]any type, so a revert fails at the decode, as the bug did.

func vectorToken(t *testing.T, name string, edit func(tok map[string]any)) *Token {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "canonical-vectors.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var row struct {
			Name  string          `json:"name"`
			Token json.RawMessage `json:"token"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		if row.Name != name {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal(row.Token, &raw); err != nil {
			t.Fatal(err)
		}
		if edit != nil {
			edit(raw)
		}
		wire, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		var tok Token
		if err := json.Unmarshal(wire, &tok); err != nil {
			t.Fatalf("%s: wire token does not decode: %v", name, err)
		}
		return &tok
	}
	t.Fatalf("vector %q not found", name)
	return nil
}

func signAndVerify(t *testing.T, tok *Token) VerifyResult {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	msg, err := CanonicalizeToken(tok)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	tok.SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	issued, err := time.Parse("2006-01-02T15:04:05Z", tok.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	return verifyAt(tok, makeRoots(tok.RegistryKeyID, pub), issued.Add(time.Minute))
}

// setAttenuationValue replaces the first attenuation's wire value.
func setAttenuationValue(v any) func(map[string]any) {
	return func(tok map[string]any) {
		tok["attenuations"].([]any)[0].(map[string]any)["value"] = v
	}
}

// setEnvelope sets one envelope field, to make a fixture a consistent chain.
func setEnvelope(field string, v any) func(map[string]any) {
	return func(tok map[string]any) {
		tok["envelope"].(map[string]any)[field] = v
	}
}

func both(a, b func(map[string]any)) func(map[string]any) {
	return func(tok map[string]any) { a(tok); b(tok) }
}

func TestVerify_ScalarAndListAttenuationValues(t *testing.T) {
	cases := []struct {
		vector, rule string
		edit         func(map[string]any)
		check        func(any) bool
	}{
		// envelope max_runtime_seconds 60, shrink to 60: consistent as shipped.
		{"scalar-attenuation", "shrink_max_runtime_seconds", nil,
			func(v any) bool { n, ok := v.(float64); return ok && n == 60 }},
		// shrink to [c.example, a.example]; the final envelope must lie inside it.
		{"list-attenuation", "shrink_egress_allowlist", setEnvelope("egress_allowlist", []any{"a.example", "c.example"}),
			func(v any) bool { l, ok := v.([]any); return ok && len(l) == 2 }},
	}
	for _, c := range cases {
		t.Run(c.vector, func(t *testing.T) {
			tok := vectorToken(t, c.vector, c.edit)
			if len(tok.Attenuations) != 1 || tok.Attenuations[0].Rule != c.rule {
				t.Fatalf("vector changed shape: %+v", tok.Attenuations)
			}
			if v := any(tok.Attenuations[0].Value); !c.check(v) {
				t.Fatalf("value decoded as %T %v, not as the wire shape", v, v)
			}
			if res := signAndVerify(t, tok); !res.OK {
				t.Fatalf("Verify refused a %s chain: %s", c.vector, res.Reason)
			}
		})
	}
}

// Counter-check, so the test above cannot pass by Verify accepting anything:
// the same scalar and list shapes that GROW the envelope are refused.
func TestVerify_ScalarAndListAttenuationStillRefuseGrowth(t *testing.T) {
	tok := vectorToken(t, "scalar-attenuation", setAttenuationValue(30)) // envelope says 60: the chain grew
	if res := signAndVerify(t, tok); res.OK || res.Reason != "envelope_grew" {
		t.Fatalf("scalar growth: want envelope_grew, got OK=%v reason=%s", res.OK, res.Reason)
	}
	tok = vectorToken(t, "list-attenuation", both(
		setEnvelope("egress_allowlist", []any{"a.example", "c.example"}),
		setAttenuationValue([]any{"a.example"}))) // envelope also has c.example
	if res := signAndVerify(t, tok); res.OK || res.Reason != "envelope_grew" {
		t.Fatalf("list growth: want envelope_grew, got OK=%v reason=%s", res.OK, res.Reason)
	}
}

// The legacy {"_value": <inner>} wrapper that pre-BUG-0143 Go callers used is
// still read the same way.
func TestVerify_LegacyValueWrapperStillAccepted(t *testing.T) {
	tok := vectorToken(t, "scalar-attenuation", setAttenuationValue(map[string]any{"_value": 60}))
	if res := signAndVerify(t, tok); !res.OK {
		t.Fatalf("legacy wrapper refused: %s", res.Reason)
	}
}
