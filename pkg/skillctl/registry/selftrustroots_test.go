package registry

// SEC-L1 regression tests for the `self`-tenant trust-roots loader.
//
//   (a) governance_minimum: "red" (and any non-floor value) must be REJECTED —
//       "red" as a floor would silently admit everything, defeating the gate.
//       Only "green" and "yellow" are valid floors.
//   (b) the loader must use STRICT YAML decoding (KnownFields(true)) so an
//       unknown / typo'd field fails loudly instead of being silently ignored.
//
// Both behaviours mirror the SPEC-0188 strict loader in verify/trustroots.go.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validPubKeyB64 returns a base64 of a real raw ed25519 public key, so the
// loader's pubkey checks pass and a test failure can be attributed to the
// field under test rather than a malformed key.
func validPubKeyB64(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(pub)
}

// writeSelfTrustRoots writes a raw self trust-roots YAML body to a temp file and
// returns its path. Named distinctly from the er1_pull_test.go helper of the
// same package (which takes an ed25519.PublicKey and synthesizes the body) so
// the two test files do not collide.
func writeSelfTrustRoots(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "trust-roots.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return p
}

// SEC-L1(a): governance_minimum: red must be refused.
func TestLoadSelfTrustRoots_RejectsRedFloor(t *testing.T) {
	body := "registry: self\n" +
		"pubkey_b64: " + validPubKeyB64(t) + "\n" +
		"governance_minimum: red\n"
	p := writeSelfTrustRoots(t, body)

	tr, err := LoadSelfTrustRoots(p)
	if err == nil {
		t.Fatalf("expected governance_minimum: red to be rejected, got tr=%+v", tr)
	}
	if !strings.Contains(err.Error(), "governance_minimum") {
		t.Fatalf("error should name governance_minimum, got: %v", err)
	}
}

// SEC-L1(a): an arbitrary unknown floor value is also refused.
func TestLoadSelfTrustRoots_RejectsUnknownFloor(t *testing.T) {
	body := "registry: self\n" +
		"pubkey_b64: " + validPubKeyB64(t) + "\n" +
		"governance_minimum: purple\n"
	p := writeSelfTrustRoots(t, body)

	if tr, err := LoadSelfTrustRoots(p); err == nil {
		t.Fatalf("expected unknown floor to be rejected, got tr=%+v", tr)
	}
}

// SEC-L1(a): the valid floors still load.
func TestLoadSelfTrustRoots_AcceptsGreenAndYellow(t *testing.T) {
	for _, floor := range []string{"green", "yellow", "GREEN", "Yellow"} {
		body := "registry: self\n" +
			"pubkey_b64: " + validPubKeyB64(t) + "\n" +
			"governance_minimum: " + floor + "\n"
		p := writeSelfTrustRoots(t, body)
		tr, err := LoadSelfTrustRoots(p)
		if err != nil {
			t.Fatalf("floor %q should load, got: %v", floor, err)
		}
		if tr == nil {
			t.Fatalf("floor %q: nil trust-roots", floor)
		}
	}
}

// SEC-L1(a): an absent governance_minimum still defaults to green and loads.
func TestLoadSelfTrustRoots_DefaultFloorLoads(t *testing.T) {
	body := "registry: self\n" +
		"pubkey_b64: " + validPubKeyB64(t) + "\n"
	p := writeSelfTrustRoots(t, body)
	tr, err := LoadSelfTrustRoots(p)
	if err != nil {
		t.Fatalf("default floor should load, got: %v", err)
	}
	if tr.GovernanceMinimum != "green" {
		t.Fatalf("default floor = %q, want green", tr.GovernanceMinimum)
	}
}

// SEC-L1(b): a typo'd / unknown YAML field must fail loudly (strict decoding),
// not be silently ignored. Before the fix, `governance_minumum` (typo) would be
// dropped and the floor would default to green without any signal to the user.
func TestLoadSelfTrustRoots_StrictRejectsUnknownField(t *testing.T) {
	body := "registry: self\n" +
		"pubkey_b64: " + validPubKeyB64(t) + "\n" +
		"governance_minumum: yellow\n" // deliberate typo: minumum
	p := writeSelfTrustRoots(t, body)

	tr, err := LoadSelfTrustRoots(p)
	if err == nil {
		t.Fatalf("expected strict decode to reject the unknown field, got tr=%+v", tr)
	}
	if !strings.Contains(err.Error(), "parse") && !strings.Contains(err.Error(), "field") {
		t.Logf("strict-decode error (informational): %v", err)
	}
}

// SEC-L1(b): a completely bogus extra field is rejected too.
func TestLoadSelfTrustRoots_StrictRejectsExtraneousField(t *testing.T) {
	body := "registry: self\n" +
		"pubkey_b64: " + validPubKeyB64(t) + "\n" +
		"governance_minimum: green\n" +
		"trusted_everything: true\n"
	p := writeSelfTrustRoots(t, body)

	if tr, err := LoadSelfTrustRoots(p); err == nil {
		t.Fatalf("expected strict decode to reject an extraneous field, got tr=%+v", tr)
	}
}
