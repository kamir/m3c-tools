package verify

// SPEC-0279 R5 — emergency deny-list channel tests.
//
// AC3 (emergency half): an emergency deny-list entry denies BEFORE the normal
// cadence — even with a fresh snapshot and a low-risk, fail-open action.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEmergency_SignVerifyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := revocationRoot(t, pub)
	list, err := NewSignedEmergencyDenyList(root.RegistryURL, "2026-06-22T12:00:00Z", 2,
		[]string{"agent:burned", digestOf("compromised-bundle"), "id:rogue@m3c"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	set, err := VerifyEmergencyDenyList(list, root, 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, bad := EmergencyDenies(set, "agent:burned"); !bad {
		t.Error("agent:burned should be emergency-denied")
	}
	if _, bad := EmergencyDenies(set, "id:rogue@m3c"); !bad {
		t.Error("id:rogue@m3c should be emergency-denied")
	}
	if _, bad := EmergencyDenies(set, "agent:innocent"); bad {
		t.Error("agent:innocent must NOT be emergency-denied")
	}
}

func TestEmergency_ForgedSignatureRefused(t *testing.T) {
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	pinned, _, _ := ed25519.GenerateKey(rand.Reader)
	root := revocationRoot(t, pinned)
	list, _ := NewSignedEmergencyDenyList(root.RegistryURL, "2026-06-22T12:00:00Z", 1, []string{"agent:x"}, attacker)
	if _, err := VerifyEmergencyDenyList(list, root, 0); !errors.Is(err, ErrRegistryNotTrusted) {
		t.Fatalf("forged emergency list must be refused, got: %v", err)
	}
}

func TestEmergency_RollbackEpochRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := revocationRoot(t, pub)
	list, _ := NewSignedEmergencyDenyList(root.RegistryURL, "2026-06-22T12:00:00Z", 1, []string{"agent:x"}, priv)
	if _, err := VerifyEmergencyDenyList(list, root, 3); !errors.Is(err, ErrRegistryNotTrusted) {
		t.Fatalf("rollback emergency list must be refused, got: %v", err)
	}
}

func TestEmergency_TamperedTokensBreakSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := revocationRoot(t, pub)
	list, _ := NewSignedEmergencyDenyList(root.RegistryURL, "2026-06-22T12:00:00Z", 1, []string{"agent:x"}, priv)
	list.DeniedTokens = append(list.DeniedTokens, "agent:sneaky") // post-sign tamper
	if _, err := VerifyEmergencyDenyList(list, root, 0); !errors.Is(err, ErrRegistryNotTrusted) {
		t.Fatalf("tampered emergency list must be refused, got: %v", err)
	}
}

// AC3: the emergency channel short-circuits the cadence. We model the consumer's
// FIRST-consult order: even with a perfectly fresh snapshot and a low-risk
// fail-open action (which the normal cadence would ALLOW), an emergency entry
// denies on sight.
func TestAC3_EmergencyShortCircuitsFreshLowRisk(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := revocationRoot(t, pub)

	// Fresh snapshot + low-risk + fail-open → the normal freshness check ALLOWS.
	p := freshPolicy(t, "24h", "open", nil)
	now := mustTime(t, "2026-06-22T01:00:00Z")
	dec, err := EvaluateFreshness(2, "2026-06-22T00:00:00Z", p, RiskLow, now)
	if err != nil || !dec.Allowed {
		t.Fatalf("precondition: fresh low-risk fail-open must allow, got err=%v dec=%+v", err, dec)
	}

	// But the agent is on the emergency deny-list → deny BEFORE the cadence runs.
	em, _ := NewSignedEmergencyDenyList(root.RegistryURL, "2026-06-22T00:30:00Z", 1, []string{"agent:burned"}, priv)
	set, verr := VerifyEmergencyDenyList(em, root, 0)
	if verr != nil {
		t.Fatal(verr)
	}
	if tok, bad := EmergencyDenies(set, "agent:burned"); !bad || tok != "agent:burned" {
		t.Fatalf("emergency must deny agent:burned regardless of fresh+low-risk allow; got tok=%q bad=%v", tok, bad)
	}
}

// LoadVerifiedEmergencyDenyList: a MISSING file is an empty set (opt-in); a
// PRESENT-but-forged file is fail-closed.
func TestEmergency_LoadMissingIsEmpty_PresentForgedFailsClosed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := revocationRoot(t, pub)

	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	set, err := LoadVerifiedEmergencyDenyList(missing, root)
	if err != nil || len(set) != 0 {
		t.Fatalf("missing file must yield empty set, no error; got set=%v err=%v", set, err)
	}

	// Present + good.
	good, _ := NewSignedEmergencyDenyList(root.RegistryURL, "2026-06-22T00:00:00Z", 1, []string{"agent:x"}, priv)
	goodPath := filepath.Join(t.TempDir(), "em.json")
	writeJSON(t, goodPath, good)
	gset, err := LoadVerifiedEmergencyDenyList(goodPath, root)
	if err != nil {
		t.Fatalf("good emergency list load: %v", err)
	}
	if _, bad := EmergencyDenies(gset, "agent:x"); !bad {
		t.Error("agent:x should load as denied")
	}

	// Present + forged → fail-closed.
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := NewSignedEmergencyDenyList(root.RegistryURL, "2026-06-22T00:00:00Z", 1, []string{"agent:y"}, attacker)
	forgedPath := filepath.Join(t.TempDir(), "forged.json")
	writeJSON(t, forgedPath, forged)
	if _, err := LoadVerifiedEmergencyDenyList(forgedPath, root); !errors.Is(err, ErrRegistryNotTrusted) {
		t.Fatalf("present forged emergency list must fail closed, got: %v", err)
	}
}

// Domain separation: an emergency deny-list signature cannot be replayed as a
// revocation list (different canonical type).
func TestEmergency_DomainSeparatedFromRevocationList(t *testing.T) {
	emBytes, err := CanonicalEmergencyDenyBytes("https://reg.example/api/skills", "2026-06-22T00:00:00Z", 1, []string{digestOf("a")})
	if err != nil {
		t.Fatal(err)
	}
	revBytes, err := CanonicalRevocationBytes("https://reg.example/api/skills", "2026-06-22T00:00:00Z", 1, []string{digestOf("a")})
	if err != nil {
		t.Fatal(err)
	}
	if string(emBytes) == string(revBytes) {
		t.Fatal("emergency and revocation canonical bytes must differ (domain separation)")
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
