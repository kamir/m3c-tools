package main

// SPEC-0276 R4.3 — end-to-end tests for `skillctl export-verification-kit`.
// The decisive test (TestExportKit_BuildsAndReverifies) proves the round trip:
// export a kit, then verify it with ONLY the kit's own files — the trustless
// third-party path, demonstrated.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

func TestExportKit_BuildsAndReverifies(t *testing.T) {
	f := buildBundleFixture(t)
	kit := filepath.Join(t.TempDir(), "kit")

	var out, errBuf bytes.Buffer
	code := runExportKit([]string{"--bundle", f.skbPath, "--trust-roots", f.trPath, "--out", kit}, &out, &errBuf)
	if code != exitOK {
		t.Fatalf("export want 0, got %d; stderr=%s", code, errBuf.String())
	}

	for _, want := range []string{"demo@1.0.0.skb", "demo@1.0.0.skbmeta.json", "trust-roots.pinned.yaml", "VERIFY.md", "verify.sh"} {
		if _, err := os.Stat(filepath.Join(kit, want)); err != nil {
			t.Errorf("kit missing %s", want)
		}
	}

	// The decisive check: verify using ONLY the kit's files (no original paths).
	var vout, verr bytes.Buffer
	vc := runVerify([]string{
		"--bundle", filepath.Join(kit, "demo@1.0.0.skb"),
		"--trust-roots", filepath.Join(kit, "trust-roots.pinned.yaml"),
	}, &vout, &verr)
	if vc != exitOK {
		t.Fatalf("re-verify from kit want 0, got %d; stderr=%s", vc, verr.String())
	}

	// VERIFY.md must carry the expected digest and an out-of-band fingerprint.
	md, _ := os.ReadFile(filepath.Join(kit, "VERIFY.md"))
	if !bytes.Contains(md, []byte(f.digest)) || !bytes.Contains(md, []byte("fingerprint:")) {
		t.Errorf("VERIFY.md missing digest or fingerprint:\n%s", md)
	}
}

func TestExportKit_SecretScrubRefuses(t *testing.T) {
	f := buildBundleFixture(t)
	// Inject a secret into a benign extra field of the sidecar: json.Unmarshal
	// ignores it (so verify still passes) but its raw bytes trip the scrub.
	raw, _ := os.ReadFile(f.metaPath)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["note"] = "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBg...\n-----END PRIVATE KEY-----"
	patched, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(f.metaPath, patched, 0o644); err != nil {
		t.Fatal(err)
	}

	kit := filepath.Join(t.TempDir(), "kit")
	var out, errBuf bytes.Buffer
	code := runExportKit([]string{"--bundle", f.skbPath, "--trust-roots", f.trPath, "--out", kit}, &out, &errBuf)
	if code != exitGeneric {
		t.Fatalf("want exitGeneric on secret, got %d", code)
	}
	if !bytes.Contains(errBuf.Bytes(), []byte("secret-scrub")) {
		t.Errorf("expected secret-scrub message; stderr=%s", errBuf.String())
	}
	// Nothing should have been written (scrub runs before any file write).
	if _, err := os.Stat(filepath.Join(kit, "demo@1.0.0.skb")); err == nil {
		t.Error("kit .skb should NOT have been written after scrub failure")
	}
}

func TestExportKit_WithRevocations(t *testing.T) {
	f := buildBundleFixture(t)
	// A valid list (signed by the pinned reg key) that does NOT revoke this
	// bundle — should be included, and the kit still verifies.
	other := sha256.Sum256([]byte("unrelated"))
	list, err := verify.NewSignedRevocationList(f.regURL, "2026-06-22T10:00:00Z", 1,
		[]string{"sha256:" + hex.EncodeToString(other[:])}, f.regPriv)
	if err != nil {
		t.Fatal(err)
	}
	revPath := writeRevocations(t, f.dir, list)

	kit := filepath.Join(t.TempDir(), "kit")
	var out, errBuf bytes.Buffer
	code := runExportKit([]string{"--bundle", f.skbPath, "--trust-roots", f.trPath, "--revocations", revPath, "--out", kit}, &out, &errBuf)
	if code != exitOK {
		t.Fatalf("export with revocations want 0, got %d; stderr=%s", code, errBuf.String())
	}
	if _, err := os.Stat(filepath.Join(kit, "revocations.json")); err != nil {
		t.Errorf("kit missing revocations.json")
	}
	// Re-verify from the kit WITH the revocation list → still 0.
	var vout, verr bytes.Buffer
	vc := runVerify([]string{
		"--bundle", filepath.Join(kit, "demo@1.0.0.skb"),
		"--trust-roots", filepath.Join(kit, "trust-roots.pinned.yaml"),
		"--revocations", filepath.Join(kit, "revocations.json"),
	}, &vout, &verr)
	if vc != exitOK {
		t.Fatalf("re-verify with revocations want 0, got %d; stderr=%s", vc, verr.String())
	}
}

func TestExportKit_RefusesAlreadyRevokedBundle(t *testing.T) {
	f := buildBundleFixture(t)
	// A list that DOES revoke this bundle → export refuses (don't ship a kit for
	// a dead bundle).
	list, err := verify.NewSignedRevocationList(f.regURL, "2026-06-22T10:00:00Z", 1, []string{f.digest}, f.regPriv)
	if err != nil {
		t.Fatal(err)
	}
	revPath := writeRevocations(t, f.dir, list)

	kit := filepath.Join(t.TempDir(), "kit")
	var out, errBuf bytes.Buffer
	code := runExportKit([]string{"--bundle", f.skbPath, "--trust-roots", f.trPath, "--revocations", revPath, "--out", kit}, &out, &errBuf)
	if code != exitBundleRevoked {
		t.Fatalf("want exit 17 for already-revoked bundle, got %d", code)
	}
}

func TestExportKit_RefusesBrokenBundle(t *testing.T) {
	f := buildBundleFixture(t)
	// Tamper the .skb after the meta was signed → self-validate fails → no kit.
	skb, _ := os.ReadFile(f.skbPath)
	_ = os.WriteFile(f.skbPath, append(skb, 'Z'), 0o644)

	kit := filepath.Join(t.TempDir(), "kit")
	var out, errBuf bytes.Buffer
	code := runExportKit([]string{"--bundle", f.skbPath, "--trust-roots", f.trPath, "--out", kit}, &out, &errBuf)
	if code != 10 {
		t.Fatalf("want exit 10 (broken bundle), got %d; stderr=%s", code, errBuf.String())
	}
}

func TestExportKit_ZipProduced(t *testing.T) {
	f := buildBundleFixture(t)
	kit := filepath.Join(t.TempDir(), "kit")
	var out, errBuf bytes.Buffer
	code := runExportKit([]string{"--bundle", f.skbPath, "--trust-roots", f.trPath, "--out", kit, "--zip"}, &out, &errBuf)
	if code != exitOK {
		t.Fatalf("want 0, got %d; stderr=%s", code, errBuf.String())
	}
	if _, err := os.Stat(kit + ".zip"); err != nil {
		t.Errorf("expected %s.zip", kit)
	}
	if !bytes.Contains(out.Bytes(), []byte("zip:")) {
		t.Errorf("stdout should mention the zip; got %s", out.String())
	}
}
