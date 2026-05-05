package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeBundleForCLI writes a small gzipped tar to dir and returns its path.
// Mirror of pkg/skillctl/signing.makeFakeBundle so the CLI tests don't
// depend on test-only helpers in another package.
func makeBundleForCLI(t *testing.T, dir, name string) string {
	t.Helper()
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	body := []byte("# tiny test skill\n")
	if err := tw.WriteHeader(&tar.Header{
		Name: "tiny/SKILL.md",
		Mode: 0o644,
		Size: int64(len(body)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestEndToEnd covers all five acceptance scenarios in PLAN
// §170-180 against the actual CLI runner functions.
//
//	AC1 — keygen produces a valid pair
//	AC2 — sign writes a 64-byte sig at the canonical path
//	AC3 — verify-sig exits 0 for a valid sig
//	AC4 — tampered bundle → non-zero exit
//	AC5 — wrong pubkey → non-zero exit (and specifically exit 11)
func TestEndToEnd(t *testing.T) {
	dir := t.TempDir()
	bundle := makeBundleForCLI(t, dir, "demo.skb")
	keyA := filepath.Join(dir, "kA")
	keyB := filepath.Join(dir, "kB")

	var stdout, stderr bytes.Buffer

	// AC1
	if code := runKeygen([]string{"--out", keyA}, &stdout, &stderr); code != 0 {
		t.Fatalf("AC1 keygen exit=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(keyA + ".priv"); err != nil {
		t.Fatalf("AC1: priv missing: %v", err)
	}
	if _, err := os.Stat(keyA + ".pub"); err != nil {
		t.Fatalf("AC1: pub missing: %v", err)
	}

	// AC2
	stdout.Reset()
	stderr.Reset()
	if code := runSign([]string{"--key", keyA + ".priv", "--identity-id", "id:test@m3c", bundle}, &stdout, &stderr); code != 0 {
		t.Fatalf("AC2 sign exit=%d stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "digest:") || !strings.Contains(out, "signature:") {
		t.Errorf("AC2: sign stdout missing digest/signature lines: %q", out)
	}
	matches, err := filepath.Glob(bundle + ".*.author.sig")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("AC2: want exactly 1 .author.sig file, got %d: %v", len(matches), matches)
	}
	sig, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Errorf("AC2: signature size = %d bytes, want 64", len(sig))
	}

	// AC3
	stdout.Reset()
	stderr.Reset()
	if code := runVerifySig([]string{"--pubkey", keyA + ".pub", bundle}, &stdout, &stderr); code != 0 {
		t.Fatalf("AC3 verify-sig exit=%d stderr=%s", code, stderr.String())
	}

	// AC4: tamper one byte. The sig file at the OLD digest path stays
	// where it was; the verifier recomputes the digest, builds a NEW
	// path, and finds nothing there → non-zero exit.
	raw, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xFF
	if err := os.WriteFile(bundle, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runVerifySig([]string{"--pubkey", keyA + ".pub", bundle}, &stdout, &stderr); code == 0 {
		t.Fatalf("AC4: tampered bundle accepted (exit=0); want non-zero. stderr=%s", stderr.String())
	}

	// AC5: sign demo2 with key A, verify with key B → exit 11.
	bundle2 := makeBundleForCLI(t, dir, "demo2.skb")
	if code := runKeygen([]string{"--out", keyB}, &stdout, &stderr); code != 0 {
		t.Fatalf("AC5 keygen B exit=%d", code)
	}
	if code := runSign([]string{"--key", keyA + ".priv", bundle2}, &stdout, &stderr); code != 0 {
		t.Fatalf("AC5 sign exit=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runVerifySig([]string{"--pubkey", keyB + ".pub", bundle2}, &stdout, &stderr); code != exitSigInval {
		t.Fatalf("AC5: wrong-pubkey exit=%d, want %d (exitSigInval). stderr=%s", code, exitSigInval, stderr.String())
	}
}

func TestRunKeygen_UsageErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runKeygen([]string{}, &stdout, &stderr); code != exitUsage {
		t.Errorf("missing --out exit=%d, want %d", code, exitUsage)
	}
}

func TestRunSign_UsageErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// Missing positional bundle arg.
	if code := runSign([]string{"--key", "/tmp/k.priv"}, &stdout, &stderr); code != exitUsage {
		t.Errorf("missing bundle exit=%d, want %d", code, exitUsage)
	}
	// Missing --key.
	stdout.Reset()
	stderr.Reset()
	if code := runSign([]string{"/tmp/x.skb"}, &stdout, &stderr); code != exitUsage {
		t.Errorf("missing --key exit=%d, want %d", code, exitUsage)
	}
}

func TestRunVerifySig_UsageErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runVerifySig([]string{"--pubkey", "/tmp/k.pub"}, &stdout, &stderr); code != exitUsage {
		t.Errorf("missing bundle exit=%d, want %d", code, exitUsage)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runVerifySig([]string{"/tmp/x.skb"}, &stdout, &stderr); code != exitUsage {
		t.Errorf("missing --pubkey exit=%d, want %d", code, exitUsage)
	}
}
