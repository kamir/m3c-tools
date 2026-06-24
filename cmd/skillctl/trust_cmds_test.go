package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeTestPubkey produces a PEM SPKI ed25519 public key file. Same shape
// the `skillctl keygen` subcommand emits — the trust commands accept that
// format so the round-trip is honest.
func writeTestPubkey(t *testing.T, dir, name string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pemBytes, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// withTrustConfig redirects the package-level trustConfigPath to a temp
// file for the duration of the test so the user's real
// ~/.claude/skill-trust-roots.yaml is never touched.
func withTrustConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "skill-trust-roots.yaml")
	orig := trustConfigPath
	trustConfigPath = func() string { return cfg }
	t.Cleanup(func() { trustConfigPath = orig })
	return cfg
}

func TestTrust_NoArgs_PrintsUsage(t *testing.T) {
	_ = withTrustConfig(t)
	var stdout, stderr bytes.Buffer
	if code := runTrust(nil, &stdout, &stderr); code != exitUsage {
		t.Errorf("runTrust() exit=%d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "Usage: skillctl trust") {
		t.Errorf("stderr should print usage; got %q", stderr.String())
	}
}

func TestTrust_UnknownVerb(t *testing.T) {
	_ = withTrustConfig(t)
	var stdout, stderr bytes.Buffer
	if code := runTrust([]string{"frobnicate"}, &stdout, &stderr); code != exitUsage {
		t.Errorf("unknown verb exit=%d, want %d", code, exitUsage)
	}
}

func TestTrust_Help(t *testing.T) {
	_ = withTrustConfig(t)
	var stdout, stderr bytes.Buffer
	if code := runTrust([]string{"--help"}, &stdout, &stderr); code != exitOK {
		t.Errorf("--help exit=%d, want %d", code, exitOK)
	}
	out := stdout.String()
	// Numbered exit codes per SPEC §11 must be advertised.
	for _, want := range []string{"10", "11", "12", "13", "14", "15", "digest mismatch", "author signature invalid"} {
		if !strings.Contains(out, want) {
			t.Errorf("--help output missing %q\n--- got ---\n%s", want, out)
		}
	}
}

func TestTrust_List_FreshMachine(t *testing.T) {
	_ = withTrustConfig(t)
	var stdout, stderr bytes.Buffer
	if code := runTrust([]string{"list"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("trust list exit=%d, stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "no trust roots configured") {
		t.Errorf("expected fresh-machine hint; got: %s", out)
	}
}

func TestTrust_AddListRemove_Roundtrip(t *testing.T) {
	cfg := withTrustConfig(t)
	dir := filepath.Dir(cfg)
	pubPath := writeTestPubkey(t, dir, "k.pub")

	var stdout, stderr bytes.Buffer

	// add
	args := []string{"add", "--registry", "https://aims.example.com/api/skills", "--pubkey", pubPath, "--id", "aims-core-dev"}
	if code := runTrust(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("trust add exit=%d, stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(cfg); err != nil {
		t.Fatalf("config not written: %v", err)
	}
	// File mode should be 0600 — a real security check on the trust config.
	// SEC-WIN: Windows reports a 0600-written file back as 0666 (ACLs, not
	// POSIX bits), so the assertion is kept full-strength on Unix and only
	// platform-gated where the OS cannot honour the mode.
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(cfg)
		if mode := st.Mode().Perm(); mode != 0o600 {
			t.Errorf("config mode = %#o, want 0600", mode)
		}
	}

	// list — should show the registry and the key.
	stdout.Reset()
	stderr.Reset()
	if code := runTrust([]string{"list"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("trust list exit=%d, stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"https://aims.example.com/api/skills", "aims-core-dev", "from-registry", "green"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output missing %q\n--- got ---\n%s", want, out)
		}
	}

	// remove
	stdout.Reset()
	stderr.Reset()
	if code := runTrust([]string{"remove", "--registry", "https://aims.example.com/api/skills"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("trust remove exit=%d, stderr=%s", code, stderr.String())
	}

	// list again — should be empty.
	stdout.Reset()
	stderr.Reset()
	if code := runTrust([]string{"list"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("trust list (after remove) exit=%d, stderr=%s", code, stderr.String())
	}
	out = stdout.String()
	if strings.Contains(out, "aims.example.com") {
		t.Errorf("remove didn't take effect; list shows: %s", out)
	}
}

func TestTrustAdd_MultipleKeys_RotationOverlap(t *testing.T) {
	cfg := withTrustConfig(t)
	dir := filepath.Dir(cfg)
	pub1 := writeTestPubkey(t, dir, "k1.pub")
	pub2 := writeTestPubkey(t, dir, "k2.pub")

	var stdout, stderr bytes.Buffer

	if code := runTrust([]string{"add", "--registry", "https://r/api/skills", "--pubkey", pub1, "--id", "k1"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("add k1: stderr=%s", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runTrust([]string{"add", "--registry", "https://r/api/skills", "--pubkey", pub2, "--id", "k2"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("add k2: stderr=%s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := runTrust([]string{"list"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("list: %s", stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "k1") || !strings.Contains(out, "k2") {
		t.Errorf("expected both k1 and k2 in list; got:\n%s", out)
	}
}

func TestTrustAdd_DuplicateID_Fails(t *testing.T) {
	cfg := withTrustConfig(t)
	dir := filepath.Dir(cfg)
	pub1 := writeTestPubkey(t, dir, "k1.pub")
	pub2 := writeTestPubkey(t, dir, "k2.pub")

	var stdout, stderr bytes.Buffer
	if code := runTrust([]string{"add", "--registry", "https://r/api/skills", "--pubkey", pub1, "--id", "same"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("first add: %s", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runTrust([]string{"add", "--registry", "https://r/api/skills", "--pubkey", pub2, "--id", "same"}, &stdout, &stderr); code == exitOK {
		t.Errorf("duplicate id should NOT succeed")
	}
}

func TestTrustAdd_MissingFlags(t *testing.T) {
	_ = withTrustConfig(t)
	var stdout, stderr bytes.Buffer
	if code := runTrust([]string{"add"}, &stdout, &stderr); code != exitUsage {
		t.Errorf("add no-flags exit=%d, want %d", code, exitUsage)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runTrust([]string{"add", "--registry", "https://r/"}, &stdout, &stderr); code != exitUsage {
		t.Errorf("add missing pubkey exit=%d, want %d", code, exitUsage)
	}
}

func TestTrustAdd_BadPubkeyFile(t *testing.T) {
	cfg := withTrustConfig(t)
	dir := filepath.Dir(cfg)
	bad := filepath.Join(dir, "garbage.pub")
	if err := os.WriteFile(bad, []byte("not a pem file"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runTrust([]string{"add", "--registry", "https://r/api/skills", "--pubkey", bad}, &stdout, &stderr)
	if code != exitGeneric {
		t.Errorf("bad pubkey exit=%d, want %d", code, exitGeneric)
	}
}

func TestTrustRemove_NotFound(t *testing.T) {
	cfg := withTrustConfig(t)
	dir := filepath.Dir(cfg)
	pubPath := writeTestPubkey(t, dir, "k.pub")
	var stdout, stderr bytes.Buffer
	if code := runTrust([]string{"add", "--registry", "https://existing/api/skills", "--pubkey", pubPath}, &stdout, &stderr); code != exitOK {
		t.Fatalf("setup add: %s", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runTrust([]string{"remove", "--registry", "https://nonexistent/api/skills"}, &stdout, &stderr); code != exitGeneric {
		t.Errorf("remove nonexistent exit=%d, want %d", code, exitGeneric)
	}
}

func TestTrustRemove_MissingFile(t *testing.T) {
	_ = withTrustConfig(t) // points at nonexistent path
	var stdout, stderr bytes.Buffer
	if code := runTrust([]string{"remove", "--registry", "https://x/"}, &stdout, &stderr); code != exitGeneric {
		t.Errorf("remove with no config exit=%d, want %d", code, exitGeneric)
	}
}

// Sanity: ensure printTrustUsage is callable with both stdout and stderr
// without nil-write panics (defensive).
func TestPrintTrustUsage(t *testing.T) {
	var b bytes.Buffer
	printTrustUsage(&b)
	if b.Len() == 0 {
		t.Errorf("printTrustUsage wrote nothing")
	}
}
