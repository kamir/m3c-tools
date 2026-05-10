package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillimport/parser"
)

// hashHex returns hex(sha256(b)).
func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// captureStderr runs fn while replacing os.Stderr with a pipe; returns whatever
// fn wrote to stderr. We don't need stdout because the next-step proposal
// message is asserted via stdout capture in the happy-path test.
func captureStdio(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	origOut, origErr := os.Stdout, os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout = wOut
	os.Stderr = wErr

	done := make(chan struct{})
	var outBuf, errBuf strings.Builder
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := rOut.Read(buf)
			if n > 0 {
				outBuf.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		close(done)
	}()
	doneErr := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := rErr.Read(buf)
			if n > 0 {
				errBuf.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		close(doneErr)
	}()

	fn()
	wOut.Close()
	wErr.Close()
	<-done
	<-doneErr
	os.Stdout = origOut
	os.Stderr = origErr
	return outBuf.String(), errBuf.String()
}

// writeMinimalPolicy creates a temp policy file and returns its path.
func writeMinimalPolicy(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return p
}

const validHex = "a3f5b9c4e8d2f1a0b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4"

// TestImportPublic_PinRequired covers exit 4.
func TestImportPublic_PinRequired(t *testing.T) {
	var rc int
	captureStdio(t, func() {
		rc = runImportPublic([]string{"github.com:anthropics/code-reviewer"})
	})
	if rc != exitImportPinRequired {
		t.Errorf("rc = %d, want %d", rc, exitImportPinRequired)
	}
}

// TestImportPublic_NoSourcePolicy covers exit 17.
func TestImportPublic_NoSourcePolicy(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-policy.yaml")
	var rc int
	captureStdio(t, func() {
		rc = runImportPublic([]string{
			"github.com:anthropics/code-reviewer@sha256:" + validHex,
			"--policy", missing,
		})
	})
	if rc != exitImportNoSourcePolicy {
		t.Errorf("rc = %d, want %d", rc, exitImportNoSourcePolicy)
	}
}

// TestImportPublic_BlockedHost covers exit 19 (blocked_hosts list).
func TestImportPublic_BlockedHost(t *testing.T) {
	policyBody := `version: 1
default_deny: true
allowed_hosts:
  - github.com
blocked_hosts:
  - badhost.example
`
	pol := writeMinimalPolicy(t, policyBody)
	var rc int
	captureStdio(t, func() {
		rc = runImportPublic([]string{
			"badhost.example:o/n@sha256:" + validHex,
			"--policy", pol,
		})
	})
	if rc != exitImportSourceBlocked {
		t.Errorf("rc = %d, want %d", rc, exitImportSourceBlocked)
	}
}

// TestImportPublic_HostNotAllowed covers exit 19 (default-deny tripped).
func TestImportPublic_HostNotAllowed(t *testing.T) {
	policyBody := `version: 1
default_deny: true
allowed_hosts:
  - github.com
`
	pol := writeMinimalPolicy(t, policyBody)
	var rc int
	captureStdio(t, func() {
		rc = runImportPublic([]string{
			"skillhub.club:o/n@sha256:" + validHex,
			"--policy", pol,
		})
	})
	if rc != exitImportSourceBlocked {
		t.Errorf("rc = %d, want %d", rc, exitImportSourceBlocked)
	}
}

// withTestServer spins up an httptest.Server returning bundleBytes for any
// path; sets fetchURLOverride to point at it; restores both at the end.
func withTestServer(t *testing.T, bundle []byte, fn func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bundle)
	}))
	t.Cleanup(srv.Close)

	prev := fetchURLOverride
	fetchURLOverride = func(ref *parser.Reference) string { return srv.URL + "/dl" }
	t.Cleanup(func() { fetchURLOverride = prev })
	fn()
}

// TestImportPublic_HappyPath covers exit 0 + the printed propose hand-off.
func TestImportPublic_HappyPath(t *testing.T) {
	// Bundle bytes are arbitrary; the staging dir won't contain bundle.json /
	// skill.md / package.json, so the scanner returns clean.
	bundle := []byte("FAKE-SKB-CONTENT")
	pinHex := hashHex(bundle)

	policyBody := `version: 1
default_deny: true
allowed_hosts:
  - upstream.test
`
	pol := writeMinimalPolicy(t, policyBody)
	staging := t.TempDir()

	var rc int
	var stdout, stderr string
	withTestServer(t, bundle, func() {
		stdout, stderr = captureStdio(t, func() {
			rc = runImportPublic([]string{
				"upstream.test:myorg/test-skill@sha256:" + pinHex,
				"--policy", pol,
				"--staging", staging,
			})
		})
	})

	if rc != 0 {
		t.Fatalf("rc = %d, want 0\nstdout=%s\nstderr=%s", rc, stdout, stderr)
	}
	if !strings.Contains(stdout, "Next step:") {
		t.Errorf("stdout missing 'Next step:' hand-off:\n%s", stdout)
	}
	if !strings.Contains(stdout, "skillctl propose") {
		t.Errorf("stdout missing 'skillctl propose' command:\n%s", stdout)
	}
	if !strings.Contains(stdout, "--derived-from upstream.test:myorg/test-skill@sha256:"+pinHex) {
		t.Errorf("stdout missing canonical --derived-from:\n%s", stdout)
	}

	// Staged dir was created with the expected layout.
	expectedDir := filepath.Join(staging, "upstream.test", "myorg", "test-skill", pinHex)
	if _, err := os.Stat(filepath.Join(expectedDir, "bundle.skb")); err != nil {
		t.Errorf("bundle.skb missing in %s: %v", expectedDir, err)
	}
	if _, err := os.Stat(filepath.Join(expectedDir, "scan-report.json")); err != nil {
		t.Errorf("scan-report.json missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(expectedDir, "import-record.json")); err != nil {
		t.Errorf("import-record.json missing: %v", err)
	}
}

// TestImportPublic_HappyPath_DigestMismatch verifies that the fetcher refuses
// when the bytes don't hash to the pin (returns exit 1, NOT 0).
func TestImportPublic_DigestMismatch(t *testing.T) {
	bundle := []byte("FAKE")
	wrongHex := strings.Repeat("0", 64) // not the actual hash of "FAKE"

	policyBody := `version: 1
default_deny: true
allowed_hosts:
  - upstream.test
`
	pol := writeMinimalPolicy(t, policyBody)
	staging := t.TempDir()

	var rc int
	withTestServer(t, bundle, func() {
		captureStdio(t, func() {
			rc = runImportPublic([]string{
				"upstream.test:myorg/test-skill@sha256:" + wrongHex,
				"--policy", pol,
				"--staging", staging,
			})
		})
	})
	if rc == 0 {
		t.Errorf("expected non-zero rc on digest mismatch")
	}
}

// TestImportPublic_ScannerRefuse covers exit 5: bundle bytes that, once written
// to staging, contain a bundle.json with a dangerous side-effect declaration.
//
// We exploit the MVP layout: the fetched bytes are written to bundle.skb and
// the scanner walks the staging dir. To inject a critical scan finding, we
// write the violator bundle.json directly into the staging dir before the
// scanner runs by using a server response that, after the airlock writes it
// to bundle.skb, leaves the rest of the dir empty. To actually trigger R-201
// we need a real bundle.json file in the staging dir at scan time.
//
// The cleanest way: create a tar/zip-free MVP path — we pre-create a file in
// the staging dir before the airlock mkdirs it (mkdir is idempotent), then run.
func TestImportPublic_ScannerRefuse(t *testing.T) {
	bundle := []byte("opaque-bundle")
	pinHex := hashHex(bundle)

	policyBody := `version: 1
default_deny: true
allowed_hosts:
  - upstream.test
`
	pol := writeMinimalPolicy(t, policyBody)
	staging := t.TempDir()

	// Pre-stage a violator bundle.json so the scanner trips R-201 (critical).
	stageDir := filepath.Join(staging, "upstream.test", "myorg", "evil", pinHex)
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	violator := `{"intent":{"side_effects":["exec","fs:write"]}}`
	if err := os.WriteFile(filepath.Join(stageDir, "bundle.json"), []byte(violator), 0o644); err != nil {
		t.Fatal(err)
	}

	var rc int
	withTestServer(t, bundle, func() {
		captureStdio(t, func() {
			rc = runImportPublic([]string{
				"upstream.test:myorg/evil@sha256:" + pinHex,
				"--policy", pol,
				"--staging", staging,
			})
		})
	})
	if rc != exitImportScannerRefuse {
		t.Errorf("rc = %d, want %d (scanner_refuse)", rc, exitImportScannerRefuse)
	}
}

// TestImportPublic_WarnWithoutAcceptYellow covers exit 18 (intent capped).
// Pre-stage a skill.md with a missing governance field (R-101 → high) and
// no critical findings; the airlock should refuse without --accept-yellow.
func TestImportPublic_WarnWithoutAcceptYellow(t *testing.T) {
	bundle := []byte("opaque-bundle-2")
	pinHex := hashHex(bundle)

	policyBody := `version: 1
default_deny: true
allowed_hosts:
  - upstream.test
`
	pol := writeMinimalPolicy(t, policyBody)
	staging := t.TempDir()

	stageDir := filepath.Join(staging, "upstream.test", "myorg", "warner", pinHex)
	claudeDir := filepath.Join(stageDir, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	skill := "---\ndescription: missing governance field\n---\n# warner\n"
	if err := os.WriteFile(filepath.Join(claudeDir, "skill.md"), []byte(skill), 0o644); err != nil {
		t.Fatal(err)
	}

	var rc int
	withTestServer(t, bundle, func() {
		captureStdio(t, func() {
			rc = runImportPublic([]string{
				"upstream.test:myorg/warner@sha256:" + pinHex,
				"--policy", pol,
				"--staging", staging,
			})
		})
	})
	if rc != exitImportIntentCapped {
		t.Errorf("rc = %d, want %d (intent_capped)", rc, exitImportIntentCapped)
	}

	// Same fixture WITH --accept-yellow → should succeed.
	rc2 := -1
	// Pre-stage again because the previous run wrote scan-report.json (which is
	// fine). Re-run with --accept-yellow.
	withTestServer(t, bundle, func() {
		captureStdio(t, func() {
			rc2 = runImportPublic([]string{
				"upstream.test:myorg/warner@sha256:" + pinHex,
				"--policy", pol,
				"--staging", staging,
				"--accept-yellow",
			})
		})
	})
	if rc2 != 0 {
		t.Errorf("--accept-yellow rc = %d, want 0", rc2)
	}
}
