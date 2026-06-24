package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
	"github.com/kamir/m3c-tools/pkg/skillctl/translog"
)

// loadPrivForTest loads a PEM private key via the same loader the CLI uses.
func loadPrivForTest(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	priv, err := signing.LoadPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// mustTime is a fixed timestamp for deterministic STHs in tests.
func mustTime() time.Time {
	return time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
}

// writeLogKeypair writes a PEM PKCS#8 priv (0600) + SPKI pub for the log.
func writeLogKeypair(t *testing.T, dir string) (privPath, pubPath string, pub ed25519.PublicKey) {
	t.Helper()
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	privPath = filepath.Join(dir, "log.priv")
	pubPath = filepath.Join(dir, "log.pub")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	return privPath, pubPath, pubKey
}

func digestN(n int) string {
	return "sha256:" + strings.Repeat("0", 63) + string(rune('0'+n))
}

// TestTranslogCLI_AppendProveVerify exercises the happy path end-to-end.
func TestTranslogCLI_AppendProveVerify(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.jsonl")
	privPath, pubPath, _ := writeLogKeypair(t, dir)

	// Append three events.
	for i, ty := range []string{"admit", "attest", "revoke"} {
		var out, errb bytes.Buffer
		rc := runTranslog([]string{"append", ty, digestN(i), "--log", logFile, "--log-id", "log-cli"}, &out, &errb)
		if rc != exitOK {
			t.Fatalf("append %s rc=%d err=%s", ty, rc, errb.String())
		}
	}

	// Prove the attest event (digest index 1) → write a receipt.
	receiptPath := filepath.Join(dir, "receipt.json")
	var out, errb bytes.Buffer
	rc := runTranslog([]string{"prove", digestN(1), "--log", logFile, "--log-id", "log-cli", "--key", privPath, "--out", receiptPath}, &out, &errb)
	if rc != exitOK {
		t.Fatalf("prove rc=%d err=%s", rc, errb.String())
	}

	// Verify the receipt offline against the pinned log pubkey.
	var vout, verr bytes.Buffer
	rc = runTranslog([]string{"verify", "--receipt", receiptPath, "--log-pubkey", pubPath}, &vout, &verr)
	if rc != exitOK {
		t.Fatalf("verify rc=%d err=%s", rc, verr.String())
	}
	if !strings.Contains(vout.String(), "OK: event included") {
		t.Fatalf("verify output missing success line: %s", vout.String())
	}
}

// TestTranslogCLI_VerifyWrongKeyFails: a receipt verified against the WRONG
// log key must fail with the not-included exit code.
func TestTranslogCLI_VerifyWrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.jsonl")
	d1 := filepath.Join(dir, "k1")
	d2 := filepath.Join(dir, "k2")
	if err := os.MkdirAll(d1, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(d2, 0o700); err != nil {
		t.Fatal(err)
	}
	privPath, _, _ := writeLogKeypair(t, d1)
	_, wrongPubPath, _ := writeLogKeypair(t, d2) // a DIFFERENT key's pub

	var out, errb bytes.Buffer
	runTranslog([]string{"append", "attest", digestN(1), "--log", logFile, "--log-id", "log-cli"}, &out, &errb)

	receiptPath := filepath.Join(dir, "r.json")
	runTranslog([]string{"prove", digestN(1), "--log", logFile, "--log-id", "log-cli", "--key", privPath, "--out", receiptPath}, &out, &errb)

	var verr bytes.Buffer
	rc := runTranslog([]string{"verify", "--receipt", receiptPath, "--log-pubkey", wrongPubPath}, &out, &verr)
	if rc != exitTranslogNotIncluded {
		t.Fatalf("wrong key: want exit %d, got %d (%s)", exitTranslogNotIncluded, rc, verr.String())
	}
}

// TestTranslogCLI_WitnessSplitView: two honestly-signed STHs at the same
// size with different roots → the witness verb DETECTS the split view.
func TestTranslogCLI_WitnessSplitView(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath, pub := writeLogKeypair(t, dir)
	_ = pub

	// Build STH A over one history of size 4, STH B over a forked history
	// of size 4. We use the package directly to construct, then the CLI to
	// detect.
	mkSTH := func(forkLeaf string) translog.STH {
		logFile := filepath.Join(dir, "tmp-"+forkLeaf+".jsonl")
		l, err := translog.OpenLog(logFile, "log-cli")
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 4; i++ {
			subj := "s" + string(rune('0'+i))
			if i == 2 && forkLeaf != "" {
				subj = forkLeaf
			}
			if _, err := l.Append(translog.LogEntry{
				Type:      translog.EventAttest,
				Digest:    digestN(i),
				Timestamp: "2026-06-24T12:00:0" + string(rune('0'+i)) + "Z",
				Subject:   subj,
			}); err != nil {
				t.Fatal(err)
			}
		}
		// Load priv via the signing loader path the CLI uses.
		priv := loadPrivForTest(t, privPath)
		sth, err := l.SignHead(priv, mustTime())
		if err != nil {
			t.Fatal(err)
		}
		return sth
	}

	sthA := mkSTH("")       // honest
	sthB := mkSTH("FORKED") // forked at leaf 2 → same size 4, different root
	if sthA.RootHash == sthB.RootHash {
		t.Fatal("test setup: expected divergent roots")
	}

	sthsPath := filepath.Join(dir, "sths.json")
	data, _ := json.Marshal([]translog.STH{sthA, sthB})
	if err := os.WriteFile(sthsPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	rc := runTranslog([]string{"witness", "--sths", sthsPath, "--log-pubkey", pubPath}, &out, &errb)
	if rc != exitTranslogSplitView {
		t.Fatalf("split view: want exit %d, got %d (out=%s err=%s)", exitTranslogSplitView, rc, out.String(), errb.String())
	}
	if !strings.Contains(errb.String(), "SPLIT VIEW DETECTED") {
		t.Fatalf("expected split-view diagnostic, got: %s", errb.String())
	}
}

// TestTranslogCLI_WitnessConsistent: two consistent heads (same head) →
// witness reports OK.
func TestTranslogCLI_WitnessConsistent(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath, _ := writeLogKeypair(t, dir)
	logFile := filepath.Join(dir, "log.jsonl")
	l, _ := translog.OpenLog(logFile, "log-cli")
	for i := 0; i < 4; i++ {
		if _, err := l.Append(translog.LogEntry{Type: translog.EventAdmit, Digest: digestN(i), Timestamp: "2026-06-24T12:00:00Z", Subject: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	priv := loadPrivForTest(t, privPath)
	sth, _ := l.SignHead(priv, mustTime())

	sthsPath := filepath.Join(dir, "sths.json")
	data, _ := json.Marshal([]translog.STH{sth, sth})
	if err := os.WriteFile(sthsPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rc := runTranslog([]string{"witness", "--sths", sthsPath, "--log-pubkey", pubPath}, &out, &errb)
	if rc != exitOK {
		t.Fatalf("consistent witness: want exit 0, got %d (%s)", rc, errb.String())
	}
}

// TestTranslogCLI_UnknownVerb returns usage exit.
func TestTranslogCLI_UnknownVerb(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := runTranslog([]string{"bogus"}, &out, &errb); rc != exitUsage {
		t.Fatalf("unknown verb: want exit %d, got %d", exitUsage, rc)
	}
}

// TestBestEffortAppend_DisabledByDefault: with M3C_TRANSLOG unset the emit
// helper is a no-op (no file is created, no note emitted) so existing
// command behaviour is unchanged for users who have not adopted L1.
func TestBestEffortAppend_DisabledByDefault(t *testing.T) {
	t.Setenv("M3C_TRANSLOG", "") // explicitly off
	var errb bytes.Buffer
	bestEffortTranslogAppend(translogEventAttest, "sha256:"+strings.Repeat("a", 64), "x", &errb)
	if errb.Len() != 0 {
		t.Fatalf("disabled emit should be silent, got: %s", errb.String())
	}
}

// TestBestEffortAppend_EnabledLogs: with M3C_TRANSLOG=1 and a HOME pointing
// at a temp dir, the helper appends an entry and reports it.
func TestBestEffortAppend_EnabledLogs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// On windows-latest CI os.UserHomeDir() (inside DefaultLogFilePath) reads
	// %USERPROFILE% and ignores $HOME, so pin both to the temp dir.
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_TRANSLOG", "1")
	t.Setenv("M3C_TRANSLOG_ID", "skillctl-local")

	var errb bytes.Buffer
	digest := "sha256:" + strings.Repeat("b", 64)
	bestEffortTranslogAppend(translogEventAttest, digest, "my-skill", &errb)
	if !strings.Contains(errb.String(), "logged attest event") {
		t.Fatalf("enabled emit should report a log append, got: %s", errb.String())
	}
	// The log file must now exist and be reloadable with the entry.
	logFile := filepath.Join(home, ".claude", "skillctl", "transparency-log.jsonl")
	l, err := translog.OpenLog(logFile, "skillctl-local")
	if err != nil {
		t.Fatalf("reopen log: %v", err)
	}
	if l.Size() != 1 {
		t.Fatalf("want 1 logged entry, got %d", l.Size())
	}
	if got := l.FindByDigest(digest); len(got) != 1 {
		t.Fatalf("logged digest not found: %v", got)
	}
}

// TestBestEffortAppend_MalformedDigestSwallowed: a bad digest is rejected by
// the entry validator but the helper must NOT panic or fail the caller (it
// is best-effort) — it emits a non-fatal note.
func TestBestEffortAppend_MalformedDigestSwallowed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// Windows CI: pin %USERPROFILE% too (os.UserHomeDir ignores $HOME there).
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_TRANSLOG", "1")
	var errb bytes.Buffer
	bestEffortTranslogAppend(translogEventAdmit, "not-a-digest", "x", &errb)
	if !strings.Contains(errb.String(), "non-fatal") {
		t.Fatalf("malformed digest should produce a non-fatal note, got: %s", errb.String())
	}
}
