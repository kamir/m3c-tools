package main

// sync_backend_select_test.go: SPEC-0455 T-02 (REQ-5.1/REQ-5.1a, decisions
// D1/D8) and acceptance A7. The selector has no default; the old
// endpoint-only configuration is refused LOUDLY (exit 30) and never mapped
// silently; the flag beats the environment.

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
)

// TestSyncBackend_EndpointWithoutBackendRefusedLoud is acceptance A7: the
// pre-T-02 configuration (endpoint set, no backend) exits 30 and the
// message names the migration.
func TestSyncBackend_EndpointWithoutBackendRefusedLoud(t *testing.T) {
	dev := syncTestDeviceKey(t)
	_, _ = syncHarness(t, dev, "dev-key")
	t.Setenv("M3C_INGEST_ENDPOINT", "https://ingest.example.com")

	var out, errb bytes.Buffer
	code := runSync([]string{"--once"}, &out, &errb)
	if code != syncExitBackendConfig {
		t.Fatalf("exit=%d, want %d; stderr=%s", code, syncExitBackendConfig, errb.String())
	}
	for _, want := range []string{"SKILLCTL_AUDIT_BACKEND=er1", "audit_backend_config"} {
		if !strings.Contains(errb.String(), want) {
			t.Fatalf("stderr misses %q: %s", want, errb.String())
		}
	}
}

// TestSyncBackend_UnknownNameRefused: the register's known-name list is
// quoted in the refusal (A4 on the CLI surface).
func TestSyncBackend_UnknownNameRefused(t *testing.T) {
	dev := syncTestDeviceKey(t)
	_, _ = syncHarness(t, dev, "dev-key")

	var out, errb bytes.Buffer
	code := runSync([]string{"--once", "--backend", "git", "--endpoint", "https://ingest.example.com"}, &out, &errb)
	if code != syncExitBackendConfig {
		t.Fatalf("exit=%d, want %d; stderr=%s", code, syncExitBackendConfig, errb.String())
	}
	if want := `unknown audit export backend "git" (known: er1)`; !strings.Contains(errb.String(), want) {
		t.Fatalf("stderr misses %q: %s", want, errb.String())
	}
}

// TestSyncBackend_NamedWithoutEndpoint: naming a backend without its
// endpoint is an incomplete configuration, refused with the same code.
func TestSyncBackend_NamedWithoutEndpoint(t *testing.T) {
	dev := syncTestDeviceKey(t)
	_, _ = syncHarness(t, dev, "dev-key")

	var out, errb bytes.Buffer
	code := runSync([]string{"--once", "--backend", "er1"}, &out, &errb)
	if code != syncExitBackendConfig {
		t.Fatalf("exit=%d, want %d; stderr=%s", code, syncExitBackendConfig, errb.String())
	}
	if want := "M3C_INGEST_ENDPOINT"; !strings.Contains(errb.String(), want) {
		t.Fatalf("stderr misses %q: %s", want, errb.String())
	}
}

// TestSyncBackend_EnvSelectsBackend: the second rung works end to end: a
// backend named ONLY via SKILLCTL_AUDIT_BACKEND drains and syncs.
func TestSyncBackend_EnvSelectsBackend(t *testing.T) {
	dev := syncTestDeviceKey(t)
	ingest := syncTestIngestKey(t)
	const keyID, logID = "dev-key", "env-select-log"
	home, store := syncHarness(t, dev, keyID)
	appendSignedRow(t, store, dev, keyID, "inv:t02:env", "2026-09-17T10:00:00Z")
	_ = store.Close()

	pemPath := writeIngestPubPEM(t, home, ingest.Public().(ed25519.PublicKey))
	var posts int32
	srv := contractDouble(t, ingest, logID, ackDurable, &posts)
	t.Setenv("SKILLCTL_AUDIT_BACKEND", "er1")

	var out, errb bytes.Buffer
	code := runSync([]string{"--once", "--endpoint", srv.URL, "--ingest-pubkey", pemPath, "--log-id", logID, "--insecure"}, &out, &errb)
	if code != syncExitOK {
		t.Fatalf("exit=%d; stderr=%s", code, errb.String())
	}
	if !strings.Contains(out.String(), "synced=1") {
		t.Fatalf("stdout misses synced=1: %s", out.String())
	}
}

// TestSyncBackend_FlagBeatsEnv: with an UNKNOWN name in the environment and
// er1 on the flag, the drain runs: proof the flag rung wins (D8). If the
// env won, this would exit 30.
func TestSyncBackend_FlagBeatsEnv(t *testing.T) {
	dev := syncTestDeviceKey(t)
	ingest := syncTestIngestKey(t)
	const keyID, logID = "dev-key", "flag-beats-env-log"
	home, store := syncHarness(t, dev, keyID)
	appendSignedRow(t, store, dev, keyID, "inv:t02:flag", "2026-09-17T10:00:00Z")
	_ = store.Close()

	pemPath := writeIngestPubPEM(t, home, ingest.Public().(ed25519.PublicKey))
	var posts int32
	srv := contractDouble(t, ingest, logID, ackDurable, &posts)
	t.Setenv("SKILLCTL_AUDIT_BACKEND", "kafka")

	var out, errb bytes.Buffer
	code := runSync([]string{"--once", "--backend", "er1", "--endpoint", srv.URL, "--ingest-pubkey", pemPath, "--log-id", logID, "--insecure"}, &out, &errb)
	if code != syncExitOK {
		t.Fatalf("exit=%d; stderr=%s", code, errb.String())
	}
	if !strings.Contains(out.String(), "synced=1") {
		t.Fatalf("stdout misses synced=1: %s", out.String())
	}
}
