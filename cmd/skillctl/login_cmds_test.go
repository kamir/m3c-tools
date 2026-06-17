package main

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/auth"
)

// FR-0043: ER1-bound commands autoload the persisted token into the env.

func TestAutoloadDeviceToken_FromStore(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("M3C_TOKEN_STORE", "file")
	t.Setenv("ER1_DEVICE_TOKEN", "")
	t.Setenv("ER1_USER_ID", "")
	t.Setenv("ER1_CONTEXT_ID", "testsub___mft") // → userID hint "testsub"

	dt := &auth.DeviceToken{
		Token:    "auto-tok",
		UserID:   "testsub",
		DeviceID: auth.DeviceID(),
		SavedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	if err := auth.Save(dt); err != nil {
		t.Fatalf("save: %v", err)
	}

	var errb bytes.Buffer
	autoloadDeviceToken(&errb)
	if got := os.Getenv("ER1_DEVICE_TOKEN"); got != "auto-tok" {
		t.Fatalf("ER1_DEVICE_TOKEN = %q, want auto-tok (stderr=%q)", got, errb.String())
	}
}

func TestAutoloadDeviceToken_RespectsExplicitEnv(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "explicit")
	autoloadDeviceToken(&bytes.Buffer{})
	if got := os.Getenv("ER1_DEVICE_TOKEN"); got != "explicit" {
		t.Fatalf("autoload overwrote an explicit token: %q", got)
	}
}

func TestAutoloadDeviceToken_ExpiredWarns(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("M3C_TOKEN_STORE", "file")
	t.Setenv("ER1_DEVICE_TOKEN", "")
	t.Setenv("ER1_USER_ID", "testsub")

	dt := &auth.DeviceToken{
		Token:     "stale",
		UserID:    "testsub",
		DeviceID:  auth.DeviceID(),
		ExpiresAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	}
	if err := auth.Save(dt); err != nil {
		t.Fatalf("save: %v", err)
	}

	var errb bytes.Buffer
	autoloadDeviceToken(&errb)
	if got := os.Getenv("ER1_DEVICE_TOKEN"); got != "" {
		t.Fatalf("expired token must not be exported, got %q", got)
	}
	if !bytes.Contains(errb.Bytes(), []byte("expired")) {
		t.Fatalf("expected an 'expired' warning, got %q", errb.String())
	}
}

func TestNetworkCommandsGating(t *testing.T) {
	if !networkCommands["pull"] || !networkCommands["publish"] {
		t.Fatal("pull/publish must be gated as network commands")
	}
	if networkCommands["keygen"] || networkCommands["version"] || networkCommands["sign"] {
		t.Fatal("offline commands must NOT trigger the keychain autoload")
	}
}
