package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/auth"
	keyring "github.com/zalando/go-keyring"
)

// Exercise main, not just the handler: the legacy startup bootstrap ran before
// attest could parse help or reject malformed input. Use only synthetic tokens
// and the file backend in children; fixture Save also has an explicit mock.
func TestAttestCLIUnrelatedDeviceToken(t *testing.T) {
	binary := skillctlBin(t)
	for _, tc := range []struct {
		name       string
		args       []string
		diagnostic string
	}{
		{"help", []string{"--help"}, "Usage: skillctl attest"},
		{"unknown flag", []string{"--unknown"}, "flag provided but not defined"},
		{"missing flags", []string{"sha256:" + strings.Repeat("a", 64)}, "Usage: skillctl attest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("M3C_TOKEN_STORE", "file")
			t.Setenv("ER1_DEVICE_TOKEN", "")
			t.Setenv("ER1_USER_ID", "attest-fixture")
			t.Setenv("ER1_CONTEXT_ID", "")
			keyring.MockInit()
			if err := auth.Save(&auth.DeviceToken{Token: "synthetic-expired-device-token", UserID: "attest-fixture", DeviceID: auth.DeviceID(), ExpiresAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}); err != nil {
				t.Fatal(err)
			}
			tokenPath := filepath.Join(home, ".m3c-tools", "device-token.enc")
			before, err := os.ReadFile(tokenPath)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(binary, append([]string{"attest"}, tc.args...)...)
			output, err := cmd.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 2 {
				t.Fatalf("exit=%v, want usage exit 2; output=%s", err, output)
			}
			if !bytes.Contains(output, []byte(tc.diagnostic)) {
				t.Fatalf("missing expected diagnostic %q: %s", tc.diagnostic, output)
			}
			if bytes.Contains(output, []byte("saved device token has expired")) {
				t.Fatalf("attest loaded unrelated device token before parsing: %s", output)
			}
			after, err := os.ReadFile(tokenPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("attest changed unrelated device-token file")
			}
		})
	}
}
