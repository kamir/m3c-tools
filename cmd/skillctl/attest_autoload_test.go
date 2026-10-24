package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/auth"
	keyring "github.com/zalando/go-keyring"
)

// Run the real main in a helper test process with an explicit in-memory native
// provider. A product binary would not inherit this mock. The expired synthetic
// native token makes restoring the unused startup lookup observable on every OS.
func TestAttestCLIUnrelatedDeviceToken(t *testing.T) {
	if os.Getenv("M3C_ATTEST_MAIN_HELPER") == "1" {
		keyring.MockInit()
		raw, err := json.Marshal(&auth.DeviceToken{Token: "synthetic-expired-device-token", ExpiresAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)})
		if err != nil {
			t.Fatal(err)
		}
		if err := keyring.Set("m3c-tools", "device-token", string(raw)); err != nil {
			t.Fatal(err)
		}
		sep := -1
		for i, arg := range os.Args {
			if arg == "--" {
				sep = i
				break
			}
		}
		if sep < 0 {
			t.Fatal("helper arguments missing")
		}
		os.Args = append([]string{"skillctl"}, os.Args[sep+1:]...)
		main()
		t.Fatal("main returned instead of exiting")
	}
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
			tokenPath := filepath.Join(home, ".m3c-tools", "device-token.enc")
			if err := os.MkdirAll(filepath.Dir(tokenPath), 0700); err != nil {
				t.Fatal(err)
			}
			before := []byte("synthetic-opaque-legacy-file")
			if err := os.WriteFile(tokenPath, before, 0600); err != nil {
				t.Fatal(err)
			}
			args := append([]string{"-test.run=^TestAttestCLIUnrelatedDeviceToken$", "--", "attest"}, tc.args...)
			cmd := exec.Command(os.Args[0], args...)
			cmd.Env = append(os.Environ(), "M3C_ATTEST_MAIN_HELPER=1", "HOME="+home, "USERPROFILE="+home, "M3C_TOKEN_STORE=keychain", "ER1_DEVICE_TOKEN=", "ER1_USER_ID=", "ER1_CONTEXT_ID=")
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
				t.Fatal("attest changed unrelated legacy token file")
			}
		})
	}
}
