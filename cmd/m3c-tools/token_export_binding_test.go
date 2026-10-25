package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/auth"
	keyring "github.com/zalando/go-keyring"
)

const syntheticExportBearer = "synthetic-native-export-bearer"

// Exercise the real cmdToken path in a helper test process. The mock is installed
// in that process before Set; no product binary is claimed to inherit the mock.
func TestTokenExportStoredBindingProcess(t *testing.T) {
	if os.Getenv("M3C_BOUND_TOKEN_EXPORT_HELPER") == "1" {
		keyring.MockInit()
		token := &auth.DeviceToken{Token: syntheticExportBearer}
		var err error
		switch os.Getenv("M3C_BOUND_TOKEN_EXPORT_VARIANT") {
		case "matching":
			token.Binding, err = auth.NewLoginBinding("https://export.example/login-prefix")
		case "foreign":
			token.Binding, err = auth.NewLoginBinding("https://foreign.example")
		case "legacy":
			// An existing native entry with no binding is never adopted.
		default:
			t.Fatal("unknown synthetic fixture variant")
		}
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(token)
		if err != nil {
			t.Fatal(err)
		}
		if err := keyring.Set("m3c-tools", "device-token", string(raw)); err != nil {
			t.Fatal(err)
		}
		cmdToken([]string{"--print"})
		// Avoid the test harness's PASS line contaminating exact token stdout.
		os.Exit(0)
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_TOKEN_STORE", "keychain")
	t.Setenv("M3C_TEST_KEYCHAIN", "0")
	t.Setenv("M3C_ER1_KEYCHAIN", "off")
	for _, variant := range []string{"matching", "legacy", "foreign"} {
		t.Run(variant, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestTokenExportStoredBindingProcess$")
			cmd.Env = append(os.Environ(),
				"M3C_BOUND_TOKEN_EXPORT_HELPER=1",
				"M3C_BOUND_TOKEN_EXPORT_VARIANT="+variant,
				"HOME="+home, "USERPROFILE="+home,
				"ER1_API_URL=https://export.example:443/upload_2",
				"ER1_DEVICE_TOKEN_ORIGIN=https://export.example:443",
				"ER1_DEVICE_TOKEN=", "ER1_API_KEY=")
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			if variant == "matching" {
				if err != nil || stdout.String() != syntheticExportBearer+"\n" || stderr.Len() != 0 {
					t.Fatal("matching native binding did not produce exact synthetic token output")
				}
				return
			}
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "token export refused") {
				t.Fatal("legacy or foreign native binding did not refuse export")
			}
			if strings.Contains(stdout.String(), syntheticExportBearer) || strings.Contains(stderr.String(), syntheticExportBearer) {
				t.Fatal("refused export disclosed the selected native bearer")
			}
		})
	}
}
