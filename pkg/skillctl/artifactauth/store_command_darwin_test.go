//go:build darwin

package artifactauth

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fakeSecurityCommand executes only a fixed shell helper. The intended native
// command is checked before substitution, and stdin is captured for assertions.
func fakeSecurityCommand(t *testing.T, wantArgs []string, diagnostic, exit string) (func(string, ...string) *exec.Cmd, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_TOKEN_STORE", "file")
	t.Setenv("M3C_TEST_KEYCHAIN", "0")
	input := filepath.Join(home, "stdin")
	return func(name string, args ...string) *exec.Cmd {
		if name != "/usr/bin/security" || !reflect.DeepEqual(args, wantArgs) {
			t.Fatalf("native command = %q %q, want fixed security argv %q", name, args, wantArgs)
		}
		// Values are positional arguments, never interpolated into shell code.
		return exec.Command("/bin/sh", "-c", `cat > "$1"; printf '%s' "$2" >&2; exit "$3"`, "helper", input, diagnostic, exit)
	}, input
}

func TestKeychainStoreCommandContract(t *testing.T) {
	for _, tc := range []struct {
		name, diagnostic, exit string
	}{
		{"success", "", "0"},
		{"failure", "synthetic backend unavailable", "7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command, input := fakeSecurityCommand(t, []string{"-i"}, tc.diagnostic, tc.exit)
			const secret = "synthetic-quoted-\"value\"-\\tail"
			err := storeKeychainWithCommand("test-service", "host.invalid", secret, command)
			if tc.exit == "0" {
				if err != nil {
					t.Fatalf("store: %v", err)
				}
			} else {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 || !strings.Contains(err.Error(), tc.diagnostic) {
					t.Fatalf("store error = %v, want wrapped exit 7 and backend diagnostic", err)
				}
				if strings.Contains(err.Error(), secret) {
					t.Fatal("store error disclosed the token")
				}
			}
			stdin, readErr := os.ReadFile(input)
			if readErr != nil {
				t.Fatal(readErr)
			}
			const want = "add-generic-password -s \"test-service\" -a \"host.invalid\" -w \"synthetic-quoted-\\\"value\\\"-\\\\tail\" -U\n"
			if string(stdin) != want {
				t.Errorf("stdin = %q, want quoted update command %q", stdin, want)
			}
		})
	}
}

func TestKeychainStoreRejectsNewlinesBeforeExec(t *testing.T) {
	for _, secret := range []string{"synthetic\nsecond-command", "synthetic\rsecond-command"} {
		err := storeKeychainWithCommand("test-service", "host.invalid", secret, func(string, ...string) *exec.Cmd {
			t.Fatal("invalid token reached process construction")
			return nil
		})
		if err == nil || !strings.Contains(err.Error(), "line break") {
			t.Fatalf("error = %v, want line-break refusal", err)
		}
	}
}

func TestKeychainDeleteCommandContract(t *testing.T) {
	for _, tc := range []struct {
		name, diagnostic, exit string
		wantError              bool
	}{
		{"success", "", "0", false},
		{"already absent", "the specified item could not be found", "44", false},
		{"denied", "synthetic access denied", "7", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			argv := []string{"delete-generic-password", "-s", "test-service", "-a", "host.invalid"}
			command, input := fakeSecurityCommand(t, argv, tc.diagnostic, tc.exit)
			err := deleteKeychainWithCommand("test-service", "host.invalid", command)
			if tc.wantError {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 || !strings.Contains(err.Error(), tc.diagnostic) {
					t.Fatalf("delete error = %v, want wrapped exit 7 and diagnostic", err)
				}
			} else if err != nil {
				t.Fatalf("delete: %v", err)
			}
			stdin, readErr := os.ReadFile(input)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(stdin) != 0 {
				t.Errorf("delete unexpectedly received stdin: %q", stdin)
			}
		})
	}
}
