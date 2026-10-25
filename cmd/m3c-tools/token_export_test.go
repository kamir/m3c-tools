package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Invoke the real command inside an isolated test process. Invalid metadata
// must be refused before a native read; local builds also inherit the provider trap.
func TestTokenExportRejectsUnboundDestination(t *testing.T) {
	if os.Getenv("M3C_TOKEN_EXPORT_HELPER") == "1" {
		cmdToken([]string{"--print"})
		os.Exit(0)
	}
	for _, tc := range []struct{ name, target, pin string }{
		{"missing pin", "https://a.example/upload_2", ""},
		{"foreign pin", "https://a.example/upload_2", "https://b.example"},
		{"unsafe target", "https://synthetic:secret@a.example", "https://a.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			cmd := exec.Command(os.Args[0], "-test.run=^TestTokenExportRejectsUnboundDestination$")
			cmd.Env = append(os.Environ(), "M3C_TOKEN_EXPORT_HELPER=1", "HOME="+home, "USERPROFILE="+home, "ER1_API_URL="+tc.target, "ER1_DEVICE_TOKEN_ORIGIN="+tc.pin, "M3C_TOKEN_STORE=keychain")
			output, err := cmd.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 || !strings.Contains(string(output), "token export refused") || strings.Contains(string(output), "synthetic:secret") {
				t.Fatalf("exit=%v output=%s", err, output)
			}
		})
	}
}

func TestCaptureLoginRefusesInvalidTarget(t *testing.T) {
	if os.Getenv("M3C_INVALID_LOGIN_HELPER") == "1" {
		cmdLogin()
		os.Exit(0)
	}
	home := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCaptureLoginRefusesInvalidTarget$")
	cmd.Env = append(os.Environ(), "M3C_INVALID_LOGIN_HELPER=1", "HOME="+home, "USERPROFILE="+home, "ER1_API_URL=https://synthetic:secret@a.example/upload_2", "M3C_TOKEN_STORE=keychain")
	out, err := cmd.CombinedOutput()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || !strings.Contains(string(out), "Invalid HTTPS login target") || strings.Contains(string(out), "synthetic:secret") {
		t.Fatalf("exit=%v output=%s", err, out)
	}
}
