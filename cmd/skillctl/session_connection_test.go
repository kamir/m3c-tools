package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
)

func TestSessionCLIRejectsUsageBeforeCredentialResolution(t *testing.T) {
	binary := skillctlBin(t)
	t.Setenv("ER1_DEVICE_TOKEN_ORIGIN", "")
	t.Setenv("ER1_API_KEY_ORIGIN", "")
	t.Setenv("ER1_API_KEY", "")
	t.Setenv("ER1_DEVICE_TOKEN", "")
	t.Setenv("M3C_TOKEN_STORE", "file")
	t.Setenv("M3C_ER1_KEYCHAIN", "off")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"open", "--help"}, "Usage of session open"},
		{[]string{"unknown"}, "session: unknown subcommand"},
		{[]string{"open", "unexpected"}, "session: unexpected or missing positional arguments"},
		{[]string{"checkpoint", "--session", "   "}, "session checkpoint: --session is required"},
		{[]string{"show"}, "session: unexpected or missing positional arguments"},
	} {
		args := tc.args
		home := t.TempDir()
		cmd := exec.Command(binary, append([]string{"session"}, args...)...)
		cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home)
		out, err := cmd.CombinedOutput()
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 2 || !bytes.Contains(out, []byte(tc.want)) || bytes.Contains(out, []byte("credential")) || strings.Contains(strings.ToLower(string(out)), "panic:") {
			t.Fatalf("args=%v exit=%v output=%s", args, err, out)
		}
	}
}

func TestSessionCLIReadVerbsUseExplicitResolvedContext(t *testing.T) {
	binary := skillctlBin(t)
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/TenantA/memory/ExplicitCtx/search" || r.Header.Get("X-Context-ID") != "ExplicitCtx" || r.Header.Get("X-API-KEY") != "synthetic-cli-session-key" {
			t.Error("CLI did not forward its bound target/context/key")
		}
		fmt.Fprint(w, `{"items":[]}`)
	}))
	defer srv.Close()
	t.Setenv("ER1_API_KEY", "synthetic-cli-session-key")
	t.Setenv("ER1_API_KEY_ORIGIN", srv.URL)
	t.Setenv("ER1_DEVICE_TOKEN", "")
	t.Setenv("ER1_DEVICE_TOKEN_ORIGIN", "")
	t.Setenv("ER1_CONTEXT_ID", "ForeignEnvContext")
	t.Setenv("M3C_ER1_KEYCHAIN", "off")
	t.Setenv("M3C_TOKEN_STORE", "file")
	for _, verb := range []string{"list", "show", "resume"} {
		home := t.TempDir()
		args := []string{"session", verb, "--er1-target", srv.URL + "/TenantA", "--er1-context", "ExplicitCtx"}
		if verb == "show" {
			args = append(args, "no-such-session")
		}
		cmd := exec.Command(binary, args...)
		cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home)
		out, err := cmd.CombinedOutput()
		if verb == "show" {
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 || !strings.Contains(string(out), "no session matching") {
				t.Fatalf("show=%v %s", err, out)
			}
		} else if err != nil {
			t.Fatalf("%s=%v %s", verb, err, out)
		}
		if bytes.Contains(out, []byte("synthetic-cli-session-key")) {
			t.Fatal("credential in CLI output")
		}
	}
	if hits.Load() != 3 {
		t.Fatalf("GET count=%d", hits.Load())
	}
}
