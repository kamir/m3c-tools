package main

import (
	"bytes"
	"strings"
	"testing"
)

// The secret comes from stdin and only the first line of it. A token has no line
// breaks, and reading further would store a multi-line blob that fails later with
// a message about cryptography rather than about a paste.
func TestReadSecretTakesOneTrimmedLine(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"glpat-abc\n", "glpat-abc"},
		{"  glpat-abc  \n", "glpat-abc"},
		{"glpat-abc", "glpat-abc"},
		{"glpat-abc\nsecond line\n", "glpat-abc"},
		{"\n", ""},
		{"", ""},
	} {
		got, err := readSecret(strings.NewReader(tc.in))
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("readSecret(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Both identifying flags are required, and the message says WHY the host is one
// of them. A credential is stored per host so one machine can hold tokens for
// several instances; a default would silently bind the token to the wrong one.
func TestTokenSetRequiresBackendAndHost(t *testing.T) {
	for _, args := range [][]string{
		{"--backend", "gitlab"},
		{"--host", "git.example.de"},
		{},
	} {
		var out, errb bytes.Buffer
		if rc := runTokenSet(args, &out, &errb); rc != exitUsage {
			t.Errorf("args %v: rc = %d, want exitUsage", args, rc)
		}
		if !strings.Contains(errb.String(), "--backend and --host are required") {
			t.Errorf("args %v: the message must name both flags, got %q", args, errb.String())
		}
	}
}

// list refuses without a host rather than guessing, and says why: it will not
// walk the credential store to find out which hosts exist.
func TestTokenListRequiresHost(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := runTokenList(nil, &out, &errb); rc != exitUsage {
		t.Errorf("rc = %d, want exitUsage", rc)
	}
	if !strings.Contains(errb.String(), "--host is required") {
		t.Errorf("message must name the flag: %q", errb.String())
	}
}

// A host with nothing provisioned prints every tier as "not provisioned" and
// never a token. The second half is the one worth pinning: a list command that
// leaks the secret it is listing would be worse than no command.
func TestTokenListPrintsNoSecret(t *testing.T) {
	t.Setenv("M3C_GITLAB_TOKEN", "glpat-should-not-be-printed")
	var out, errb bytes.Buffer
	if rc := runTokenList([]string{"--host", "nothing.invalid"}, &out, &errb); rc != exitOK {
		t.Fatalf("rc = %d, want exitOK (stderr: %s)", rc, errb.String())
	}
	if strings.Contains(out.String(), "glpat-should-not-be-printed") {
		t.Fatal("the token value was printed")
	}
	// The env override IS reported as the source, because that is the thing an
	// operator needs to know when a stored token seems to be ignored.
	if !strings.Contains(out.String(), "env M3C_GITLAB_TOKEN") {
		t.Errorf("the env source must be named: %q", out.String())
	}
}

func TestTokenUnknownSubcommandIsUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := runToken([]string{"frobnicate"}, &out, &errb); rc != exitUsage {
		t.Errorf("rc = %d, want exitUsage", rc)
	}
	if !strings.Contains(errb.String(), "unknown subcommand") {
		t.Errorf("message: %q", errb.String())
	}
}
