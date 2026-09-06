package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifactauth"
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

// The tier flag maps to the two named tiers. A bool whose polarity has to be
// looked up is exactly what the named type avoids, so the mapping is pinned.
func TestTokenTierMapping(t *testing.T) {
	if tokenTier(true) != artifactauth.TierRead {
		t.Error("--read-only must select the read tier")
	}
	if tokenTier(false) != artifactauth.TierWrite {
		t.Error("without --read-only it must be the write tier")
	}
}

func TestTokenRmRequiresBackendAndHost(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := runTokenRm([]string{"--backend", "gitlab"}, &out, &errb); rc != exitUsage {
		t.Errorf("rc = %d, want exitUsage", rc)
	}
	if !strings.Contains(errb.String(), "--backend and --host are required") {
		t.Errorf("message: %q", errb.String())
	}
}

// rm must say, in its own output, that it did not revoke anything. An operator
// who believes a local delete stopped a leaked token has been actively misled.
func TestTokenRmSaysItIsNotRevocation(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := runTokenRm([]string{"--backend", "gitlab", "--host", "nothing.invalid"}, &out, &errb); rc != exitOK {
		t.Fatalf("rc = %d (stderr %s)", rc, errb.String())
	}
	if !strings.Contains(out.String(), "not revocation") {
		t.Errorf("the output must not let a local delete pass for a revocation: %q", out.String())
	}
}

// A set against a host that reads as an option is refused before anything is
// stored, and the message says which flag is wrong.
func TestTokenSetRefusesAHostThatReadsAsAnOption(t *testing.T) {
	var out, errb bytes.Buffer
	rc := runTokenSetFrom([]string{"--backend", "gitlab", "--host", "-S"}, strings.NewReader("glpat-x\n"), &out, &errb)
	if rc == exitOK {
		t.Fatal("a host beginning with a dash must be refused")
	}
}

func TestTokenHelpMentionsStdin(t *testing.T) {
	var out bytes.Buffer
	if rc := runToken([]string{"--help"}, &out, &out); rc != exitOK {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(out.String(), "stdin") {
		t.Error("the help must say where the token comes from; that is the property this verb exists for")
	}
}
