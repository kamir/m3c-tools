package main

// token_cmds.go: put a registry credential into the platform's protected store,
// list what is provisioned, and remove one.
//
// It exists because the read side already consulted a protected store on both
// platforms and nothing could fill it. On macOS an operator could reach for
// `security add-generic-password` by hand; on Windows the DPAPI writer was built
// and unreachable, so the only option was a write-capable token in a plaintext
// environment variable, inherited by every child process and dumped into crash
// reports. That is the gap this closes, and it is why the verb reads the secret
// from STDIN and never from an argument.

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifactauth"
)

func runToken(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		tokenUsage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "set":
		return runTokenSet(args[1:], stdout, stderr)
	case "list":
		return runTokenList(args[1:], stdout, stderr)
	case "rm":
		return runTokenRm(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		tokenUsage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "skillctl token: unknown subcommand %q\n", args[0])
		tokenUsage(stderr)
		return exitUsage
	}
}

func tokenUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: skillctl token <set|list|rm> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  set     read a token from STDIN and store it protected for one host")
	fmt.Fprintln(w, "  list    show which credentials are provisioned, and from where")
	fmt.Fprintln(w, "  rm      remove a stored credential from this machine")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Flags (set, rm):\n")
	fmt.Fprintf(w, "  --backend <name>   one of %v\n", artifactauth.Backends())
	fmt.Fprintf(w, "  --host <host>      the registry host, e.g. git.kieback-peter.de\n")
	fmt.Fprintf(w, "  --read-only        the READ tier; without it the WRITE tier\n")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags (list):")
	fmt.Fprintln(w, "  --host <host>      restrict to one host (default: every host you name)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The token is read from stdin so it never appears in `ps` or in shell history:")
	fmt.Fprintln(w, "  skillctl token set --backend gitlab --host git.example.de --read-only")
	fmt.Fprintln(w, "  (paste the token, then Ctrl-D)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The routine around this, including which token to ask GitLab for:")
	fmt.Fprintln(w, "  docs/ops-registry-tokens.de.md")
}

func tokenTier(readOnly bool) artifactauth.Tier {
	if readOnly {
		return artifactauth.TierRead
	}
	return artifactauth.TierWrite
}

func runTokenSet(args []string, stdout, stderr io.Writer) int {
	return runTokenSetFrom(args, os.Stdin, stdout, stderr)
}

// runTokenSetFrom is runTokenSet with the secret source injected, so a test can
// drive the whole path without a terminal. The production caller passes os.Stdin.
func runTokenSetFrom(args []string, in io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("token set", flag.ContinueOnError)
	fs.SetOutput(stderr)
	backend := fs.String("backend", "", "credential backend (gitlab, github, registry)")
	host := fs.String("host", "", "registry host")
	readOnly := fs.Bool("read-only", false, "store the READ tier instead of the write tier")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *backend == "" || *host == "" {
		fmt.Fprintln(stderr, "skillctl token set: --backend and --host are required")
		fmt.Fprintf(stderr, "  why: one machine may hold tokens for several instances, so the host is part of the identity.\n")
		return exitUsage
	}
	if !artifactauth.HasProtectedStore() {
		_, env, _ := artifactauth.ServiceFor(*backend, tokenTier(*readOnly))
		fmt.Fprintf(stderr, "skillctl token set: this platform has no protected credential store.\n")
		fmt.Fprintf(stderr, "  fix: export %s instead, and note that it is inherited by every child process.\n", env)
		return exitGeneric
	}

	secret, err := readSecret(in)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl token set: read token from stdin: %v\n", err)
		return exitGeneric
	}
	if secret == "" {
		fmt.Fprintln(stderr, "skillctl token set: no token on stdin.")
		fmt.Fprintln(stderr, "  fix: pipe it in, or run the command and paste the token followed by Ctrl-D.")
		return exitUsage
	}

	if err := artifactauth.Store(*backend, tokenTier(*readOnly), *host, secret); err != nil {
		fmt.Fprintf(stderr, "skillctl token set: %v\n", err)
		return exitGeneric
	}
	service, _, _ := artifactauth.ServiceFor(*backend, tokenTier(*readOnly))
	fmt.Fprintf(stdout, "stored in %s\n", artifactauth.ProtectedStoreName())
	fmt.Fprintf(stdout, "  backend   %s (%s tier)\n", *backend, tokenTier(*readOnly))
	fmt.Fprintf(stdout, "  host      %s\n", *host)
	fmt.Fprintf(stdout, "  service   %s\n", service)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "An environment variable still WINS over this entry if one is set.")
	fmt.Fprintln(stdout, "Check with: skillctl token list --host "+*host)
	fmt.Fprintln(stdout, "Write the register line now, while you know the expiry: OPS/token-register.md")
	return exitOK
}

func runTokenList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("token list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	host := fs.String("host", "", "restrict to one host")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *host == "" {
		fmt.Fprintln(stderr, "skillctl token list: --host is required")
		fmt.Fprintln(stderr, "  why: a credential is stored per host, and there is no way to enumerate")
		fmt.Fprintln(stderr, "       hosts without reading every entry in the store, which this command does not do.")
		return exitUsage
	}
	fmt.Fprintf(stdout, "credentials for %s\n", *host)
	fmt.Fprintf(stdout, "  protected store: %s\n\n", artifactauth.ProtectedStoreName())
	any := false
	for _, b := range artifactauth.Backends() {
		for _, tier := range []artifactauth.Tier{artifactauth.TierRead, artifactauth.TierWrite} {
			service, env, ok := artifactauth.ServiceFor(b, tier)
			if !ok || service == "" {
				continue
			}
			src := artifactauth.Provisioned(b, tier, *host)
			mark := "not provisioned"
			if src != "" {
				mark = "from " + src
				any = true
			}
			fmt.Fprintf(stdout, "  %-9s %-5s  %-28s %s\n", b, tier, mark, "env: "+env)
		}
	}
	if !any {
		fmt.Fprintln(stdout, "\nNothing provisioned for this host. That is fine for a public instance:")
		fmt.Fprintln(stdout, "an unauthenticated request is made and the registry decides.")
	}
	fmt.Fprintln(stdout, "\nThe SOURCE column is the one that matters. An environment variable")
	fmt.Fprintln(stdout, "beats the protected store, so a stale export explains a failure that")
	fmt.Fprintln(stdout, "the stored token would not have.")
	fmt.Fprintln(stdout, "No token is printed here, by design.")
	return exitOK
}

func runTokenRm(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("token rm", flag.ContinueOnError)
	fs.SetOutput(stderr)
	backend := fs.String("backend", "", "credential backend")
	host := fs.String("host", "", "registry host")
	readOnly := fs.Bool("read-only", false, "the READ tier instead of the write tier")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *backend == "" || *host == "" {
		fmt.Fprintln(stderr, "skillctl token rm: --backend and --host are required")
		return exitUsage
	}
	if err := artifactauth.Delete(*backend, tokenTier(*readOnly), *host); err != nil {
		fmt.Fprintf(stderr, "skillctl token rm: %v\n", err)
		return exitGeneric
	}
	fmt.Fprintf(stdout, "removed from this machine: %s (%s tier) for %s\n", *backend, tokenTier(*readOnly), *host)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "This is HYGIENE, not revocation. The token is still valid wherever it")
	fmt.Fprintln(stdout, "was issued. If it may have leaked, revoke it in GitLab; that is the only")
	fmt.Fprintln(stdout, "step that stops it, and it works without touching this machine.")
	return exitOK
}

// readSecret reads the token from stdin and trims the surrounding whitespace a
// paste or a `echo` almost always adds. Only the first line is taken: a token has
// no line breaks, and reading further would silently store a multi-line blob that
// fails later with a confusing message.
func readSecret(r io.Reader) (string, error) {
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
