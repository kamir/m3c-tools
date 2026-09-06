//go:build darwin

package artifactauth

// The macOS half of the credential writer.
//
// The token is handed to `security` over STDIN, not on the command line. An
// argument is visible to every process on the machine through `ps` for as long as
// the call runs, and it lands in the shell history of anyone who reproduces the
// command by hand. `security -i` reads the same command from stdin, which is not
// visible that way, so the interactive mode is used non-interactively for exactly
// this reason.

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// HasProtectedStore reports whether this platform can keep the token out of the
// process environment.
func HasProtectedStore() bool { return true }

// ProtectedStoreName is what the store is called in a message to a human.
func ProtectedStoreName() string { return "macOS Keychain" }

// platformStore adds or replaces a generic-password item. -U updates in place,
// so re-running after a token rotation does the obvious thing instead of failing
// on a duplicate.
func platformStore(service, account, secret string) error {
	if strings.ContainsAny(secret, "\n\r") {
		// A newline would end the command line inside `security -i` and turn the
		// rest of the token into a second command. Refusing is right: no GitLab or
		// GitHub token contains one, so this is a paste accident, and the
		// alternative is a half-stored credential.
		return fmt.Errorf("artifactauth: the token contains a line break; copy it again without the surrounding whitespace")
	}
	cmd := exec.Command("/usr/bin/security", "-i")
	cmd.Stdin = strings.NewReader(fmt.Sprintf(
		"add-generic-password -s %s -a %s -w %s -U\n",
		quoteKC(service), quoteKC(account), quoteKC(secret)))
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("artifactauth: keychain write failed: %w: %s", err, strings.TrimSpace(errBuf.String()))
	}
	return nil
}

// platformDelete removes the item. A missing item is not an error.
func platformDelete(service, account string) error {
	// #nosec G204 -- no shell is involved, so there is nothing to inject, and both
	// arguments are constrained before they get here: `service` comes from the
	// internal backendCred table (fixed strings, never user input) and `account`
	// has passed validHost, which rejects a leading dash, whitespace and control
	// characters. The leading dash is the case that actually mattered: `security`
	// would have read it as a flag and acted on the wrong item, silently.
	cmd := exec.Command("/usr/bin/security", "delete-generic-password", "-s", service, "-a", account)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		if strings.Contains(errBuf.String(), "could not be found") {
			return nil
		}
		return fmt.Errorf("artifactauth: keychain delete failed: %w: %s", err, strings.TrimSpace(errBuf.String()))
	}
	return nil
}

// quoteKC quotes a value for the `security -i` command line, which splits on
// whitespace and understands double quotes.
func quoteKC(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
