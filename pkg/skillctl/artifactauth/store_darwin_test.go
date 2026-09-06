//go:build darwin

package artifactauth

import (
	"os/exec"
	"strings"
	"testing"
)

// The round trip against the real Keychain, which is the only thing that proves
// the write side works. Everything else in this package's tests checks the logic
// AROUND the store; this checks the store.
//
// It uses a service name no backend maps to, so it cannot touch an operator's
// real credential, and it removes what it wrote. It skips rather than fails when
// the Keychain is unavailable (a locked or absent login keychain on a build
// machine is not a defect in this code).
func TestKeychainRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("/usr/bin/security"); err != nil {
		t.Skip("no /usr/bin/security on this machine")
	}
	const service = "m3c-skillctl-selftest"
	const account = "roundtrip.invalid"
	const secret = `glpat-round trip "quoted" \backslash`

	if err := platformStore(service, account, secret); err != nil {
		if strings.Contains(err.Error(), "User interaction is not allowed") ||
			strings.Contains(err.Error(), "The user name or passphrase you entered is not correct") {
			t.Skipf("keychain not usable in this environment: %v", err)
		}
		t.Fatalf("platformStore: %v", err)
	}
	t.Cleanup(func() { _ = platformDelete(service, account) })

	if got := keychain(service, account); got != secret {
		t.Fatalf("read back %q, want %q", got, secret)
	}

	// Overwriting must update in place, because a token rotation re-runs the same
	// command and a duplicate-item error at that moment would be the worst timing.
	const rotated = "glpat-rotated"
	if err := platformStore(service, account, rotated); err != nil {
		t.Fatalf("second store (rotation): %v", err)
	}
	if got := keychain(service, account); got != rotated {
		t.Fatalf("after rotation read back %q, want %q", got, rotated)
	}

	if err := platformDelete(service, account); err != nil {
		t.Fatalf("platformDelete: %v", err)
	}
	if got := keychain(service, account); got != "" {
		t.Fatalf("after delete the item is still readable: %q", got)
	}
	// Deleting what is already gone is not an error: the caller asked for it to be
	// absent, and it is.
	if err := platformDelete(service, account); err != nil {
		t.Errorf("second delete: %v", err)
	}
}

// A token with a line break is refused rather than half-stored. It would end the
// command line inside `security -i` and turn the remainder into a second command.
func TestKeychainRefusesALineBreak(t *testing.T) {
	err := platformStore("m3c-skillctl-selftest", "linebreak.invalid", "glpat-a\nglpat-b")
	if err == nil || !strings.Contains(err.Error(), "line break") {
		t.Errorf("err = %v, want a refusal naming the line break", err)
	}
}

func TestQuoteKCEscapes(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`plain`, `"plain"`},
		{`with "quote"`, `"with \"quote\""`},
		{`back\slash`, `"back\\slash"`},
	} {
		if got := quoteKC(tc.in); got != tc.want {
			t.Errorf("quoteKC(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
