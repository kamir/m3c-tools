package artifactauth

// store.go is the WRITE side of the credential resolution, and it is deliberately
// small and separate.
//
// The package doc says the resolver is read-only, and that stays true: nothing in
// creds.go writes. This file adds an explicit, opt-in writer that only the
// `skillctl token` verb calls, so the property that mattered (a resolution path
// that structurally cannot delete a credential store) is unchanged.
//
// It exists because of an asymmetry that made the Windows story worse than the
// macOS one: the DPAPI writer had been built (creds_windows.go, WIN-T6) and
// nothing called it, so a Windows operator's only option was a write-capable
// token in a plaintext environment variable, inherited by every child process.
// The read side supported the protected store; the operator had no way to fill it.

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
)

// envValue reads and trims one environment variable. It exists so Provisioned
// reports exactly what the resolver would use, whitespace handling included: a
// token pasted with a trailing newline is treated the same in both places.
func envValue(name string) string { return strings.TrimSpace(os.Getenv(name)) }

// Tier names the two credential tiers. They are strings rather than a bool so a
// caller and its help text say "read" and "write" instead of a flag whose
// polarity has to be looked up.
type Tier string

const (
	TierWrite Tier = "write"
	TierRead  Tier = "read"
)

// ServiceFor returns the credential-store service name and the environment
// variable for one backend and tier.
//
// It is the single place that knows those names. Before this, the CLI, the docs
// and the resolver each spelled them out, and a rename would have had to find all
// three.
func ServiceFor(backend string, tier Tier) (service, env string, ok bool) {
	m, found := backendCred[backend]
	if !found {
		return "", "", false
	}
	if tier == TierRead {
		return m.roKcService, m.roEnv, true
	}
	return m.kcService, m.env, true
}

// Backends lists the backends that have a credential tier, sorted, for help text
// and for validating user input against something other than a hard-coded list.
func Backends() []string {
	out := make([]string, 0, len(backendCred))
	for k := range backendCred {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Store writes secret into the platform's protected credential store for
// (backend, tier, host).
//
// It refuses rather than falling back to something weaker. A silent fallback to
// a file or an environment variable would be the worst outcome here: the operator
// would believe the token is protected because the command said nothing.
func Store(backend string, tier Tier, host, secret string) error {
	service, env, ok := ServiceFor(backend, tier)
	if !ok {
		return fmt.Errorf("artifactauth: unknown backend %q (known: %v)", backend, Backends())
	}
	if service == "" {
		return fmt.Errorf("artifactauth: backend %q has no %s tier", backend, tier)
	}
	if err := validHost(host); err != nil {
		return err
	}
	if secret == "" {
		return fmt.Errorf("artifactauth: refusing to store an empty token")
	}
	if !HasProtectedStore() {
		return fmt.Errorf("artifactauth: %s has no protected credential store here; "+
			"use the environment variable %s instead, and keep in mind it is inherited by every child process",
			runtime.GOOS, env)
	}
	return platformStore(service, host, secret)
}

// Delete removes the stored credential. A missing entry is not an error: the
// caller asked for it to be gone, and it is.
//
// Deleting locally is HYGIENE, not a revocation. The credential remains valid
// wherever it was issued until it is revoked there, and any message about this
// has to say so, or an operator will believe they closed a door they only shut.
func Delete(backend string, tier Tier, host string) error {
	service, _, ok := ServiceFor(backend, tier)
	if !ok {
		return fmt.Errorf("artifactauth: unknown backend %q (known: %v)", backend, Backends())
	}
	if service == "" {
		return fmt.Errorf("artifactauth: backend %q has no %s tier", backend, tier)
	}
	if err := validHost(host); err != nil {
		return err
	}
	return platformDelete(service, host)
}

// Provisioned reports where a credential for (backend, tier, host) comes from,
// or "" when none is found. It never returns the secret.
//
// The distinction between "env" and the protected store is the point: an operator
// who thinks a token sits in the keychain, while an old environment variable
// actually wins, will not understand a later failure. The order here is the
// resolver's order, so what this prints is what a pull would use.
func Provisioned(backend string, tier Tier, host string) string {
	service, env, ok := ServiceFor(backend, tier)
	if !ok || service == "" {
		return ""
	}
	if env != "" && envValue(env) != "" {
		return "env " + env
	}
	if runtime.GOOS == "darwin" && keychain(service, host) != "" {
		return "keychain " + service
	}
	if osCredStore(service, host) != "" {
		return "protected store " + service
	}
	return ""
}

// validHost rejects a host that could be mistaken for an option by the tool that
// stores the credential.
//
// The macOS store shells out to `security`, and although exec.Command uses no
// shell (so there is nothing to inject), a value beginning with "-" would be read
// by `security` as a FLAG rather than as an account name. That is not a code
// injection, it is worse in one respect: it would silently act on the wrong item.
// Whitespace and control characters are rejected for the same reason, plus the
// `security -i` line format, which splits on whitespace.
//
// A host is a hostname, optionally with a port. Nothing legitimate is lost.
func validHost(host string) error {
	if host == "" {
		return fmt.Errorf("artifactauth: a host is required; it is what lets one machine hold tokens for several instances")
	}
	if strings.HasPrefix(host, "-") {
		return fmt.Errorf("artifactauth: refusing host %q: a leading dash would be read as an option, not as a host", host)
	}
	for _, r := range host {
		if r < 0x21 || r == 0x7f {
			return fmt.Errorf("artifactauth: refusing host %q: it contains whitespace or a control character", host)
		}
	}
	return nil
}
