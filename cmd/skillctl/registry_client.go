package main

// registry_client.go resolves the credential for the HTTP registry and hands
// back a client that carries it (FR-0117).
//
// The resolution lives here, at the command layer, and not in pkg/skillctl/registry.
// That package is the transport: it should be drivable from a test without an
// environment, a keychain or a home directory, and a future credential source
// should be changeable without touching it. The git backends already work this
// way, with credentials injected through artifact.OpenOptions, and this is the
// same seam for the third backend.
//
// Anonymous stays the default. A registry that serves its endpoints without
// authentication keeps working for someone who provisioned nothing, which is how
// the public path and every existing test behave.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	"github.com/kamir/m3c-tools/pkg/skillctl/artifactauth"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// errRegistryUnauthorized is registry.ErrUnauthorized under a local name.
//
// attest_cmds.go has a flag variable called `registry`, which shadows the
// package name in that file, so it cannot write registry.ErrUnauthorized. Naming
// it once here is cheaper than renaming a flag that appears in documented output.
var errRegistryUnauthorized = registry.ErrUnauthorized

// registryCredScheme is the key artifactauth uses for the HTTP registry tier.
const registryCredScheme = "registry"

// newRegistryClient builds a registry client for baseURL with whatever token is
// provisioned for its host, or none.
//
// The tier matters: an operator who provisioned only a write token gets it for
// both, which is the existing single-token behaviour; one who also provisioned a
// read-only token never transmits the write token on a read.
// newRegistryClient builds a READ client. Every registry.Client in this binary
// reads: pull, verify, export. The write surface is `attest`, which posts a raw
// request and takes its token from registryToken directly.
func newRegistryClient(baseURL string, httpClient *http.Client) *registry.Client {
	c := registry.New(baseURL, httpClient)
	c.Token = registryToken(baseURL, artifact.ModeRead)
	return c
}

// registryToken resolves the token for baseURL's host, or "" for anonymous.
//
// Every failure path is silent and yields anonymous on purpose: a missing
// keychain entry, an unparsable URL or a locked store must not stop a command
// that may not need a credential at all. What must NOT be silent is the refusal
// that follows, and that is what explainUnauthorized is for.
func registryToken(baseURL string, mode artifact.AccessMode) string {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return ""
	}
	cred, err := artifactauth.New().Credential(context.Background(), registryCredScheme, u.Host, mode)
	if err != nil {
		return ""
	}
	return cred.Token
}

// explainUnauthorized turns a 401 or 403 into a message that names the next
// action, and returns err unchanged for anything else.
//
// The point is the distinction a bare status code cannot make: whether no
// credential was sent (provision one) or the one sent was rejected (it is wrong,
// expired or lacks the scope). The client knows which, because it knows whether
// it set the header.
func explainUnauthorized(w io.Writer, baseURL string, sent bool, err error) error {
	if !errors.Is(err, registry.ErrUnauthorized) {
		return err
	}
	host := baseURL
	if u, perr := url.Parse(baseURL); perr == nil && u.Host != "" {
		host = u.Host
	}
	if sent {
		fmt.Fprintf(w, "registry %s: the token was REJECTED.\n", host)
		fmt.Fprintln(w, "  why: it is wrong, expired, or lacks the scope this endpoint needs.")
		fmt.Fprintf(w, "  fix: issue a new token and replace it, then re-run. See docs/ops-registry-tokens.de.md\n")
		return err
	}
	fmt.Fprintf(w, "registry %s: this instance requires authentication and NO token was sent.\n", host)
	fmt.Fprintln(w, "  why: no credential is provisioned on this machine for that host.")
	fmt.Fprintf(w, "  fix: provide one of, in this order of precedence:\n")
	fmt.Fprintf(w, "         env   M3C_REGISTRY_TOKEN (read-only: M3C_REGISTRY_RO_TOKEN)\n")
	fmt.Fprintf(w, "         macOS security add-generic-password -s m3c-skillctl-registry -a %s -w '<token>' -U\n", host)
	fmt.Fprintln(w, "  The full routine, including how a KuP account issues the token: docs/ops-registry-tokens.de.md")
	return err
}
