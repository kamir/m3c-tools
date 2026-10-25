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
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/kamir/m3c-tools/pkg/httpsafe"
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

// newManagedRegistryClient keeps an explicit invalid environment assignment
// from silently becoming an anonymous managed operation.
func newManagedRegistryClient(baseURL string, httpClient *http.Client) (*registry.Client, error) {
	if _, err := httpsafe.NewGETBoundary(baseURL, strings.HasPrefix(baseURL, "http://"), registry.MaxRedirects); err != nil {
		return nil, err
	}
	token, err := boundRegistryToken(baseURL, artifact.ModeRead)
	if err != nil {
		return nil, err
	}
	client := registry.New(baseURL, httpClient)
	client.Token = token
	return client, nil
}

// registryToken resolves the token for baseURL's host, or "" for anonymous.
//
// Every failure path is silent and yields anonymous on purpose: a missing
// keychain entry, an unparsable URL or a locked store must not stop a command
// that may not need a credential at all. What must NOT be silent is the refusal
// that follows, and that is what explainUnauthorized is for.
func registryToken(baseURL string, mode artifact.AccessMode) string {
	token, _ := boundRegistryToken(baseURL, mode)
	return token
}

// registryOrigin compares scheme, normalized hostname and effective port only.
func registryOrigin(raw string) (string, bool, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", false, errors.New("registry URL must have a host and no userinfo, query or fragment")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false, errors.New("unsupported registry URL scheme")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", false, errors.New("registry URL has no hostname")
	}
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", false, errors.New("invalid registry port")
	}
	ip := net.ParseIP(host)
	credentialTransport := scheme == "https" || host == "localhost" || (ip != nil && ip.IsLoopback())
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(number)), credentialTransport, nil
}

// boundRegistryToken refuses unbound environment credentials without mutating the environment.
func boundRegistryToken(baseURL string, mode artifact.AccessMode) (string, error) {
	origin, transportOK, err := registryOrigin(baseURL)
	if err != nil {
		return "", err
	}
	token := ""
	if mode == artifact.ModeRead {
		token = strings.TrimSpace(os.Getenv("M3C_REGISTRY_RO_TOKEN"))
	}
	if token == "" {
		token = strings.TrimSpace(os.Getenv("M3C_REGISTRY_TOKEN"))
	}
	if token != "" {
		pin := os.Getenv("M3C_REGISTRY_TOKEN_ORIGIN")
		pinned, pinnedTransport, pinErr := registryOrigin(pin)
		parsedPin, parseErr := url.Parse(pin)
		if pinErr != nil || parseErr != nil || (parsedPin.Path != "" && parsedPin.Path != "/") || !transportOK || !pinnedTransport || origin != pinned {
			return "", errors.New("registry environment token requires a matching M3C_REGISTRY_TOKEN_ORIGIN (HTTPS or loopback HTTP)")
		}
	}
	// Plain HTTP outside loopback remains anonymous; never consult host stores for it.
	if !transportOK {
		return "", nil
	}
	u, _ := url.Parse(baseURL)
	cred, err := artifactauth.New().Credential(context.Background(), registryCredScheme, u.Host, mode)
	if err != nil {
		return "", err
	}
	return cred.Token, nil
}

// explainUnauthorized turns a 401 or 403 into a message that names the next
// action, and returns err unchanged for anything else.
//
// The point is the distinction a bare status code cannot make: whether no
// credential was sent (absent, disabled or blocked by policy) or the sent token was rejected (wrong,
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
		fmt.Fprintf(w, "  fix: issue a new token and replace it, then re-run. See docs/v2/betrieb/ops-registry-tokens.de.md\n")
		return err
	}
	fmt.Fprintf(w, "registry %s: this instance requires authentication and NO token was sent.\n", host)
	fmt.Fprintln(w, "  why: credentials may be absent, native storage disabled, or an environment token blocked by its origin pin.")
	fmt.Fprintln(w, "  fix: configure M3C_REGISTRY_TOKEN (read-only: M3C_REGISTRY_RO_TOKEN) together with")
	fmt.Fprintln(w, "       M3C_REGISTRY_TOKEN_ORIGIN set to the separately approved HTTPS or loopback-HTTP origin (scheme, host, port).")
	fmt.Fprintln(w, "       Where protected storage is supported, use skillctl token set --backend registry --host <registry-host> [--read-only].")
	fmt.Fprintln(w, "       Native management is disabled by M3C_TOKEN_STORE=file or M3C_TEST_KEYCHAIN=0.")
	fmt.Fprintln(w, "  Guide: docs/v2/betrieb/ops-registry-tokens.en.md (DE: ops-registry-tokens.de.md)")
	return err
}
