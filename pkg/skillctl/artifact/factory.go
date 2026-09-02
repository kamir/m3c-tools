package artifact

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// OpenFunc constructs a Backend from a --registry spec and the shared options.
type OpenFunc func(spec string, opts OpenOptions) (Backend, error)

// drivers maps a normalized scheme (SchemeOf) to its constructor. It is
// populated from each backend package's init() via Register; the CLI blank-
// imports those packages to trigger registration. This is the database/sql
// driver pattern — the factory stays decoupled from the implementations.
var drivers = map[string]OpenFunc{}

// Register wires a scheme to its constructor. Called from a backend package's
// init(). Panics on a nil func or a duplicate scheme (a programming error).
func Register(scheme string, fn OpenFunc) {
	if fn == nil {
		panic("artifact: Register with nil OpenFunc for scheme " + scheme)
	}
	if _, dup := drivers[scheme]; dup {
		panic("artifact: duplicate Register for scheme " + scheme)
	}
	drivers[scheme] = fn
}

// Open is the single entry point that replaces the IsER1Registry string check.
// It normalizes spec to a scheme, looks up the registered driver, and builds
// the backend. Unknown schemes return a helpful error naming what IS known.
func Open(spec string, opts OpenOptions) (Backend, error) {
	scheme := SchemeOf(spec)
	fn, ok := drivers[scheme]
	if !ok {
		return nil, fmt.Errorf("artifact: no backend registered for scheme %q (spec %q); known: %s",
			scheme, spec, strings.Join(knownSchemes(), ", "))
	}
	return fn(spec, opts)
}

// SchemeOf normalizes a --registry spec to its backend scheme key. The bare
// literal "self" and any "er1://…" both map to "er1"; http(s) admission URLs
// map to "https"; the git/OCI schemes map to themselves. An unrecognized
// "foo://…" maps to "foo" (so Open returns a precise "no backend for foo"),
// and a spec with no scheme maps to "".
func SchemeOf(spec string) string {
	switch {
	case spec == "self":
		return "er1"
	case strings.HasPrefix(spec, "er1://"):
		return "er1"
	case strings.HasPrefix(spec, "http://"), strings.HasPrefix(spec, "https://"):
		return "https"
	case strings.HasPrefix(spec, "github://"):
		return "github"
	case strings.HasPrefix(spec, "gitlab://"):
		return "gitlab"
	case strings.HasPrefix(spec, "oci://"):
		return "oci"
	default:
		if i := strings.Index(spec, "://"); i > 0 {
			return spec[:i]
		}
		return ""
	}
}

// Registered reports whether a driver is registered for the given spec's
// scheme. Useful for CLI capability checks before Open.
func Registered(spec string) bool {
	_, ok := drivers[SchemeOf(spec)]
	return ok
}

func knownSchemes() []string {
	out := make([]string, 0, len(drivers))
	for s := range drivers {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// OpenOptions carries everything a backend constructor needs that is not
// encoded in the spec. Credential and trust-root resolution are injected as
// interfaces so this package stays a leaf and the CLI wires the concrete
// implementations (pkg/skillctl/artifactauth, pkg/skillctl/verify).
type OpenOptions struct {
	// ER1 knobs (er1 backend). Resolved today by resolveER1Config/er1Endpoint;
	// those move behind the er1 backend's OpenFunc.
	ER1Target  string
	ER1Context string

	// Creds resolves the auth material for a (scheme, host). nil is allowed for
	// backends/operations that need none (e.g. an anonymous read).
	Creds CredentialSource

	// TrustRoots supplies the pinned pubkey material the verify gates need.
	TrustRoots TrustProvider

	// HTTPClient allows tests to inject a transport; nil => backend default.
	HTTPClient *http.Client
}

// AccessMode distinguishes a read-only credential resolution (a verifying PULL:
// Fetch/List/Resolve/Events) from a write resolution (Publish/attest/revoke — a
// push). CD-13: the mode lets a resolver hand back a NARROWER, read-only token on
// the read path when the operator provisioned one, so a verifying pull never
// transmits a write-scoped registry token. A resolver that ignores the mode stays
// correct — it just returns the same token for both — so the interface remains
// backward-compatible.
type AccessMode int

const (
	// ModeRead is a verifying pull; the least-privilege (read-only) token is
	// preferred when one exists.
	ModeRead AccessMode = iota
	// ModeWrite is a publish/attest/revoke; a write-capable token is required.
	ModeWrite
)

// String renders the mode for logs/errors.
func (m AccessMode) String() string {
	if m == ModeWrite {
		return "write"
	}
	return "read"
}

// CredentialSource resolves backend credentials keyed on scheme+host (the
// git-credential.<url> / npm-per-registry-token shape) and an access mode
// (read vs write — CD-13). Read-only by contract: implementations MUST NOT write
// or delete any credential store.
type CredentialSource interface {
	Credential(ctx context.Context, scheme, host string, mode AccessMode) (Credential, error)
}

// Credential is one resolved credential. Value is the raw secret; the caller
// applies the wire encoding appropriate to the backend.
type Credential struct {
	Scheme string // "X-API-KEY" | "Bearer" | "PRIVATE-TOKEN" | "oci-login" | ...
	Token  string
	User   string
}

// TrustProvider is the minimal pinned-trust surface a backend needs to hand to
// the verifier. registry.SelfTrustRoots satisfies this almost verbatim.
type TrustProvider interface {
	PubKey() ed25519.PublicKey
	MeetsFloor(level string) bool
	GovernanceMinimum() string
	Fingerprint() string
}
