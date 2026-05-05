package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultTimeout is the per-request deadline applied if the caller hasn't
// configured an HTTPClient explicitly. 30s mirrors what the SPEC-0188
// implementation plan promises in its risk section ("30s default timeout
// per HTTP call").
const DefaultTimeout = 30 * time.Second

// MaxRedirects bounds how many redirects a single request will follow
// before erroring. The spec doesn't require us to follow ANY — admission
// endpoints are direct — but we accept a small number to survive load
// balancers without enabling a redirect-bounce attack.
const MaxRedirects = 5

// MaxBlobSize is a defensive ceiling on the bundle blob a single
// `GetBundle` call will read into memory. 256 MiB is well above any
// realistic skill bundle (typical bundles measure in tens of KiB to a
// few MiB) but small enough that a server-side bug or a hostile registry
// can't OOM the verifier. S8 may choose to stream to a temp file
// instead — that's its call; this client serves the in-memory case.
const MaxBlobSize int64 = 256 << 20 // 256 MiB

// ErrNotFound is returned by the high-level methods when the registry
// returns 404 for the resource. Sentinel-comparable so callers can branch
// without parsing strings.
//
// Note: this does NOT map directly to verify.ErrBlobMissing. The verify
// layer maps a 404 on `GET /bundles/<digest>` (blob path) to
// ErrBlobMissing; a 404 on `/by-name` is "name unknown" and surfaces as
// a generic install failure. Translation lives in S8, not here.
var ErrNotFound = errors.New("registry: not found")

// Client is the HTTP client for the aims-core skill-registry endpoints.
// Construct via New(); zero-value Client is not usable (BaseURL would be
// empty).
type Client struct {
	// BaseURL is the registry root, e.g.
	// https://aims.example.com/api/skills. Must NOT have a trailing
	// slash (the constructor strips it). Path segments are appended
	// directly, so "/api/skills" + "/by-name/foo" = "/api/skills/by-name/foo".
	BaseURL string

	// HTTPClient is the underlying transport. Callers can inject a
	// pre-configured client for tests (httptest.Server) or for production
	// timeout/transport tuning. If nil, the constructor installs a
	// default with DefaultTimeout and MaxRedirects.
	HTTPClient *http.Client

	// UserAgent is sent on every request. Defaults to "skillctl/<version>"
	// per stream S7 brief; callers can override for diagnostic tags.
	UserAgent string
}

// New constructs a Client with sane defaults. Pass nil for httpClient to
// get the default (30s timeout, redirect cap). The baseURL trailing slash
// is stripped.
//
// New does NOT validate the URL scheme; that's trustroots.go's job at
// config time. By the time a Client is constructed against a registry,
// the URL has already passed through trust-roots validation.
func New(baseURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: DefaultTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= MaxRedirects {
					return fmt.Errorf("registry: stopped after %d redirects", MaxRedirects)
				}
				return nil
			},
		}
	}
	return &Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: httpClient,
		UserAgent:  "skillctl/0.0.0-spec0188",
	}
}

// ResolveByName issues `GET /by-name/<name>` and returns the version
// list. Newest-first ordering is the server's responsibility; this
// client preserves whatever order it received.
//
// Returns ErrNotFound (wrapped) on 404 so callers can distinguish "no
// such skill name" from network/transport failures.
func (c *Client) ResolveByName(ctx context.Context, name string) ([]BundleVersion, error) {
	if name == "" {
		return nil, errors.New("registry: name is required")
	}
	if err := validateNameSafe(name); err != nil {
		return nil, err
	}
	u := c.BaseURL + "/by-name/" + url.PathEscape(name)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("registry: build request: %w", err)
	}
	c.setHeaders(req, "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registry: GET %s: %w", u, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("registry: by-name %q: %w", name, ErrNotFound)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("registry: GET %s: HTTP %d", u, resp.StatusCode)
	}

	var body struct {
		Name     string          `json:"name"`
		Versions []BundleVersion `json:"versions"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)) // 8 MiB cap on metadata
	if err := dec.Decode(&body); err != nil {
		return nil, fmt.Errorf("registry: decode by-name response: %w", err)
	}
	return body.Versions, nil
}

// GetBundle issues `GET /bundles/<digest>` and returns the raw blob
// bytes. Reads up to MaxBlobSize; if the server sends more, the read
// errors out so a hostile or buggy server can't blow up memory.
//
// digest must be the canonical "sha256:<hex>" form. We don't validate
// here — the verify layer in S8 recomputes the digest from the returned
// bytes and refuses on mismatch, which is the authoritative check.
func (c *Client) GetBundle(ctx context.Context, digest string) ([]byte, error) {
	if digest == "" {
		return nil, errors.New("registry: digest is required")
	}
	u := c.BaseURL + "/bundles/" + url.PathEscape(digest)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("registry: build request: %w", err)
	}
	c.setHeaders(req, "application/octet-stream")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registry: GET %s: %w", u, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("registry: bundle %s: %w", digest, ErrNotFound)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("registry: GET %s: HTTP %d", u, resp.StatusCode)
	}

	// io.ReadAll with a LimitReader so a 100-GB Content-Length doesn't
	// trick us into trying to allocate it all.
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBlobSize+1))
	if err != nil {
		return nil, fmt.Errorf("registry: read blob: %w", err)
	}
	if int64(len(body)) > MaxBlobSize {
		return nil, fmt.Errorf("registry: bundle %s exceeds max size %d bytes", digest, MaxBlobSize)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("registry: bundle %s: empty body", digest)
	}
	return body, nil
}

// GetBundleMeta issues `GET /bundles/<digest>?meta=1` and returns the
// JSON envelope (bundle metadata + signatures + optional manifest).
//
// This is the canonical metadata fetch the verifier uses; GetBundle
// returns just the blob bytes for digest recomputation, while
// GetBundleMeta returns the surrounding signatures and provenance.
func (c *Client) GetBundleMeta(ctx context.Context, digest string) (*BundleMeta, error) {
	if digest == "" {
		return nil, errors.New("registry: digest is required")
	}
	u := c.BaseURL + "/bundles/" + url.PathEscape(digest) + "?meta=1"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("registry: build request: %w", err)
	}
	c.setHeaders(req, "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registry: GET %s: %w", u, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("registry: bundle %s meta: %w", digest, ErrNotFound)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("registry: GET %s: HTTP %d", u, resp.StatusCode)
	}

	var meta BundleMeta
	dec := json.NewDecoder(io.LimitReader(resp.Body, 8<<20))
	if err := dec.Decode(&meta); err != nil {
		return nil, fmt.Errorf("registry: decode bundle meta: %w", err)
	}
	return &meta, nil
}

// GetIdentity issues `GET /identities/<id>` and returns the identity
// document. The wire format spelled the public-key field as either
// `pubkey` or `pubkey_b64`; Identity.UnmarshalJSON handles both.
func (c *Client) GetIdentity(ctx context.Context, id string) (*Identity, error) {
	if id == "" {
		return nil, errors.New("registry: identity id is required")
	}
	u := c.BaseURL + "/identities/" + url.PathEscape(id)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("registry: build request: %w", err)
	}
	c.setHeaders(req, "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registry: GET %s: %w", u, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("registry: identity %s: %w", id, ErrNotFound)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("registry: GET %s: HTTP %d", u, resp.StatusCode)
	}

	var ident Identity
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err := dec.Decode(&ident); err != nil {
		return nil, fmt.Errorf("registry: decode identity: %w", err)
	}
	if ident.ID == "" {
		// Defensive: a server that returns 200 with no `id` is
		// malformed enough that we shouldn't accept it.
		return nil, fmt.Errorf("registry: identity %s: response has empty id", id)
	}
	return &ident, nil
}

// setHeaders applies the standard request headers. Pulled out so
// callers can't accidentally diverge between the four methods.
func (c *Client) setHeaders(req *http.Request, accept string) {
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
}

// validateNameSafe rejects skill names containing path separators or
// control characters. The server is responsible for its own validation,
// but we don't want a malicious or buggy caller to construct a request
// path that escapes the `/by-name/` segment.
func validateNameSafe(name string) error {
	if strings.ContainsAny(name, "/\\\x00") {
		return fmt.Errorf("registry: skill name %q contains invalid characters", name)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("registry: skill name %q contains control characters", name)
		}
	}
	return nil
}

// Retry policy: there is none. Each method makes exactly ONE HTTP
// request. The verifier sits on the user's machine and is invoked
// interactively; a transient 5xx surfaces immediately so the user can
// retry rather than the client silently masking a registry outage. If a
// future requirement adds retries it should land at the call site (with
// jitter, with idempotency keys for POSTs) — not transparently inside
// these getters.
var _ = struct{}{} // documentation anchor, intentionally empty
