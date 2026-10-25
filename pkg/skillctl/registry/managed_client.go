package registry

import (
	"errors"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/kamir/m3c-tools/pkg/httpsafe"
)

// ErrManagedTransport is a constant request/constructor refusal.
var ErrManagedTransport = errors.New("registry: managed HTTP request refused")

type managedTransport struct {
	boundary     *httpsafe.GETBoundary
	next         http.RoundTripper
	token, agent string
	owned        *http.Transport
	closed       atomic.Bool
}

func (t *managedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.closed.Load() || t.boundary.Validate(req) != nil {
		return nil, ErrManagedTransport
	}
	copy := req.Clone(req.Context())
	copy.Header = req.Header.Clone()
	copy.Header.Del("Authorization")
	copy.Header.Del("Cookie")
	if t.token != "" {
		copy.Header.Set("Authorization", "Bearer "+t.token)
	}
	if t.agent != "" {
		copy.Header.Set("User-Agent", t.agent)
	} else {
		copy.Header.Del("User-Agent")
	}
	response, err := t.next.RoundTrip(copy)
	if err != nil {
		return nil, managedRequestError{operation: "request", cause: err}
	}
	return response, nil
}
func (t *managedTransport) close() {
	if !t.closed.Swap(true) && t.owned != nil {
		t.owned.CloseIdleConnections()
	}
}

type managedRequestError struct {
	operation string
	cause     error
}

func (e managedRequestError) Error() string { return "registry: managed " + e.operation + " refused" }
func (e managedRequestError) Unwrap() error { return e.cause }
func (c *Client) managedError(operation string, err error) error {
	if err == nil || c.managed == nil {
		return err
	}
	return managedRequestError{operation: operation, cause: err}
}

// NewManagedClient retains explicit client/credential inputs under a validated
// complete GET authority. It never reads environment or native credentials.
// cleanup closes owned idle connections, never a shared custom RoundTripper.
func NewManagedClient(client *Client, expectedBase string, allowLoopbackHTTP bool) (*Client, func(), error) {
	if client == nil || len(client.BaseURL) > 8192 || len(client.Token) > 16384 || len(client.UserAgent) > 512 {
		return nil, nil, ErrManagedTransport
	}
	boundary, err := httpsafe.NewGETBoundary(expectedBase, allowLoopbackHTTP, MaxRedirects)
	if err != nil {
		return nil, nil, ErrManagedTransport
	}
	actual, err := httpsafe.ParseAPIBase(client.BaseURL, allowLoopbackHTTP)
	if err != nil {
		return nil, nil, ErrManagedTransport
	}
	expected, err := httpsafe.ParseAPIBase(expectedBase, allowLoopbackHTTP)
	if err != nil || strings.TrimRight(actual.URL, "/") != strings.TrimRight(expected.URL, "/") {
		return nil, nil, ErrManagedTransport
	}
	if !safeIdentityText(client.Token, 16384, true) || !safeIdentityText(client.UserAgent, 512, true) {
		return nil, nil, ErrManagedTransport
	}
	hc := http.Client{Timeout: DefaultTimeout}
	if client.HTTPClient != nil {
		hc = *client.HTTPClient
	}
	if hc.Timeout <= 0 || hc.Timeout > DefaultTimeout {
		hc.Timeout = DefaultTimeout
	}
	hc.Jar = nil
	hc.CheckRedirect = boundary.CheckRedirect
	next := hc.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	transport := &managedTransport{boundary: boundary, next: next, token: strings.TrimSpace(client.Token), agent: client.UserAgent}
	if tr, ok := next.(*http.Transport); ok {
		copy := tr.Clone()
		if strings.HasPrefix(expected.URL, "http://") {
			copy.Proxy = nil
		}
		transport.next = copy
		transport.owned = copy
	}
	hc.Transport = transport
	result := *client
	result.BaseURL = strings.TrimRight(expected.URL, "/")
	result.Token = transport.token
	result.HTTPClient = &hc
	result.managed = transport
	return &result, transport.close, nil
}
