package registry

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kamir/m3c-tools/pkg/httpsafe"
)

const (
	IdentityJSONTokens          = 4096
	IdentityResponseBytes int64 = 1 << 20
	IdentityPhaseCalls          = 256
	IdentityPhaseTimeout        = 30 * time.Second
	// IdentityDecodeWork is a conservative reservation for a response and decode.
	IdentityDecodeWork = 8 * (IdentityResponseBytes + 1)
)

var ErrIdentityResponse = errors.New("registry: bound identity lookup refused")

// BoundIdentityReader snapshots an explicitly selected HTTP identity authority.
// Custom transports remain trusted caller capabilities; this is not a sandbox.
type BoundIdentityReader struct {
	base, token, agent string
	client             http.Client
	owned              *http.Transport
	closed             atomic.Bool
}

// NewBoundIdentityReader validates the complete base before retaining a token.
// Redirects are refused. HTTP is supported only for explicitly allowed loopback.
func NewBoundIdentityReader(client *Client, expectedBase string, allowLoopbackHTTP bool) (*BoundIdentityReader, error) {
	if client == nil || len(expectedBase) > 8192 || len(client.BaseURL) > 8192 || len(client.Token) > 16384 || len(client.UserAgent) > 512 {
		return nil, ErrIdentityResponse
	}
	expected, err := httpsafe.ParseAPIBase(expectedBase, allowLoopbackHTTP)
	if err != nil {
		return nil, ErrIdentityResponse
	}
	actual, err := httpsafe.ParseAPIBase(client.BaseURL, allowLoopbackHTTP)
	if err != nil || strings.TrimRight(actual.URL, "/") != strings.TrimRight(expected.URL, "/") {
		return nil, ErrIdentityResponse
	}
	if !safeIdentityText(client.Token, 16384, true) || !safeIdentityText(client.UserAgent, 512, true) {
		return nil, ErrIdentityResponse
	}
	hc := http.Client{Timeout: IdentityPhaseTimeout}
	if client.HTTPClient != nil {
		hc = *client.HTTPClient
	}
	if hc.Timeout <= 0 || hc.Timeout > IdentityPhaseTimeout {
		hc.Timeout = IdentityPhaseTimeout
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	hc.Jar = nil
	var owned *http.Transport
	transport := hc.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	if tr, ok := transport.(*http.Transport); ok {
		copy := tr.Clone()
		if strings.HasPrefix(expected.URL, "http://") {
			copy.Proxy = nil
		}
		hc.Transport = copy
		owned = copy
	}
	return &BoundIdentityReader{base: strings.TrimRight(expected.URL, "/"), token: strings.TrimSpace(client.Token), agent: client.UserAgent, client: hc, owned: owned}, nil
}

// Close releases this reader's owned idle transport connections and prevents
// subsequent lookups. Trusted custom RoundTrippers are never closed here.
func (r *BoundIdentityReader) Close() {
	if r != nil && !r.closed.Swap(true) && r.owned != nil {
		r.owned.CloseIdleConnections()
	}
}

// IdentityPhase caches successful observations only within one bounded phase.
// A new phase must be used for the final publication recheck.
type IdentityPhase struct {
	reader   *BoundIdentityReader
	mu       sync.Mutex
	started  time.Time
	calls    int
	cache    map[string]Identity
	terminal error
}

func (r *BoundIdentityReader) NewPhase() *IdentityPhase {
	return &IdentityPhase{reader: r, cache: make(map[string]Identity)}
}

func safeIdentityText(s string, max int, empty bool) bool {
	if len(s) > max || !utf8.ValidString(s) || (!empty && (s == "" || strings.TrimSpace(s) != s)) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (p *IdentityPhase) fail(cause error) (*Identity, error) {
	p.terminal = ErrIdentityResponse
	if cause != nil {
		p.terminal = errors.Join(ErrIdentityResponse, cause)
	}
	return nil, p.terminal
}

// GetIdentity returns a copy of a bounded, exact-ID response from the selected
// authority. Errors never include token, URL, response body or transport errors.
func (p *IdentityPhase) GetIdentity(ctx context.Context, id string) (*Identity, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.terminal != nil {
		return nil, p.terminal
	}
	if ctx == nil || p.reader == nil || p.reader.closed.Load() || !safeIdentityText(id, 1024, false) || strings.ContainsAny(id, "/\\") || id == "." || id == ".." {
		return p.fail(nil)
	}
	if err := ctx.Err(); err != nil {
		return p.fail(err)
	}
	now := time.Now()
	if p.started.IsZero() {
		p.started = now
	}
	deadline := p.started.Add(IdentityPhaseTimeout)
	if !now.Before(deadline) {
		return p.fail(context.DeadlineExceeded)
	}
	if value, ok := p.cache[id]; ok {
		return &value, nil
	}
	if p.calls >= IdentityPhaseCalls {
		return p.fail(nil)
	}
	p.calls++
	requestCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, p.reader.base+"/identities/"+url.PathEscape(id), nil)
	if err != nil {
		return p.fail(nil)
	}
	req.Header.Set("Accept", "application/json")
	if p.reader.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.reader.token)
	}
	if p.reader.agent != "" {
		req.Header.Set("User-Agent", p.reader.agent)
	}
	response, err := p.reader.client.Do(req)
	if err != nil {
		return p.fail(requestCtx.Err())
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, IdentityResponseBytes+1))
	closeErr := response.Body.Close()
	if requestCtx.Err() != nil {
		return p.fail(requestCtx.Err())
	}
	if readErr != nil || closeErr != nil || len(body) > int(IdentityResponseBytes) || response.StatusCode/100 != 2 {
		return p.fail(nil)
	}
	identity, err := decodeBoundIdentity(body, id)
	if err != nil {
		return p.fail(nil)
	}
	if requestCtx.Err() != nil {
		return p.fail(requestCtx.Err())
	}
	if p.reader.token != "" {
		for _, value := range []string{identity.ID, identity.PubkeyB64, identity.AuthSource, identity.RevokedAt} {
			if strings.Contains(value, p.reader.token) {
				return p.fail(nil)
			}
		}
	}
	p.cache[id] = *identity
	return identity, nil
}
