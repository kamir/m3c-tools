package registry

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type identityRoundTrip func(*http.Request) (*http.Response, error)

func (f identityRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type identityBody struct {
	io.Reader
	closeErr error
	closed   bool
}

func (b *identityBody) Close() error { b.closed = true; return b.closeErr }
func identityWire(id string) string {
	return fmt.Sprintf(`{"id":%q,"pubkey_b64":%q,"auth_source":"manual"}`, id, base64.StdEncoding.EncodeToString(make([]byte, 32)))
}
func identityTestReader(t *testing.T, rt http.RoundTripper) *BoundIdentityReader {
	t.Helper()
	r, err := NewBoundIdentityReader(&Client{BaseURL: "https://registry.invalid/prefix", Token: "synthetic-secret", HTTPClient: &http.Client{Transport: rt}}, "https://registry.invalid/prefix", false)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestBoundIdentityReaderResponses(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cases := map[string]string{
		"valid":             identityWire("author"),
		"legacy":            `{"id":"author","pubkey":"` + key + `","auth_source":"manual"}`,
		"same_aliases":      `{"id":"author","pubkey":"` + key + `","pubkey_b64":"` + key + `","auth_source":"manual"}`,
		"foreign":           identityWire("foreign"),
		"duplicate":         `{"id":"author","id":"author","pubkey":"` + key + `","auth_source":"manual"}`,
		"escaped_duplicate": `{"id":"author","\u0069d":"author","pubkey":"` + key + `","auth_source":"manual"}`,
		"case_alias":        `{"ID":"author","pubkey":"` + key + `","auth_source":"manual"}`,
		"null":              `null`, "trailing": identityWire("author") + `{}`,
		"missing_auth":     `{"id":"author","pubkey":"` + key + `"}`,
		"null_status":      `{"id":"author","pubkey":"` + key + `","auth_source":"manual","revoked_at": null }`,
		"conflict":         `{"id":"author","pubkey":"` + key + `","pubkey_b64":"different","auth_source":"manual"}`,
		"utf8":             strings.Replace(identityWire("author"), "manual", string([]byte{0xff}), 1),
		"known_secret":     strings.Replace(identityWire("author"), "manual", "synthetic-secret", 1),
		"oversize":         identityWire("author") + strings.Repeat(" ", int(IdentityResponseBytes)),
		"nested_duplicate": strings.TrimSuffix(identityWire("author"), "}") + `,"unknown":{"a":1,"a":2}}`,
		"token_budget":     strings.TrimSuffix(identityWire("author"), "}") + `,"unknown":[` + strings.Repeat("0,", IdentityJSONTokens) + `0]}`,
		"depth":            strings.TrimSuffix(identityWire("author"), "}") + `,"unknown":` + strings.Repeat("[", 32) + `0` + strings.Repeat("]", 32) + `}`,
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			body := &identityBody{Reader: strings.NewReader(wire)}
			calls := 0
			r := identityTestReader(t, identityRoundTrip(func(req *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header)}, nil
			}))
			id, err := r.NewPhase().GetIdentity(context.Background(), "author")
			good := name == "valid" || name == "legacy" || name == "same_aliases"
			if good {
				if err != nil || id == nil || id.ID != "author" {
					t.Fatalf("valid response refused: %v", err)
				}
			} else if !errors.Is(err, ErrIdentityResponse) || id != nil || strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatalf("invalid response accepted or reflected: %v", err)
			}
			if calls != 1 || !body.closed {
				t.Fatal("response lifecycle not exercised")
			}
		})
	}
	for _, fault := range []string{"close", "read", "status", "network"} {
		t.Run(fault, func(t *testing.T) {
			body := &identityBody{Reader: strings.NewReader(identityWire("author"))}
			r := identityTestReader(t, identityRoundTrip(func(*http.Request) (*http.Response, error) {
				if fault == "network" {
					return nil, errors.New("synthetic-secret")
				}
				if fault == "close" {
					body.closeErr = errors.New("synthetic-secret")
				}
				if fault == "read" {
					body.Reader = io.MultiReader(strings.NewReader("{"), identityReadError{})
				}
				status := 200
				if fault == "status" {
					status = 401
				}
				return &http.Response{StatusCode: status, Body: body, Header: make(http.Header)}, nil
			}))
			_, err := r.NewPhase().GetIdentity(context.Background(), "author")
			if err == nil || strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatalf("fault escaped: %v", err)
			}
			if fault != "network" && !body.closed {
				t.Fatal("body not closed")
			}
		})
	}
}

type identityReadError struct{}

func (identityReadError) Read([]byte) (int, error) { return 0, errors.New("synthetic-secret") }

func TestBoundIdentityReaderPhases(t *testing.T) {
	calls := 0
	r := identityTestReader(t, identityRoundTrip(func(req *http.Request) (*http.Response, error) {
		calls++
		id := strings.TrimPrefix(req.URL.Path, "/prefix/identities/")
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(identityWire(id))), Header: make(http.Header)}, nil
	}))
	phase := r.NewPhase()
	a, err := phase.GetIdentity(context.Background(), "author")
	if err != nil {
		t.Fatal(err)
	}
	a.AuthSource = "mutated"
	b, err := phase.GetIdentity(context.Background(), "author")
	if err != nil || calls != 1 || b.AuthSource != "manual" {
		t.Fatal("cache snapshot failed")
	}
	if _, err := r.NewPhase().GetIdentity(context.Background(), "author"); err != nil || calls != 2 {
		t.Fatal("fresh phase reused cache")
	}
	p := r.NewPhase()
	for n := 0; n < IdentityPhaseCalls; n++ {
		if _, err := p.GetIdentity(context.Background(), fmt.Sprintf("author%d", n)); err != nil {
			t.Fatal(err)
		}
	}
	before := calls
	if _, err := p.GetIdentity(context.Background(), "overflow"); err == nil || calls != before {
		t.Fatal("call cap ignored")
	}
	if _, err := p.GetIdentity(context.Background(), "author0"); err == nil || calls != before {
		t.Fatal("terminal failure retried")
	}
	expired := r.NewPhase()
	expired.started = time.Now().Add(-IdentityPhaseTimeout)
	if _, err := expired.GetIdentity(context.Background(), "author"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("phase deadline ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.NewPhase().GetIdentity(ctx, "author"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	for _, bad := range []string{"", "..", "a/b", "a\\b", "a\n", strings.Repeat("a", 1025)} {
		if _, err := r.NewPhase().GetIdentity(context.Background(), bad); err == nil {
			t.Fatal("bad ID accepted")
		}
	}
}
func TestBoundIdentityReaderTransport(t *testing.T) {
	requests := 0
	original := &Client{BaseURL: "https://registry.invalid/prefix", Token: " synthetic-secret ", UserAgent: "synthetic-agent", HTTPClient: &http.Client{Transport: identityRoundTrip(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.URL.String() != "https://registry.invalid:443/prefix/identities/author" || req.Header.Get("Authorization") != "Bearer synthetic-secret" || req.Header.Get("User-Agent") != "synthetic-agent" {
			t.Fatal("binding drift")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(identityWire("author"))), Header: make(http.Header)}, nil
	})}}
	r, err := NewBoundIdentityReader(original, original.BaseURL, false)
	if err != nil {
		t.Fatal(err)
	}
	original.BaseURL = "https://foreign.invalid"
	original.Token = "changed"
	original.UserAgent = "changed"
	original.HTTPClient.Transport = identityRoundTrip(func(*http.Request) (*http.Response, error) { t.Fatal("mutated transport used"); return nil, nil })
	if _, err := r.NewPhase().GetIdentity(context.Background(), "author"); err != nil || requests != 1 {
		t.Fatal("snapshot unusable")
	}
	r.Close()
	if _, err := r.NewPhase().GetIdentity(context.Background(), "author"); err == nil {
		t.Fatal("closed reader used")
	}
	if err := r.client.CheckRedirect(&http.Request{}, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatal("redirect allowed")
	}
	for _, base := range []string{"https://registry.invalid/other", "http://remote.invalid/prefix", "https://user:pass@registry.invalid/prefix"} {
		if _, err := NewBoundIdentityReader(&Client{BaseURL: base}, "https://registry.invalid/prefix", false); err == nil {
			t.Fatal("bad base accepted")
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyFromEnvironment
	for _, https := range []bool{false, true} {
		base := "http://127.0.0.1/prefix"
		if https {
			base = "https://registry.invalid/prefix"
		}
		reader, err := NewBoundIdentityReader(&Client{BaseURL: base, HTTPClient: &http.Client{Transport: tr}}, base, !https)
		if err != nil {
			t.Fatal(err)
		}
		actual := reader.client.Transport.(*http.Transport)
		if (actual.Proxy != nil) != https {
			t.Fatal("proxy policy wrong")
		}
		if tr.Proxy == nil {
			t.Fatal("caller transport mutated")
		}
	}
}
