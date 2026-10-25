package registry

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestManagedClientBoundary(t *testing.T) {
	for _, route := range []string{"lookup", "bundle", "metadata"} {
		for _, target := range []string{"foreign-port", "outside", "lookalike", "valid"} {
			t.Run(route+"/"+target, func(t *testing.T) {
				var foreign atomic.Int32
				decoy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { foreign.Add(1) }))
				defer decoy.Close()
				var escaped atomic.Int32
				var base string
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/outside" || strings.HasPrefix(r.URL.Path, "/api/skills-other") {
						escaped.Add(1)
					}
					if r.Header.Get("Authorization") != "Bearer synthetic-managed" {
						t.Error("frozen header missing")
					}
					if r.URL.Query().Get("done") != "1" {
						next := base + r.URL.Path + "?done=1"
						switch target {
						case "foreign-port":
							next = decoy.URL + r.URL.Path
						case "outside":
							next = base + "/outside"
						case "lookalike":
							next = base + "/api/skills-other/x"
						}
						http.Redirect(w, r, next, http.StatusTemporaryRedirect)
						return
					}
					switch route {
					case "lookup":
						_, _ = io.WriteString(w, `{"versions":[]}`)
					case "bundle":
						_, _ = io.WriteString(w, "synthetic-bundle")
					case "metadata":
						_, _ = io.WriteString(w, `{}`)
					}
				}))
				defer srv.Close()
				base = srv.URL
				managed, close, err := NewManagedClient(&Client{BaseURL: base + "/api/skills", Token: "synthetic-managed", HTTPClient: srv.Client()}, base+"/api/skills", true)
				if err != nil {
					t.Fatal(err)
				}
				defer close()
				switch route {
				case "lookup":
					_, err = managed.ResolveByName(context.Background(), "name")
				case "bundle":
					_, err = managed.GetBundle(context.Background(), "sha256:abc")
				case "metadata":
					_, err = managed.GetBundleMeta(context.Background(), "sha256:abc")
				}
				if target == "valid" {
					if err != nil {
						t.Fatalf("legitimate redirect refused: %v", err)
					}
				} else if err == nil {
					t.Fatal("authority escape accepted")
				}
				if foreign.Load() != 0 || escaped.Load() != 0 {
					t.Fatal("redirect reached unapproved authority")
				}
			})
		}
	}
}

func TestManagedClientSnapshotAndLifecycle(t *testing.T) {
	called := 0
	client := &Client{BaseURL: "https://registry.invalid/api/skills", Token: " synthetic-managed ", UserAgent: "test-agent", HTTPClient: &http.Client{Transport: identityRoundTrip(func(req *http.Request) (*http.Response, error) {
		called++
		if req.Header.Get("Authorization") != "Bearer synthetic-managed" || req.URL.Hostname() != "registry.invalid" {
			t.Error("client snapshot drift")
		}
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("synthetic-managed")), Header: make(http.Header)}, nil
	})}}
	managed, cleanup, err := NewManagedClient(client, client.BaseURL, false)
	if err != nil {
		t.Fatal(err)
	}
	client.BaseURL = "https://foreign.invalid"
	client.Token = "changed"
	client.HTTPClient.Transport = identityRoundTrip(func(*http.Request) (*http.Response, error) {
		t.Fatal("original mutable transport used")
		return nil, nil
	})
	_, err = managed.GetBundle(context.Background(), "sha256:abc")
	if !errors.Is(err, ErrNotFound) || strings.Contains(err.Error(), "synthetic-managed") || called != 1 {
		t.Fatalf("managed error/identity failed: %v", err)
	}
	cleanup()
	if _, err = managed.GetBundle(context.Background(), "sha256:abc"); err == nil || called != 1 {
		t.Fatal("closed transport used")
	}
	for _, fault := range []string{"malformed-location", "context", "decode", "close"} {
		t.Run(fault, func(t *testing.T) {
			c := &Client{BaseURL: "https://registry.invalid/api/skills", Token: "synthetic-managed", HTTPClient: &http.Client{Transport: identityRoundTrip(func(req *http.Request) (*http.Response, error) {
				switch fault {
				case "context":
					return nil, context.Canceled
				case "close":
					return &http.Response{StatusCode: 200, Body: managedFaultBody{Reader: strings.NewReader(`{"versions":[]}`)}, Header: make(http.Header)}, nil
				case "malformed-location":
					return &http.Response{StatusCode: 302, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{"Location": []string{"http://bad/%zz/synthetic-managed"}}}, nil
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"synthetic-managed":42,"versions":false}`)), Header: make(http.Header)}, nil
			})}}
			m, done, e := NewManagedClient(c, c.BaseURL, false)
			if e != nil {
				t.Fatal(e)
			}
			defer done()
			_, e = m.ResolveByName(context.Background(), "name")
			if e == nil || strings.Contains(e.Error(), "synthetic-managed") {
				t.Fatalf("managed error reflected server input: %v", e)
			}
			if fault == "context" && !errors.Is(e, context.Canceled) {
				t.Fatal("context identity lost")
			}
		})
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyFromEnvironment
	for _, https := range []bool{false, true} {
		base := "http://127.0.0.1/api/skills"
		if https {
			base = "https://registry.invalid/api/skills"
		}
		m, done, e := NewManagedClient(&Client{BaseURL: base, HTTPClient: &http.Client{Transport: tr}}, base, !https)
		if e != nil {
			t.Fatal(e)
		}
		actual := m.managed.owned
		if actual == nil || (actual.Proxy != nil) != https {
			t.Fatal("owned proxy policy wrong")
		}
		done()
		if tr.Proxy == nil {
			t.Fatal("caller transport mutated")
		}
	}
}

// A successful decode cannot hide a managed body-close failure.
type managedFaultBody struct{ io.Reader }

func (managedFaultBody) Close() error { return errors.New("synthetic-managed close failure") }
