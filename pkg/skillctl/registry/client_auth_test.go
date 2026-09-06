package registry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The header is sent when a token is set, and NOT sent when it is not. The
// second half matters as much as the first: a public instance must keep seeing
// an anonymous request, and an empty Bearer would be a lie about the caller.
func TestClientSendsBearerOnlyWhenTokenIsSet(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token string
		want  string
	}{
		{"with a token", "s3cr3t", "Bearer s3cr3t"},
		{"without one", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			var seen bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Get("Authorization")
				seen = true
				w.WriteHeader(http.StatusNotFound)
			}))
			defer srv.Close()

			c := New(srv.URL, srv.Client())
			c.Token = tc.token
			_, _ = c.ResolveByName(context.Background(), "demo")

			if !seen {
				t.Fatal("the server was never called; the test proves nothing")
			}
			if got != tc.want {
				t.Errorf("Authorization = %q, want %q", got, tc.want)
			}
		})
	}
}

// A 401 and a 403 must be distinguishable from every other refusal, because the
// operator's next action is different: provision or fix a credential, rather
// than look for the bundle.
func TestUnauthorizedIsItsOwnError(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		_, err := New(srv.URL, srv.Client()).ResolveByName(context.Background(), "demo")
		srv.Close()
		if !errors.Is(err, ErrUnauthorized) {
			t.Errorf("HTTP %d: err = %v, want ErrUnauthorized", code, err)
		}
	}
}

// A 500 must NOT be reported as an authorization problem. Without this the
// mapping above could swallow every failure and send an operator hunting for a
// token that was never the issue.
func TestServerErrorIsNotUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	_, err := New(srv.URL, srv.Client()).ResolveByName(context.Background(), "demo")
	if err == nil {
		t.Fatal("a 500 must be an error")
	}
	if errors.Is(err, ErrUnauthorized) {
		t.Errorf("a 500 was reported as ErrUnauthorized: %v", err)
	}
}
