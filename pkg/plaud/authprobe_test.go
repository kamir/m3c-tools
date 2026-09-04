package plaud

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newAuthProbeServer returns an httptest server that accepts exactly one token
// value (returns status:0) and rejects everything else with Plaud's -3900
// "invalid auth header", mimicking the real API's HTTP-200-with-status-envelope.
func newAuthProbeServer(t *testing.T, goodToken string) (*Config, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "Bearer "+goodToken {
			fmt.Fprint(w, `{"status":0,"data_file_total":0,"data_file_list":[]}`)
			return
		}
		fmt.Fprint(w, `{"status":-3900,"msg":"invalid auth header"}`)
	}))
	return &Config{APIURL: srv.URL}, srv.Close
}

func TestTokenAuthenticates(t *testing.T) {
	const good = "eyJhbGciOiJIUzI1NiJ9.good.sig"
	cfg, closeSrv := newAuthProbeServer(t, good)
	defer closeSrv()

	if ok, err := NewClient(cfg, good).TokenAuthenticates(); err != nil || !ok {
		t.Errorf("good token: ok=%v err=%v, want ok=true err=nil", ok, err)
	}
	if ok, err := NewClient(cfg, "eyJhbGciOiJIUzI1NiJ9.wrong.sig").TokenAuthenticates(); err != nil || ok {
		t.Errorf("wrong token: ok=%v err=%v, want ok=false err=nil", ok, err)
	}
}

func TestTokenAuthenticates_Unreachable(t *testing.T) {
	// Port 1 refuses instantly: a transport error, distinct from "rejected".
	cfg := &Config{APIURL: "http://127.0.0.1:1"}
	ok, err := NewClient(cfg, "eyJhbGciOiJIUzI1NiJ9.x.sig").TokenAuthenticates()
	if err == nil {
		t.Fatalf("expected transport error, got ok=%v err=nil", ok)
	}
	if ok {
		t.Errorf("ok=true on transport error, want false")
	}
}

func TestSelectValidatedToken(t *testing.T) {
	const good = "eyJhbGciOiJIUzI1NiJ9.real-bearer.sig"
	cfg, closeSrv := newAuthProbeServer(t, good)
	defer closeSrv()

	t.Run("picks the token the API accepts", func(t *testing.T) {
		// Identity JWT first (the wrong one we used to grab), real bearer second.
		cands := []candidate{
			{Value: "eyJhbGciOiJIUzI1NiJ9.identity-email-id-name.sig", Src: "LS:jwt"},
			{Value: good, Src: "LS:name"},
		}
		tok, src, err := selectValidatedToken(cfg, cands)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tok != good {
			t.Errorf("selected %q, want the accepted bearer %q", tok, good)
		}
		if src != "LS:name" {
			t.Errorf("src = %q, want LS:name", src)
		}
	})

	t.Run("API reached but rejects all → actionable error, not unreachable", func(t *testing.T) {
		cands := []candidate{{Value: "eyJhbGciOiJIUzI1NiJ9.nope.sig", Src: "LS:jwt"}}
		_, _, err := selectValidatedToken(cfg, cands)
		if err == nil {
			t.Fatal("expected error when no candidate authenticates")
		}
		if errors.Is(err, errProbeUnreachable) {
			t.Errorf("should NOT be errProbeUnreachable when the API was reached: %v", err)
		}
	})

	t.Run("empty candidates → error", func(t *testing.T) {
		if _, _, err := selectValidatedToken(cfg, nil); err == nil {
			t.Error("expected error for empty candidate list")
		}
	})

	t.Run("unreachable API → errProbeUnreachable", func(t *testing.T) {
		down := &Config{APIURL: "http://127.0.0.1:1"}
		cands := []candidate{{Value: good, Src: "LS:jwt"}}
		_, _, err := selectValidatedToken(down, cands)
		if !errors.Is(err, errProbeUnreachable) {
			t.Errorf("err = %v, want errProbeUnreachable", err)
		}
	})
}
