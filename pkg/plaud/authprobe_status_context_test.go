package plaud

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTokenAuthenticates_RequiresExplicitStatus(t *testing.T) {
	for _, body := range []string{`{}`, `null`, `{"msg":"upstream unavailable"}`, `{"status":null}`, `{"status":"0"}`, `[]`, `<html>portal</html>`} {
		t.Run(body, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
			defer s.Close()
			ok, err := NewClient(&Config{APIURL: s.URL}, "synthetic-test-token").TokenAuthenticates()
			if ok || err == nil {
				t.Fatalf("body %q: accepted=%v err=%v; want unverified error", body, ok, err)
			}
		})
	}
	for _, tc := range []struct {
		body string
		want bool
	}{{`{"status":0}`, true}, {`{"status":-3900}`, false}} {
		t.Run(tc.body, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, tc.body) }))
			defer s.Close()
			ok, err := NewClient(&Config{APIURL: s.URL}, "synthetic-test-token").TokenAuthenticates()
			if err != nil || ok != tc.want {
				t.Fatalf("explicit status: accepted=%v err=%v", ok, err)
			}
		})
	}
}

type operationsRoundTrip func(*http.Request) (*http.Response, error)

func (f operationsRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestTokenAuthenticatesContext_DeadlineCoversRegionRedirect(t *testing.T) {
	calls := 0
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	c := NewClient(&Config{APIURL: "https://api.plaud.ai"}, "synthetic-test-token")
	c.httpClient.Transport = operationsRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		got, ok := r.Context().Deadline()
		if !ok || !got.Equal(deadline) {
			t.Errorf("request %d lost shared diagnostic deadline", calls)
		}
		if calls == 1 {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"status":-302,"data":{"domains":{"api":"https://eu.plaud.ai"}}}`)), Header: make(http.Header)}, nil
		}
		cancel()
		select {
		case <-r.Context().Done():
			return nil, r.Context().Err()
		case <-time.After(time.Second):
			return nil, errors.New("caller cancellation was lost")
		}
	})
	start := time.Now()
	ok, err := c.TokenAuthenticatesContext(ctx)
	if ok || !errors.Is(err, context.Canceled) || calls != 2 || time.Since(start) > time.Second {
		t.Fatalf("accepted=%v error=%v calls=%d elapsed=%s", ok, err, calls, time.Since(start))
	}
}
