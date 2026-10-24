package outbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/httpsafe"
)

type diagnosticTransport func(*http.Request) (*http.Response, error)

func (f diagnosticTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type diagnosticBody struct{ err error }

func (b diagnosticBody) Read([]byte) (int, error) { return 0, b.err }
func (diagnosticBody) Close() error               { return nil }

func TestIngestMalformedRedirectDoesNotReflectBearer(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer synthetic-ingest-key" {
			t.Error("selected bearer not sent to bound fixture")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || !strings.Contains(string(body), "synthetic evidence") {
			t.Error("initial evidence missing")
		}
		w.Header().Set("Location", "https://example.invalid/synthetic-ingest-key%zz")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = httpsafe.NoCredentialRedirect
	c := IngestClient{Endpoint: server.URL, Token: "synthetic-ingest-key", Client: client}
	response, status, err := c.PostBatch(context.Background(), [][]byte{[]byte(`{"data":"synthetic evidence"}`)})
	if calls.Load() != 1 || response != nil || status != 0 || err == nil || err.Error() != "outbox: ingest I/O failed" || strings.Contains(err.Error(), "synthetic-ingest-key") {
		t.Fatalf("unsafe or missing diagnostic status=%d error=%v", status, err)
	}
}

func TestIngestIOErrorsRedactRemoteTextAndKeepContextSentinels(t *testing.T) {
	for _, phase := range []string{"transport", "read"} {
		for _, sentinel := range []error{nil, context.Canceled, context.DeadlineExceeded} {
			name := phase
			if sentinel != nil {
				name += "/" + sentinel.Error()
			}
			t.Run(name, func(t *testing.T) {
				raw := errors.New("remote synthetic-ingest-key and https://example.invalid/private")
				if sentinel != nil {
					raw = fmt.Errorf("remote synthetic-ingest-key: %w", sentinel)
				}
				calls := 0
				c := IngestClient{Endpoint: "https://fixture.example", Token: "synthetic-ingest-key", Client: &http.Client{Transport: diagnosticTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					if phase == "transport" {
						return nil, raw
					}
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: diagnosticBody{raw}}, nil
				})}}
				response, status, err := c.PostBatch(context.Background(), [][]byte{[]byte(`{}`)})
				expected := 0
				if phase == "read" {
					expected = http.StatusOK
				}
				if calls != 1 || response != nil || status != expected || err == nil || strings.Contains(err.Error(), "synthetic-ingest-key") || strings.Contains(err.Error(), "https://") {
					t.Fatalf("unsafe/missing I/O error status=%d error=%v", status, err)
				}
				if sentinel != nil && !errors.Is(err, sentinel) {
					t.Fatal("trusted context sentinel lost")
				}
				if errors.Is(err, raw) {
					t.Fatal("untrusted underlying error retained")
				}
			})
		}
	}
}

func TestIngestCanceledRequestPreservesContextIdentity(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprint(deadline), func(t *testing.T) {
			var ctx context.Context
			var cancel context.CancelFunc
			expected := context.Canceled
			if deadline {
				ctx, cancel = context.WithDeadline(context.Background(), time.Unix(1, 0))
				expected = context.DeadlineExceeded
			} else {
				ctx, cancel = context.WithCancel(context.Background())
				cancel()
			}
			defer cancel()
			c := IngestClient{Endpoint: server.URL, Client: server.Client()}
			response, status, err := c.PostBatch(ctx, [][]byte{[]byte(`{}`)})
			if calls.Load() != 0 || response != nil || status != 0 || !errors.Is(err, expected) {
				t.Fatalf("context identity changed: %v", err)
			}
		})
	}
}
