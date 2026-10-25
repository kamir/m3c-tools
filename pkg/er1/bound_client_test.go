package er1

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

	"github.com/kamir/m3c-tools/pkg/httpsafe"
)

func TestBoundClientPreflightBeforeReaders(t *testing.T) {
	for _, tc := range []struct {
		name, base, bearer, key string
		verify                  bool
	}{
		{"no_pin", "https://a.example", "", "", true},
		{"http", "http://127.0.0.1", "http://127.0.0.1", "", true},
		{"userinfo", "https://bob@a.example", "https://a.example", "", true},
		{"query", "https://a.example?x=y", "https://a.example", "", true},
		{"fragment", "https://a.example#x", "https://a.example", "", true},
		{"foreign_bearer", "https://a.example", "https://b.example", "", true},
		{"foreign_key", "https://a.example", "", "https://b.example", true},
		{"mixed_foreign_key", "https://a.example", "https://a.example", "https://b.example", true},
		{"mixed_foreign_bearer", "https://a.example", "https://b.example", "https://a.example", true},
		{"pin_path", "https://a.example", "https://a.example/prefix", "", true},
		{"pin_space", "https://a.example", " ", "", true},
		{"unsafe_tls", "https://a.example", "https://a.example", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			sources := boundSources{readBearer: func(string) (string, error) { reads++; return "fixture-bearer", nil }, readAPIKey: func() (string, error) { reads++; return "fixture-api-key", nil }}
			c, err := newBoundClient(BoundOptions{BaseURL: tc.base, VerifySSL: tc.verify, BearerOrigin: tc.bearer, APIKeyOrigin: tc.key}, sources)
			if err == nil || c != nil || reads != 0 {
				t.Fatalf("preflight client=%v error=%v reads=%d", c != nil, err, reads)
			}
		})
	}
}

func TestBoundClientSelectedReaderFailsClosed(t *testing.T) {
	for _, family := range []string{"bearer", "api_key"} {
		for _, value := range []string{"", " ", " surrounding ", "line\rbreak", "line\nbreak", "nul\x00byte"} {
			t.Run(family+fmt.Sprintf("_%q", value), func(t *testing.T) {
				bearer, key := 0, 0
				o := BoundOptions{BaseURL: "https://a.example", VerifySSL: true}
				if family == "bearer" {
					o.BearerOrigin = o.BaseURL
				} else {
					o.APIKeyOrigin = o.BaseURL
				}
				_, err := newBoundClient(o, boundSources{readBearer: func(string) (string, error) { bearer++; return value, nil }, readAPIKey: func() (string, error) { key++; return value, nil }})
				if !errors.Is(err, errBoundCredential) || bearer+key != 1 {
					t.Fatalf("selected invalid error=%v reads=%d/%d", err, bearer, key)
				}
				if family == "bearer" && key != 0 || family == "api_key" && bearer != 0 {
					t.Fatal("read unselected family")
				}
			})
		}
	}
	t.Run("native_error_no_other_family", func(t *testing.T) {
		keys := 0
		_, err := newBoundClient(BoundOptions{BaseURL: "https://a.example", VerifySSL: true, BearerOrigin: "https://a.example", APIKeyOrigin: "https://a.example"}, boundSources{
			readBearer: func(string) (string, error) { return "", errors.New("sensitive-provider-diagnostic") }, readAPIKey: func() (string, error) { keys++; return "fixture-api-key", nil },
		})
		if err == nil || strings.Contains(err.Error(), "sensitive") || keys != 0 {
			t.Fatalf("unsafe fallback or error: %v keys=%d", err, keys)
		}
	})
}

func TestBoundClientGETUploadSnapshot(t *testing.T) {
	var gets, posts atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-bearer" || r.Header.Get("X-Context-ID") != "skills" {
			t.Error("captured bearer/context not sent")
		}
		switch r.Method {
		case http.MethodGet:
			gets.Add(1)
			if r.URL.Path != "/prefix/memory/skills" || r.URL.Query().Get("limit") != "2" || r.Header.Get("X-API-KEY") != "fixture-api-key" {
				t.Error("GET path/key mismatch")
			}
			_, _ = io.WriteString(w, `{"items":[]}`)
		case http.MethodPost:
			posts.Add(1)
			if r.URL.Path != "/prefix/upload_2" || r.Header.Get("X-API-KEY") != "" {
				t.Error("upload path or bearer preference mismatch")
			}
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Error(err)
			}
			if r.FormValue("context_id") != "skills" || r.FormValue("tags") != "session-fixture" {
				t.Error("multipart fields missing")
			}
			part, _, err := r.FormFile("transcript_file_ext")
			if err != nil {
				t.Error(err)
			} else {
				b, _ := io.ReadAll(part)
				_ = part.Close()
				if string(b) != "fixture-body" {
					t.Error("transcript changed")
				}
			}
			_, _ = io.WriteString(w, `{"doc_id":"fixture-document"}`)
		}
	}))
	defer srv.Close()
	t.Setenv("M3C_ER1_KEYCHAIN", "off")
	t.Setenv("ER1_DEVICE_TOKEN", "fixture-bearer")
	t.Setenv("ER1_API_KEY", "fixture-api-key")
	c, err := NewBoundClient(BoundOptions{BaseURL: srv.URL + "/prefix/", ContextID: "skills", BearerOrigin: srv.URL, APIKeyOrigin: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ER1_DEVICE_TOKEN", "mutated-bearer")
	t.Setenv("ER1_API_KEY", "mutated-api-key")
	if _, err = c.HTTPGetJSON(context.Background(), "/memory/skills?limit=2"); err != nil {
		t.Fatal(err)
	}
	out, err := c.Upload(context.Background(), &UploadPayload{TranscriptData: []byte("fixture-body"), TranscriptFilename: "fixture.txt", Tags: "session-fixture"})
	if err != nil || out.DocID != "fixture-document" {
		t.Fatalf("upload result=%v error=%v", out, err)
	}
	if gets.Load() != 1 || posts.Load() != 1 {
		t.Fatalf("requests=%d/%d", gets.Load(), posts.Load())
	}
}

func TestBoundClientAPIKeyOnlyAndReaderCounts(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-API-KEY") != "fixture-api-key" {
			t.Error("wrong selected auth")
		}
		_, _ = io.WriteString(w, `{"doc_id":"fixture-document"}`)
	}))
	defer srv.Close()
	bearer, keys := 0, 0
	c, err := newBoundClient(BoundOptions{BaseURL: srv.URL, APIKeyOrigin: srv.URL}, boundSources{readBearer: func(string) (string, error) { bearer++; t.Error("unselected reader"); return "", nil }, readAPIKey: func() (string, error) { keys++; return "fixture-api-key", nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ER1_DEVICE_TOKEN", "ambient-unselected-bearer")
	if _, err = c.HTTPGetJSON(context.Background(), "/memory/skills"); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Upload(context.Background(), &UploadPayload{}); err != nil {
		t.Fatal(err)
	}
	if keys != 1 || bearer != 0 || requests.Load() != 2 {
		t.Fatalf("read counts=%d/%d requests=%d", bearer, keys, requests.Load())
	}
}

func TestBoundClientInvalidPathNoRequests(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { count.Add(1) }))
	defer srv.Close()
	c, err := newBoundClient(BoundOptions{BaseURL: srv.URL, APIKeyOrigin: srv.URL}, boundSources{readAPIKey: func() (string, error) { return "fixture-api-key", nil }})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"https://foreign.example/a", "//foreign.example/a", "/x#fragment", "/../escape", "/%2e%2e/escape", "/x\\escape", "/x\n"} {
		if _, err := c.HTTPGetJSON(context.Background(), path); !errors.Is(err, errBoundPath) {
			t.Fatalf("path accepted: %q error=%v", path, err)
		}
	}
	if count.Load() != 0 {
		t.Fatal("invalid path sent request")
	}
}

func TestBoundClientRedirectPolicy(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, status := range []int{302, 303, 307, 308} {
			t.Run(fmt.Sprintf("%s_%d", method, status), func(t *testing.T) {
				var foreign atomic.Int32
				b := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					foreign.Add(1)
					body, _ := io.ReadAll(r.Body)
					if r.Header.Get("Authorization") != "" || r.Header.Get("X-API-KEY") != "" || r.Header.Get("X-Context-ID") != "" || len(body) != 0 || r.Method != http.MethodGet {
						t.Error("foreign credential/body replay")
					}
					_, _ = io.WriteString(w, `{"doc_id":"redirected-document"}`)
				}))
				defer b.Close()
				a := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Authorization") != "Bearer fixture-bearer" {
						t.Error("initial request missing captured bearer")
					}
					http.Redirect(w, r, b.URL+"/capture", status)
				}))
				defer a.Close()
				c, err := newBoundClient(BoundOptions{BaseURL: a.URL, ContextID: "skills", BearerOrigin: a.URL, APIKeyOrigin: a.URL}, boundSources{readBearer: func(string) (string, error) { return "fixture-bearer", nil }, readAPIKey: func() (string, error) { return "fixture-api-key", nil }})
				if err != nil {
					t.Fatal(err)
				}
				if method == http.MethodGet {
					_, err = c.HTTPGetJSON(context.Background(), "/memory/skills")
				} else {
					_, err = c.Upload(context.Background(), &UploadPayload{TranscriptData: []byte("private-fixture-body")})
				}
				if method == http.MethodPost && (status == 307 || status == 308) {
					if err == nil || foreign.Load() != 0 {
						t.Fatalf("body redirect not denied err=%v foreign=%d", err, foreign.Load())
					}
				} else if err != nil || foreign.Load() != 1 {
					t.Fatalf("sanitized redirect err=%v foreign=%d", err, foreign.Load())
				}
			})
		}
	}
}

func TestBoundClientSafeResponseErrors(t *testing.T) {
	for _, upload := range []bool{false, true} {
		for _, kind := range []string{"status", "invalid_json", "reflect_bearer", "reflect_key", "malformed_redirect"} {
			t.Run(fmt.Sprintf("%t_%s", upload, kind), func(t *testing.T) {
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch kind {
					case "status":
						w.WriteHeader(500)
						_, _ = io.WriteString(w, "fixture-bearer fixture-api-key")
					case "invalid_json":
						_, _ = io.WriteString(w, `{bad`)
					case "reflect_bearer":
						_, _ = io.WriteString(w, `{"doc_id":"fixture-bearer"}`)
					case "reflect_key":
						_, _ = io.WriteString(w, `{"doc_id":"fixture-api-key"}`)
					case "malformed_redirect":
						w.Header().Set("Location", "https://example.invalid/fixture-bearer%zz")
						w.WriteHeader(302)
					}
				}))
				defer srv.Close()
				c, err := newBoundClient(BoundOptions{BaseURL: srv.URL, BearerOrigin: srv.URL, APIKeyOrigin: srv.URL}, boundSources{readBearer: func(string) (string, error) { return "fixture-bearer", nil }, readAPIKey: func() (string, error) { return "fixture-api-key", nil }})
				if err != nil {
					t.Fatal(err)
				}
				if upload {
					_, err = c.Upload(context.Background(), &UploadPayload{})
				} else {
					_, err = c.HTTPGetJSON(context.Background(), "/memory/skills")
				}
				if err == nil || strings.Contains(err.Error(), "fixture-") || strings.Contains(err.Error(), srv.URL) {
					t.Fatalf("unsafe response error: %v", err)
				}
			})
		}
	}
}

func TestBoundClientContextCancellation(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { count.Add(1) }))
	defer srv.Close()
	c, err := newBoundClient(BoundOptions{BaseURL: srv.URL, APIKeyOrigin: srv.URL}, boundSources{readAPIKey: func() (string, error) { return "fixture-api-key", nil }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = c.HTTPGetJSON(ctx, "/memory/skills"); !errors.Is(err, context.Canceled) {
		t.Fatalf("GET cancel: %v", err)
	}
	if _, err = c.Upload(ctx, &UploadPayload{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("upload cancel: %v", err)
	}
	if count.Load() != 0 {
		t.Fatal("canceled request sent")
	}
}

func TestBoundClientProductionInvalidSelectedValueNoNativeFallback(t *testing.T) {
	t.Setenv("M3C_ER1_KEYCHAIN", "off")
	for _, tc := range []struct{ name, value string }{{"blank", " "}, {"control", "fixture\rvalue"}, {"empty", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ER1_API_KEY", tc.value)
			_, err := NewBoundClient(BoundOptions{BaseURL: "https://a.example", VerifySSL: true, APIKeyOrigin: "https://a.example"})
			if !errors.Is(err, errBoundCredential) {
				t.Fatalf("selected source unexpectedly accepted: %v", err)
			}
		})
	}
	// Invalid pins must reject before even the selected synthetic env value.
	t.Setenv("ER1_DEVICE_TOKEN", "fixture-bearer")
	_, err := NewBoundClient(BoundOptions{BaseURL: "https://a.example", VerifySSL: true, BearerOrigin: "https://b.example"})
	if !errors.Is(err, httpsafe.ErrCredentialBinding) {
		t.Fatal(err)
	}
}

func TestBoundClientDecodedJSONReflection(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		deny       bool
	}{
		{"value", `{"items":[{"tags":"fixture\u002dbearer"}]}`, true},
		{"key", `{"nested":{"fixture\u002dapi-key":true}}`, true},
		{"doc_id", `{"doc_id":"fixture\u002dbearer"}`, true},
		{"message", `{"message":"prefix fixture-api\u002dkey suffix"}`, true},
		{"array", `{"extension":[["fixture\u002dbearer"]]}`, true},
		{"ordinary_escaped", `{"doc_id":"ordinary\u002ddocument","message":"escaped \"text\"","items":[{"tags":"ordinary\u002dtags"}]}`, false},
	} {
		for _, upload := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s_upload_%t", tc.name, upload), func(t *testing.T) {
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, tc.body) }))
				defer srv.Close()
				c, err := newBoundClient(BoundOptions{BaseURL: srv.URL, BearerOrigin: srv.URL, APIKeyOrigin: srv.URL}, boundSources{readBearer: func(string) (string, error) { return "fixture-bearer", nil }, readAPIKey: func() (string, error) { return "fixture-api-key", nil }})
				if err != nil {
					t.Fatal(err)
				}
				if upload {
					out, uploadErr := c.Upload(context.Background(), &UploadPayload{})
					err = uploadErr
					if !tc.deny && (out == nil || out.DocID != "ordinary-document" || out.Message != `escaped "text"`) {
						t.Fatalf("ordinary escaped upload changed: %+v", out)
					}
				} else {
					out, getErr := c.HTTPGetJSON(context.Background(), "/memory/skills")
					err = getErr
					if !tc.deny {
						object, ok := out.(map[string]any)
						if !ok || object["doc_id"] != "ordinary-document" {
							t.Fatalf("ordinary escaped GET changed: %v", out)
						}
					}
				}
				if tc.deny && !errors.Is(err, errBoundResponse) {
					t.Fatalf("decoded reflection not refused: %v", err)
				}
				if !tc.deny && err != nil {
					t.Fatalf("ordinary escaped JSON refused: %v", err)
				}
				if err != nil && (strings.Contains(err.Error(), "fixture-") || strings.Contains(err.Error(), srv.URL)) {
					t.Fatalf("unsafe error: %v", err)
				}
			})
		}
	}
}
