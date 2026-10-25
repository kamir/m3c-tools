package session

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func boundSessionHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_ER1_KEYCHAIN", "off")
	t.Setenv("M3C_TEST_KEYCHAIN", "0")
	t.Setenv("ER1_DEVICE_TOKEN_ORIGIN", "")
	t.Setenv("ER1_API_KEY_ORIGIN", "")
	t.Setenv("ER1_DEVICE_TOKEN", "")
	t.Setenv("ER1_API_KEY", "")
	t.Setenv("M3C_DEVICES_DIR", filepath.Join(home, "devices"))
	return home
}

func writeSessionDescriptor(t *testing.T, dir, target, ctx string) {
	t.Helper()
	p := filepath.Join(dir, ".m3c")
	if err := os.MkdirAll(p, 0700); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("schema: m3c.project-descriptor/v2\ner1:\n  target: %q\n  context: %q\n", target, ctx)
	if err := os.WriteFile(filepath.Join(p, "project.yaml"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestBoundSessionOpenUsesOneCredentialAndContextSnapshot(t *testing.T) {
	for _, tc := range []struct{ name, descriptor, override, want string }{
		{"override", "DescriptorCtx", "ExplicitCtx", "ExplicitCtx"},
		{"descriptor", "DescriptorCtx", "", "DescriptorCtx"},
		{"default", "", "", "main"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := boundSessionHome(t)
			t.Setenv("ER1_CONTEXT_ID", "ForeignEnvContext")
			t.Setenv("ER1_DEVICE_TOKEN", "synthetic-original-bearer")
			t.Setenv("ER1_API_KEY", "synthetic-original-key")
			gotRead := make(chan struct{}, 1)
			release := make(chan struct{})
			var uploads atomic.Int32
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/TenantA/memory/"+tc.want+"/search" {
					if r.Header.Get("Authorization") != "Bearer synthetic-original-bearer" || r.Header.Get("X-API-KEY") != "synthetic-original-key" || r.Header.Get("X-Context-ID") != tc.want {
						t.Error("GET credential/context snapshot mismatch")
					}
					gotRead <- struct{}{}
					<-release
					fmt.Fprint(w, `{"items":[]}`)
					return
				}
				if r.URL.Path == "/TenantA/upload_2" {
					uploads.Add(1)
					if r.Header.Get("Authorization") != "Bearer synthetic-original-bearer" || r.Header.Get("X-API-KEY") != "" {
						t.Error("upload did not retain selected Bearer preference")
					}
					if err := r.ParseMultipartForm(1 << 20); err != nil {
						t.Error(err)
						return
					}
					if r.MultipartForm != nil {
						defer r.MultipartForm.RemoveAll()
					}
					if r.FormValue("context_id") != tc.want || r.Header.Get("X-Context-ID") != tc.want {
						t.Error("upload context differs from resolved session context")
					}
					fmt.Fprint(w, `{"doc_id":"bound-doc"}`)
					return
				}
				t.Errorf("unexpected request path %q", r.URL.Path)
				http.NotFound(w, r)
			}))
			defer srv.Close()
			t.Setenv("ER1_DEVICE_TOKEN_ORIGIN", srv.URL)
			t.Setenv("ER1_API_KEY_ORIGIN", srv.URL)
			writeSessionDescriptor(t, home, srv.URL+"/TenantA", tc.descriptor)
			type result struct {
				value *OpenResult
				err   error
			}
			done := make(chan result, 1)
			go func() {
				value, err := Open(OpenOpts{WorkingDir: home, SessionID: "bound-session", ER1Context: tc.override})
				done <- result{value, err}
			}()
			select {
			case <-gotRead:
			case r := <-done:
				t.Fatalf("operation stopped before GET: %v", r.err)
			case <-time.After(10 * time.Second):
				close(release)
				t.Fatal("GET did not arrive")
			}
			t.Setenv("ER1_DEVICE_TOKEN", "synthetic-mutated-bearer")
			t.Setenv("ER1_API_KEY", "synthetic-mutated-key")
			t.Setenv("ER1_DEVICE_TOKEN_ORIGIN", "https://foreign.example")
			t.Setenv("ER1_API_KEY_ORIGIN", "https://foreign.example")
			close(release)
			select {
			case r := <-done:
				if r.err != nil || r.value.DocID != "bound-doc" || uploads.Load() != 1 {
					t.Fatalf("open=%v uploads=%d", r.err, uploads.Load())
				}
			case <-time.After(10 * time.Second):
				t.Fatal("open did not finish")
			}
		})
	}
}

func TestBoundSessionLookupFailureNeverUploads(t *testing.T) {
	for _, mode := range []string{"forbidden", "invalid-json", "disconnect", "null", "error-object", "scalar-row", "invalid-wrapper", "missing-id"} {
		t.Run(mode, func(t *testing.T) {
			home := boundSessionHome(t)
			var uploads atomic.Int32
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					uploads.Add(1)
					fmt.Fprint(w, `{"doc_id":"unexpected"}`)
					return
				}
				switch mode {
				case "null":
					fmt.Fprint(w, "null")
				case "error-object":
					fmt.Fprint(w, `{"error":"synthetic lookup failed"}`)
				case "scalar-row":
					fmt.Fprint(w, `[7]`)
				case "invalid-wrapper":
					fmt.Fprint(w, `{"items":null}`)
				case "missing-id":
					fmt.Fprint(w, `{"items":[{}]}`)
				case "forbidden":
					w.WriteHeader(403)
					fmt.Fprint(w, "synthetic-error-key")
				case "invalid-json":
					fmt.Fprint(w, "invalid synthetic-error-key")
				case "disconnect":
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					if err := conn.Close(); err != nil {
						t.Error(err)
					}
				}
			}))
			defer srv.Close()
			t.Setenv("ER1_API_KEY", "synthetic-error-key")
			t.Setenv("ER1_API_KEY_ORIGIN", srv.URL)
			for _, op := range []string{"open", "checkpoint"} {
				var err error
				if op == "open" {
					_, err = Open(OpenOpts{WorkingDir: home, SessionID: "failure-session", ER1Target: srv.URL})
				} else {
					_, err = Checkpoint(CheckpointOpts{WorkingDir: home, SessionID: "failure-session", ER1Target: srv.URL, Note: "note"})
				}
				if err == nil || strings.Contains(err.Error(), "synthetic-error-key") {
					t.Fatalf("%s error=%v", op, err)
				}
			}
			if uploads.Load() != 0 {
				t.Fatal("lookup failure permitted a write")
			}
		})
	}
}

func TestBoundSessionTargetOverrideCannotBorrowCredentialPin(t *testing.T) {
	home := boundSessionHome(t)
	var calls atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, `{"items":[]}`) })
	a := httptest.NewTLSServer(handler)
	defer a.Close()
	b := httptest.NewTLSServer(handler)
	defer b.Close()
	t.Setenv("ER1_DEVICE_TOKEN", "synthetic-assigned-to-a")
	t.Setenv("ER1_DEVICE_TOKEN_ORIGIN", a.URL)
	writeSessionDescriptor(t, home, b.URL, "main")
	if _, err := List(ListOpts{WorkingDir: home}); err == nil {
		t.Fatal("foreign descriptor target accepted")
	}
	writeSessionDescriptor(t, home, a.URL, "main")
	if _, err := List(ListOpts{WorkingDir: home, ER1Target: b.URL}); err == nil {
		t.Fatal("foreign override target accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("foreign target received a request")
	}
}

func TestSessionSearchAcceptsOnlyConfirmedShapes(t *testing.T) {
	for _, value := range []any{[]any{}, map[string]any{"items": []any{}}, map[string]any{"results": []any{}}, map[string]any{"memories": []any{}}, map[string]any{"docs": []any{}}, []any{map[string]any{"doc_id": "item-1"}}, map[string]any{"id": "item-1"}} {
		if _, err := coerceItems(value); err != nil {
			t.Fatalf("valid shape rejected: %v", err)
		}
	}
	for _, value := range []any{nil, map[string]any{"items": []any{}, "results": []any{}}, []any{map[string]any{"doc_id": "   "}}} {
		if _, err := coerceItems(value); err == nil {
			t.Fatal("unconfirmed response accepted")
		}
	}
}

func TestBoundSessionUploadRequiresDocumentID(t *testing.T) {
	for _, body := range []string{"null", `{}`, `{"doc_id":"   "}`, `{"doc_id":"\u001bunsafe"}`} {
		t.Run(body, func(t *testing.T) {
			home := boundSessionHome(t)
			var writes atomic.Int32
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					fmt.Fprint(w, `{"items":[{"doc_id":"existing-parent"}]}`)
					return
				}
				writes.Add(1)
				fmt.Fprint(w, body)
			}))
			defer srv.Close()
			t.Setenv("ER1_API_KEY", "synthetic-ack-key")
			t.Setenv("ER1_API_KEY_ORIGIN", srv.URL)
			// Checkpoint necessarily writes after finding the existing parent. A missing
			// acknowledgement is an error even though the server already received POST.
			result, err := Checkpoint(CheckpointOpts{WorkingDir: home, SessionID: "ack-session", ER1Target: srv.URL, Note: "checkpoint"})
			if err == nil || result != nil || writes.Load() != 1 {
				t.Fatalf("result=%v err=%v writes=%d", result, err, writes.Load())
			}
		})
	}
}
