package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/outbox"
)

func TestSyncConnectionPreReadBoundary(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		pin  string
		want int
	}{
		{"help", []string{"--help"}, "", 0},
		{"missing mode", nil, "", 2},
		{"missing flag value", []string{"--once", "--endpoint"}, "", 2},
		{"zero daemon interval", []string{"--daemon", "--interval", "0s", "--backend", "er1", "--endpoint", "https://a.example"}, "https://a.example", 2},
		{"negative daemon interval", []string{"--daemon", "--interval", "-1s", "--backend", "er1", "--endpoint", "https://a.example"}, "https://a.example", 2}, {"unknown flag", []string{"--unknown"}, "", 2},
		{"positional", []string{"--once", "unexpected"}, "", 2}, {"both modes", []string{"--once", "--daemon"}, "", 2},
		{"default off", []string{"--once"}, "", 0},
		{"endpoint only", []string{"--once", "--endpoint", "https://a.example"}, "", 40},
		{"backend only", []string{"--once", "--backend", "er1"}, "", 40},
		{"unknown backend", []string{"--once", "--backend", "git", "--endpoint", "https://a.example"}, "", 40},
		{"userinfo", []string{"--once", "--backend", "er1", "--endpoint", "https://synthetic:secret@a.example"}, "https://a.example", 1},
		{"query", []string{"--once", "--backend", "er1", "--endpoint", "https://a.example?secret"}, "https://a.example", 1},
		{"fragment", []string{"--once", "--backend", "er1", "--endpoint", "https://a.example#secret"}, "https://a.example", 1},
		{"HTTP loopback refused", []string{"--once", "--backend", "er1", "--endpoint", "http://127.0.0.1", "--insecure"}, "http://127.0.0.1", 1},
		{"insecure remote", []string{"--once", "--backend", "er1", "--endpoint", "https://a.example", "--insecure"}, "https://a.example", 1},
		{"missing pin", []string{"--once", "--backend", "er1", "--endpoint", "https://a.example"}, "", 1},
		{"foreign pin", []string{"--once", "--backend", "er1", "--endpoint", "https://a.example"}, "https://b.example", 1},
		{"path pin", []string{"--once", "--backend", "er1", "--endpoint", "https://a.example"}, "https://a.example/path", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			reads := 0
			getenv := func(name string) string {
				if name == "ER1_DEVICE_TOKEN" {
					reads++
					t.Fatal("secret environment read before validation")
				}
				if name == "ER1_DEVICE_TOKEN_ORIGIN" {
					return tc.pin
				}
				return ""
			}
			var out, errb bytes.Buffer
			code := runSyncWithReaders(tc.args, &out, &errb, getenv, func() ([]byte, error) { reads++; t.Fatal("store read before validation"); return nil, nil })
			if code != tc.want || reads != 0 {
				t.Fatalf("exit=%d want=%d reads=%d stderr=%s", code, tc.want, reads, errb.String())
			}
			files, err := os.ReadDir(home)
			if err != nil || len(files) != 0 {
				t.Fatal("pre-read refusal created local state")
			}
		})
	}
}

func TestSyncCredentialSelectionSnapshot(t *testing.T) {
	for _, source := range []string{"environment", "stored"} {
		t.Run(source, func(t *testing.T) {
			env := map[string]string{"ER1_DEVICE_TOKEN_ORIGIN": "https://a.example"}
			if source == "environment" {
				env["ER1_DEVICE_TOKEN"] = " synthetic-selected "
			}
			reads := 0
			selected := syncBearerSource(func(k string) string { return env[k] }, func() ([]byte, error) { reads++; return []byte("synthetic-selected"), nil })
			c, err := buildIngestClient("https://A.example:00443/prefix/", "", "synthetic", false, io.Discard, selected)
			if err != nil {
				t.Fatal(err)
			}
			env["ER1_DEVICE_TOKEN"] = "synthetic-other"
			env["ER1_DEVICE_TOKEN_ORIGIN"] = "https://b.example"
			if c.Endpoint != "https://a.example:443/prefix/" || c.Token != "synthetic-selected" {
				t.Fatal("connection snapshot changed")
			}
			if (reads == 1) != (source == "stored") {
				t.Fatalf("stored reads=%d", reads)
			}
			calls := 0
			c.Client.Transport = syncRoundTrip(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.Host != "a.example:443" || !strings.HasPrefix(req.URL.Path, "/prefix/") || req.Header.Get("Authorization") != "Bearer synthetic-selected" {
					t.Error("captured invocation values changed")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"acks":[]}`))}, nil
			})
			if _, _, err := c.PostBatch(context.Background(), [][]byte{[]byte(`{"synthetic":true}`)}); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatal("captured client did not issue request")
			}
		})
	}
	for _, value := range []string{" \t", "synthetic\r\nheader"} {
		reads := 0
		s := syncBearerSource(func(k string) string {
			if k == "ER1_DEVICE_TOKEN_ORIGIN" {
				return "https://a.example"
			}
			if k == "ER1_DEVICE_TOKEN" {
				return value
			}
			return ""
		}, func() ([]byte, error) { reads++; return []byte("fallback"), nil })
		if _, err := buildIngestClient("https://a.example", "", "log", false, io.Discard, s); err == nil || reads != 0 {
			t.Fatal("invalid selected environment fell back")
		}
	}
}

func TestSyncBoundCLIEntryPoint(t *testing.T) {
	if networkCommands["sync"] {
		t.Fatal("sync still eagerly autoloads native token")
	}
	binary := skillctlBin(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("ER1_DEVICE_TOKEN", "synthetic-sync-key")
	t.Setenv("ER1_DEVICE_TOKEN_ORIGIN", "")
	t.Setenv("M3C_INGEST_ENDPOINT", "")
	t.Setenv("SKILLCTL_AUDIT_BACKEND", "")
	var gotA, gotB atomic.Int32
	var malformed atomic.Bool
	a := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotA.Add(1)
		if r.Header.Get("Authorization") != "Bearer synthetic-sync-key" {
			t.Error("wrong bearer")
		}
		body, _ := io.ReadAll(r.Body)
		if !bytes.Contains(body, []byte("inv:sync:process")) {
			t.Error("signed inventory missing")
		}
		if malformed.Load() {
			w.Header().Set("Location", "https://example.invalid/synthetic-sync-key%zz")
			w.WriteHeader(http.StatusFound)
			return
		}
		http.Error(w, "reflected synthetic-sync-key", http.StatusUnauthorized)
	}))
	defer a.Close()
	b := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { gotB.Add(1); t.Error("foreign endpoint received data") }))
	defer b.Close()
	run := func(args ...string) int {
		t.Helper()
		cmd := exec.Command(binary, append([]string{"sync"}, args...)...)
		output, err := cmd.CombinedOutput()
		if cmd.ProcessState == nil {
			t.Fatal(err)
		}
		if bytes.Contains(output, []byte("synthetic-sync-key")) {
			t.Fatal("credential reflected")
		}
		return cmd.ProcessState.ExitCode()
	}
	for _, args := range [][]string{{"--help"}, {"--once"}} {
		if rc := run(args...); rc != 0 {
			t.Fatalf("exit=%d", rc)
		}
	}
	if rc := run("--unknown"); rc != 2 {
		t.Fatalf("usage exit=%d", rc)
	}
	if rc := run("--once", "--backend", "er1", "--endpoint", b.URL, "--insecure"); rc != 1 {
		t.Fatalf("missing pin exit=%d", rc)
	}
	t.Setenv("ER1_DEVICE_TOKEN_ORIGIN", a.URL)
	if rc := run("--once", "--backend", "er1", "--endpoint", b.URL, "--insecure"); rc != 1 {
		t.Fatalf("foreign pin exit=%d", rc)
	}
	if gotA.Load() != 0 || gotB.Load() != 0 {
		t.Fatal("pre-read refusal sent request")
	}
	store, err := outbox.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	appendSignedRow(t, store, syncTestDeviceKey(t), "synthetic", "inv:sync:process", "2026-10-24T00:00:00Z")
	store.Close()
	if rc := run("--once", "--backend", "er1", "--endpoint", a.URL, "--insecure"); rc != 29 {
		t.Fatalf("HTTP401 exit=%d", rc)
	}
	if gotA.Load() != 1 || gotB.Load() != 0 {
		t.Fatal("request routing mismatch")
	}
	malformed.Store(true)
	if rc := run("--once", "--backend", "er1", "--endpoint", a.URL, "--insecure"); rc != syncExitOK {
		t.Fatalf("transient reflected redirect exit=%d", rc)
	}
	if gotA.Load() != 2 || gotB.Load() != 0 {
		t.Fatal("malformed redirect caused unexpected requests")
	}
	check, err := outbox.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	pending, err := check.PendingCount()
	if err != nil || pending != 1 {
		t.Fatal("unacknowledged evidence lost pending state")
	}
	attempts, err := check.Attempts("inv:sync:process")
	if err != nil || len(attempts) != 1 || attempts[0].Error != "outbox: ingest I/O failed" || strings.Contains(attempts[0].Error, "synthetic-sync-key") {
		t.Fatal("unsafe or missing persisted transient diagnostic")
	}
}

func TestSyncActualTLSRedirectPolicy(t *testing.T) {
	for _, code := range []int{302, 303, 307, 308} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var received atomic.Int32
			var sent atomic.Int32
			var unsafe atomic.Bool
			b := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received.Add(1)
				body, _ := io.ReadAll(r.Body)
				if r.Header.Get("Authorization") != "" || len(body) != 0 {
					unsafe.Store(true)
				}
				json.NewEncoder(w).Encode(outbox.IngestResponse{})
			}))
			defer b.Close()
			a := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sent.Add(1)
				body, _ := io.ReadAll(r.Body)
				if !bytes.Contains(body, []byte("private evidence")) {
					t.Error("initial evidence body missing")
				}
				if r.Header.Get("Authorization") != "Bearer synthetic-sync-key" {
					t.Error("missing initial bearer")
				}
				http.Redirect(w, r, b.URL+"/sink", code)
			}))
			defer a.Close()
			c, err := buildIngestClient(a.URL, "", "synthetic", true, io.Discard, syncTestCredential(a.URL))
			if err != nil {
				t.Fatal(err)
			}
			response, status, postErr := c.PostBatch(context.Background(), [][]byte{[]byte(`{"synthetic":"private evidence"}`)})
			if sent.Load() != 1 {
				t.Fatal("initial signed-evidence request was not executed exactly once")
			}
			if code < 307 && (received.Load() != 1 || postErr != nil || status != 200 || response == nil) {
				t.Fatal("sanitized redirect control did not complete")
			}
			if code >= 307 && (postErr == nil || status != 0 || response != nil) {
				t.Fatal("body-preserving redirect was not refused")
			}
			if unsafe.Load() {
				t.Fatal("redirect leaked bearer or evidence body")
			}
			if code >= 307 && received.Load() != 0 {
				t.Fatal("body-preserving redirect reached foreign origin")
			}
		})
	}
}

type syncRoundTrip func(*http.Request) (*http.Response, error)

func (fn syncRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func TestSyncSameOriginRedirectPreservesExistingPolicy(t *testing.T) {
	var calls atomic.Int32
	var origin string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer synthetic-sync-key" {
			t.Error("same-origin request lost captured bearer")
		}
		body, _ := io.ReadAll(r.Body)
		if !bytes.Contains(body, []byte("synthetic evidence")) {
			t.Error("same-origin307 lost body")
		}
		if r.URL.Path != "/sink" {
			http.Redirect(w, r, origin+"/sink", http.StatusTemporaryRedirect)
			return
		}
		json.NewEncoder(w).Encode(outbox.IngestResponse{})
	}))
	defer server.Close()
	origin = server.URL
	c, err := buildIngestClient(origin, "", "synthetic", true, io.Discard, syncTestCredential(origin))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ER1_DEVICE_TOKEN", "synthetic-other")
	t.Setenv("ER1_DEVICE_TOKEN_ORIGIN", "https://foreign.example")
	if _, _, err = c.PostBatch(context.Background(), [][]byte{[]byte(`{"data":"synthetic evidence"}`)}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("same-origin policy changed")
	}
}
