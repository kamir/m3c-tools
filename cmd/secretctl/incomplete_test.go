package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"gopkg.in/yaml.v3"
)

const syntheticSecret = "synthetic-secret-for-incomplete-check"

func incompleteTestRegistry(t *testing.T, holders []Holder, probeURL string) string {
	t.Helper()
	entry := Entry{Name: "demo", Source: Source{Kind: "gcp-secret-manager", Project: "test", Secret: "demo"}, Roles: []Role{{ID: "service-auth", Was: "synthetic authentication", BeiRotation: "synthetic test"}}, Holders: holders}
	if probeURL != "" {
		entry.Probe = Probe{Kind: "http", URL: probeURL, Header: "X-API-KEY", ExpectOK: 200, ExpectRevoked: 401}
	}
	content, err := yaml.Marshal(Registry{Schema: registrySchema, Secrets: []Entry{entry}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "registry.yaml")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func incompleteTestFileHolder(t *testing.T) Holder {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("file-holder fixture uses the POSIX grep executable")
	}
	path := filepath.Join(t.TempDir(), "holder.env")
	if err := os.WriteFile(path, []byte("API_KEY="+syntheticSecret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return Holder{ID: "file-holder", Kind: "file", Path: path, Key: "API_KEY"}
}

func incompleteTestCloudHolder() Holder {
	return Holder{ID: "cloud-holder", Kind: "cloud-run", Project: "test", Region: "test", Service_: "demo", Env: "API_KEY"}
}

func incompleteTestSource(t *testing.T, available bool) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("synthetic gcloud executable uses a POSIX shell")
	}
	directory := t.TempDir()
	script := "#!/bin/sh\nexit 1\n"
	if available {
		script = "#!/bin/sh\nif [ \"$1\" = secrets ]; then printf '%s\\n' '" + syntheticSecret + "'; exit 0; fi\nexit 1\n"
	}
	if err := os.WriteFile(filepath.Join(directory, "gcloud"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("HOME", t.TempDir())
}

func TestInventoryRefusesIncompleteSource(t *testing.T) {
	incompleteTestSource(t, false)
	path := incompleteTestRegistry(t, []Holder{incompleteTestFileHolder(t)}, "")
	var stdout, stderr bytes.Buffer
	code := cmdInventory([]string{"--registry", path, "demo"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), "UNVOLLSTAENDIG") {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, &stdout, &stderr)
	}
	if strings.Contains(stdout.String(), syntheticSecret) {
		t.Fatal("secret in inventory output")
	}
}

func TestInventoryRefusesUnreadableHolder(t *testing.T) {
	incompleteTestSource(t, true)
	path := incompleteTestRegistry(t, []Holder{incompleteTestCloudHolder()}, "")
	var stdout, stderr bytes.Buffer
	code := cmdInventory([]string{"--registry", path, "demo"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), "unlesbar") || !strings.Contains(stdout.String(), "UNVOLLSTAENDIG") {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, &stdout, &stderr)
	}
}

func TestInventoryCompleteSourceAndHolderStillPass(t *testing.T) {
	incompleteTestSource(t, true)
	path := incompleteTestRegistry(t, []Holder{incompleteTestFileHolder(t)}, "")
	var stdout, stderr bytes.Buffer
	if code := cmdInventory([]string{"--registry", path, "demo"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, &stdout, &stderr)
	}
}

func TestVerifyNeverConfirmsUnprobedHolders(t *testing.T) {
	for _, old := range []bool{false, true} {
		for _, mixed := range []bool{false, true} {
			t.Run(strings.Join([]string{map[bool]string{false: "current", true: "old"}[old], map[bool]string{false: "cloud-only", true: "mixed"}[mixed]}, "/"), func(t *testing.T) {
				var requests atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if r.Header.Get("X-API-KEY") != syntheticSecret {
						t.Error("unexpected test credential")
					}
					if old {
						w.WriteHeader(401)
					} else {
						w.WriteHeader(200)
					}
				}))
				defer server.Close()
				holders := []Holder{incompleteTestCloudHolder()}
				if mixed {
					holders = append(holders, incompleteTestFileHolder(t))
				}
				path := incompleteTestRegistry(t, holders, server.URL)
				args := []string{"--registry", path}
				if old {
					args = append(args, "--old")
				}
				args = append(args, "demo")
				var stdout, stderr bytes.Buffer
				code := cmdVerify(args, &stdout, &stderr)
				if code != 1 || strings.Contains(stdout.String(), "alle wie erwartet") || !strings.Contains(stdout.String(), "NICHT PRUEFBAR") {
					t.Fatalf("exit=%d stdout=%s stderr=%s", code, &stdout, &stderr)
				}
				wantRequests := int32(0)
				if mixed {
					wantRequests = 1
				}
				if requests.Load() != wantRequests {
					t.Fatalf("requests=%d want %d", requests.Load(), wantRequests)
				}
			})
		}
	}
}
