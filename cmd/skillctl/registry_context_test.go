// registry_context_test.go: BUG-0437.
//
// `registry ls` and `registry show` passed the --er1-context flag value to ER1
// raw. The default is the bare name "skills", while ER1 contexts are named
// "<owner>___skills". The read commands therefore asked a context that does
// not exist and answered "(no skills in registry)" or "not found in
// registry", a silent wrong answer to a question about the catalogue. The
// publish and pull paths already resolve the name with ownerPrefixedContext.
package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeRegistryER1 answers every /memory/<ctx> read with an empty list and
// records which contexts were asked.
func fakeRegistryER1(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/memory/") {
			mu.Lock()
			asked = append(asked, strings.TrimPrefix(r.URL.Path, "/memory/"))
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), asked...)
	}
}

func registryReadEnv(t *testing.T, owner string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("ER1_API_KEY", "fake-key-for-test")
	t.Setenv("ER1_DEVICE_TOKEN", "")
	t.Setenv("ER1_CONTEXT", "")
	t.Setenv("ER1_CONTEXT_ID", "")
	t.Setenv("ER1_USER_ID", owner)
}

func TestBUG0437_ReadCommandsPrefixTheDefaultContext(t *testing.T) {
	const owner = "107677460544181387647"
	for _, tc := range []struct {
		name string
		run  func(args []string, stdout, stderr *bytes.Buffer) int
		args []string
	}{
		{"ls", func(a []string, o, e *bytes.Buffer) int { return runRegistryLs(a, o, e) }, nil},
		{"show", func(a []string, o, e *bytes.Buffer) int { return runRegistryShow(a, o, e) }, []string{"review-plan"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registryReadEnv(t, owner)
			srv, asked := fakeRegistryER1(t)
			var stdout, stderr bytes.Buffer
			args := append([]string{"--er1-target", srv.URL}, tc.args...)
			tc.run(args, &stdout, &stderr)
			got := asked()
			if len(got) == 0 {
				t.Fatalf("no context was asked; stdout=%s stderr=%s", &stdout, &stderr)
			}
			for _, c := range got {
				if c != owner+"___skills" {
					t.Fatalf("registry %s asked context %q, want %q (the bare default does not exist)", tc.name, c, owner+"___skills")
				}
			}
			// The answer names the context it was given, so a reader sees where
			// the catalogue was looked up.
			if !strings.Contains(stdout.String()+stderr.String(), owner+"___skills") {
				t.Fatalf("output does not name the resolved context:\nstdout=%s\nstderr=%s", &stdout, &stderr)
			}
		})
	}
}

// Without a resolvable owner the bare name stays bare, and a bare name cannot
// be an ER1 context. That is an error, never an empty list.
func TestBUG0437_UnresolvableContextIsAnErrorNotAnEmptyList(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(args []string, stdout, stderr *bytes.Buffer) int
		args []string
	}{
		{"ls", func(a []string, o, e *bytes.Buffer) int { return runRegistryLs(a, o, e) }, nil},
		{"show", func(a []string, o, e *bytes.Buffer) int { return runRegistryShow(a, o, e) }, []string{"review-plan"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registryReadEnv(t, "")
			if strings.Contains(ownerPrefixedContext("skills"), "___") {
				t.Skip("an owner is still resolvable from the environment; the bare case cannot be built")
			}
			srv, asked := fakeRegistryER1(t)
			var stdout, stderr bytes.Buffer
			args := append([]string{"--er1-target", srv.URL}, tc.args...)
			code := tc.run(args, &stdout, &stderr)
			if code == 0 {
				t.Fatalf("exit 0 for a context that cannot exist; stdout=%s", &stdout)
			}
			if strings.Contains(stdout.String(), "no skills in registry") {
				t.Fatal("an unanswerable question was reported as an empty registry")
			}
			if len(asked()) != 0 {
				t.Fatalf("asked ER1 for a context that cannot exist: %v", asked())
			}
			if !strings.Contains(stderr.String(), `"skills"`) {
				t.Fatalf("the error does not name the context: %s", &stderr)
			}
		})
	}
}

// A full context name passes through unchanged.
func TestBUG0437_FullContextIsUsedAsGiven(t *testing.T) {
	registryReadEnv(t, "107677460544181387647")
	srv, asked := fakeRegistryER1(t)
	var stdout, stderr bytes.Buffer
	runRegistryLs([]string{"--er1-target", srv.URL, "--er1-context", "42___skillenv"}, &stdout, &stderr)
	for _, c := range asked() {
		if c != "42___skillenv" {
			t.Fatalf("a full context was rewritten to %q", c)
		}
	}
	if len(asked()) == 0 {
		t.Fatalf("no request; stderr=%s", &stderr)
	}
}
