package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The advertised flag has to EXIST. Both `skillctl revoke feed`'s own usage text
// and docs/manual-skillctl.md have documented `--status` since FR-0045; for as
// long, no FlagSet defined it, so the documented command died with "flag
// provided but not defined: -status" (exit 2) before it ever reached a registry.
// The CLI flag gate cannot see that class of defect: it compares the flag names
// of a whole CLI against a whole manual, and `login --status` kept the name
// present somewhere in skillctl.
//
// Hermetic: the registry is an httptest server in this process, so the test
// measures argument parsing and mode selection, never the network.
func TestRevokeFeedStatusFlagExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := runRevokeFeed(append(args, "--registry", srv.URL+"/api/skills", "--timeout", "5s"), &out, &errb)
		return code, out.String(), errb.String()
	}

	bareCode, bareOut, bareErr := run()
	statusCode, statusOut, statusErr := run("--status")

	if strings.Contains(statusErr, "not defined") {
		t.Fatalf("--status is not registered as a flag: %s", statusErr)
	}
	if statusCode == exitUsage {
		t.Fatalf("--status exited %d (usage error): %s", statusCode, statusErr)
	}
	// --status names the DEFAULT mode, so it must reach the same code path with
	// the same result. Equality of both streams is the evidence.
	if statusCode != bareCode || statusOut != bareOut || statusErr != bareErr {
		t.Fatalf("--status took a different path than the default:\n  bare:   %d %q %q\n  status: %d %q %q",
			bareCode, bareOut, bareErr, statusCode, statusOut, statusErr)
	}
}

// The read-only mode and a mode that writes cannot both be meant. Refuse rather
// than pick: silently adopting a HEAD an operator only wanted to inspect is the
// expensive half of the guess.
//
// The pin is not only the exit code, it is that the refusal happens BEFORE any
// registry contact. So the stub counts its requests and the test asserts zero:
// dropping the guard makes `--status --refresh` run the sweep, and a test that
// only checked the exit code would let that reach a real registry and a real
// credential store instead of failing here.
func TestRevokeFeedStatusRefusesWriteModes(t *testing.T) {
	for _, other := range []string{"--refresh", "--gossip"} {
		var hits int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&hits, 1)
			w.WriteHeader(http.StatusInternalServerError)
		}))

		var out, errb bytes.Buffer
		code := runRevokeFeed([]string{"--status", other, "--registry", srv.URL + "/api/skills", "--timeout", "2s"}, &out, &errb)
		srv.Close()

		if code != exitUsage {
			t.Fatalf("--status %s exited %d, want %d (usage)", other, code, exitUsage)
		}
		if !strings.Contains(errb.String(), "read-only") {
			t.Fatalf("--status %s: stderr does not say why: %q", other, errb.String())
		}
		if n := atomic.LoadInt32(&hits); n != 0 {
			t.Fatalf("--status %s reached the registry %d time(s) before refusing", other, n)
		}
	}
}
