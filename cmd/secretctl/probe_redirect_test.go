package main

// Challenge-gate F4 (PR #319): a probe request carries the live value in a
// header, and the tool whose one hard promise is "never hands a value on"
// must not follow a redirect with it. Probe.Ask therefore follows NO redirect
// at all: the 30x IS the answer. This test pins that behaviour with a 302
// pointing at a second host; the value must not travel there, whatever the
// header is called (the httpsafe strip list knows four canonical names, the
// registry field is free text).

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestProbeAskDoesNotFollowRedirect(t *testing.T) {
	var collectorHits atomic.Int64
	var leakedHeader atomic.Value
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		collectorHits.Add(1)
		leakedHeader.Store(r.Header.Get("X-ER1-KEY"))
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	var targetGotValue atomic.Value
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetGotValue.Store(r.Header.Get("X-ER1-KEY"))
		http.Redirect(w, r, collector.URL, http.StatusFound)
	}))
	defer target.Close()

	p := Probe{Kind: "http", URL: target.URL, Header: "X-ER1-KEY"}
	status, err := p.Ask(Secret("live-value-do-not-travel"))
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if status != http.StatusFound {
		t.Errorf("status = %d, want %d (the 30x is the answer)", status, http.StatusFound)
	}
	if got, _ := targetGotValue.Load().(string); got != "live-value-do-not-travel" {
		t.Errorf("the probed service itself did not receive the header (got %q)", got)
	}
	if n := collectorHits.Load(); n != 0 {
		t.Fatalf("the redirect target received %d request(s); the value travelled: header=%q",
			n, leakedHeader.Load())
	}

	// Counter-probe (claims rule 4): the collector's counter does count. One
	// direct request must register, so the zero above is a measured zero.
	resp, err := http.Get(collector.URL)
	if err != nil {
		t.Fatalf("direct GET: %v", err)
	}
	_ = resp.Body.Close()
	if n := collectorHits.Load(); n != 1 {
		t.Fatalf("collector counter did not register the planted request: %d", n)
	}
}
