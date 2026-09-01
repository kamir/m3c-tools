// Package httpsafe holds small, dependency-free HTTP hardening helpers shared
// across the credential-bearing clients (er1, session, plaud, pocket).
//
// SEC F25 (2026-06-13 security review): Go's stdlib redirect policy strips
// Authorization/Cookie/WWW-Authenticate when a redirect crosses to a different
// host — but it does NOT strip custom credential headers like X-API-KEY or
// X-Context-ID. A hostile or compromised ER1 server can therefore answer any
// request with `302 Location: https://collector.attacker.tld/` and harvest the
// long-lived ER1 API key + context id. This package centralizes the fix so all
// five credential clients share one implementation (the review's parity rule).
package httpsafe

import (
	"fmt"
	"net/http"
)

// MaxRedirects caps any single redirect chain.
const MaxRedirects = 10

// sensitiveHeaders are dropped when a redirect crosses to a different host.
// Stored in canonical (textproto) form so Header.Del matches regardless of the
// case the caller used when setting them.
var sensitiveHeaders = []string{
	"X-Api-Key",     // X-API-KEY (ER1 long-lived key — the exposed credential)
	"X-Context-Id",  // X-Context-ID
	"Authorization", // Bearer device token; stdlib also strips this — belt & suspenders
	"Cookie",
}

// NoCredentialRedirect returns a CheckRedirect that (1) caps the chain at
// MaxRedirects and (2) deletes sensitiveHeaders from the upcoming request
// whenever its host differs from the ORIGINATING request's host. Host
// comparison uses the hostname only (a same-host port change — e.g. a local
// load balancer — keeps the headers; a different hostname does not).
func NoCredentialRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= MaxRedirects {
		return fmt.Errorf("stopped after %d redirects", MaxRedirects)
	}
	if len(via) > 0 && !sameHost(req, via[0]) {
		for _, h := range sensitiveHeaders {
			req.Header.Del(h)
		}
	}
	return nil
}

func sameHost(a, b *http.Request) bool {
	if a == nil || b == nil || a.URL == nil || b.URL == nil {
		return false
	}
	return equalFoldASCII(a.URL.Hostname(), b.URL.Hostname())
}

// equalFoldASCII compares two ASCII hostnames case-insensitively without
// pulling in strings (keeps this leaf package allocation-light).
func equalFoldASCII(x, y string) bool {
	if len(x) != len(y) {
		return false
	}
	for i := 0; i < len(x); i++ {
		cx, cy := x[i], y[i]
		if 'A' <= cx && cx <= 'Z' {
			cx += 'a' - 'A'
		}
		if 'A' <= cy && cy <= 'Z' {
			cy += 'a' - 'A'
		}
		if cx != cy {
			return false
		}
	}
	return true
}
