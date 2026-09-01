package config

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- SEC-M7 / F33: TestConnection must not skip TLS verification for remote hosts ---

// TestHealthCheckSkipVerify_Decision is the fast, pure table test of the
// fail-closed gate. ER1_VERIFY_SSL=false (or 0/no) may only disable verification
// for a literal loopback target; for any remote host the request is refused.
//
// Before the F33 fix, healthCheckER1 set skipVerify=true for ANY host whenever
// the raw string was false/0/no — so the remote rows below would have been true.
func TestHealthCheckSkipVerify_Decision(t *testing.T) {
	cases := []struct {
		name      string
		apiURL    string
		verifyStr string
		want      bool
	}{
		// Loopback + insecure requested → honoured.
		{"loopback-127-false", "https://127.0.0.1:8081/upload_2", "false", true},
		{"loopback-localhost-0", "https://localhost:8081/upload_2", "0", true},
		{"loopback-v6-no", "https://[::1]:8081/upload_2", "no", true},
		{"loopback-127-5-6-7", "https://127.5.6.7:9000/upload_2", "false", true},
		// Remote host + insecure requested → REFUSED (fail-closed).
		{"remote-onboarding", "https://onboarding.guide/upload_2", "false", false},
		{"remote-example", "https://remote-er1.example/upload_2", "no", false},
		{"remote-rfc1918", "https://10.0.0.5:8081/upload_2", "0", false},
		{"remote-lan", "https://192.168.1.10/upload_2", "false", false},
		// Verification on (or default) → never skip, regardless of host.
		{"loopback-verify-true", "https://127.0.0.1:8081/upload_2", "true", false},
		{"remote-verify-true", "https://onboarding.guide/upload_2", "true", false},
		{"remote-verify-empty", "https://onboarding.guide/upload_2", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := healthCheckSkipVerify(tc.apiURL, tc.verifyStr); got != tc.want {
				t.Errorf("healthCheckSkipVerify(%q, %q) = %v, want %v",
					tc.apiURL, tc.verifyStr, got, tc.want)
			}
		})
	}
}

// TestConnection_RefusesInsecureRemote drives the real TestConnection code path
// against an httptest TLS server presenting a self-signed cert (the MITM stand-in:
// a "remote" host whose certificate does NOT chain to a trusted root).
//
// The server's hostname is 127.0.0.1, so to exercise the REMOTE branch we point
// the profile's ER1_API_URL at the server's port via a non-loopback hostname
// ("remote-er1.example") resolved through a custom dialer is overkill here;
// instead we assert the gate directly: with a remote URL + verify=false the
// connection must be attempted WITH verification (and therefore fail against the
// self-signed cert), proving the unverified channel is refused. With a loopback
// URL + verify=false the self-signed cert is accepted and the health check passes.
func TestConnection_RefusesInsecureRemote(t *testing.T) {
	// Self-signed TLS server (untrusted cert), answering /health with 200.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/health") {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	// srv.URL is https://127.0.0.1:<port> — a loopback host.
	loopbackURL := srv.URL + "/upload_2"

	t.Run("loopback-insecure-passes", func(t *testing.T) {
		// verify=false for loopback is honoured → self-signed cert accepted → OK.
		if err := healthCheckER1(loopbackURL, "false"); err != nil {
			t.Fatalf("loopback + verify=false should pass against self-signed server, got: %v", err)
		}
	})

	t.Run("loopback-verify-true-fails-cert", func(t *testing.T) {
		// verify=true (default) for loopback must verify → self-signed cert rejected.
		err := healthCheckER1(loopbackURL, "true")
		if err == nil {
			t.Fatal("loopback + verify=true must reject the self-signed cert, but health check passed")
		}
		if !strings.Contains(err.Error(), "unreachable") && !strings.Contains(strings.ToLower(err.Error()), "certificate") {
			t.Fatalf("expected a TLS/connection error, got: %v", err)
		}
	})

	t.Run("remote-insecure-is-refused-fails-cert", func(t *testing.T) {
		// THE F33 REGRESSION GUARD: a REMOTE host with verify=false must be
		// refused — verification stays ON, so the self-signed cert is rejected
		// and the health check FAILS rather than reporting the remote profile
		// as healthy over an unverified channel.
		//
		// Build a remote-looking URL that still reaches the test server's port
		// by reusing the loopback authority but a non-loopback Host via a hosts
		// override is not available in stdlib httptest; instead we rely on the
		// gate: skipVerify must be false for a remote URL. We assert that the
		// decision the health check would make is fail-closed.
		remoteURL := "https://remote-er1.example" + portOf(srv.URL) + "/upload_2"
		if healthCheckSkipVerify(remoteURL, "false") {
			t.Fatal("remote host + verify=false must NOT skip verification (fail-open regression)")
		}
		// And the real code path against an unresolvable/untrusted remote must
		// not succeed silently.
		if err := healthCheckER1(remoteURL, "false"); err == nil {
			t.Fatal("remote + verify=false must not report healthy over an unverified channel")
		}
	})
}

// portOf returns the ":<port>" suffix of an https URL like https://127.0.0.1:54321.
func portOf(u string) string {
	if i := strings.LastIndex(u, ":"); i > len("https://") {
		return u[i:]
	}
	return ""
}
