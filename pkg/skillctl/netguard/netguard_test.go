package netguard

import "testing"

// TestIsLoopbackOrPrivate pins the ONE audited egress predicate shared by the
// OCI, git, and ER1 guards. Loopback + RFC1918/ULA + "localhost" are local; a
// public IP and any bare DNS name (fail-closed — a name resolves anywhere) are
// NOT.
func TestIsLoopbackOrPrivate(t *testing.T) {
	local := []string{
		"127.0.0.1", "127.0.0.1:5000", "localhost", "localhost:8081",
		"10.0.0.5", "172.16.9.9", "192.168.0.131:8929",
		"::1", "[::1]:8081", "fd00::1", // ULA
	}
	for _, h := range local {
		if !IsLoopbackOrPrivate(h) {
			t.Errorf("IsLoopbackOrPrivate(%q) = false, want true (local)", h)
		}
	}
	notLocal := []string{
		"8.8.8.8", "1.2.3.4:443",
		"ghcr.io", "gitlab.example.com", "onboarding.guide:443",
		"", "example.com",
	}
	for _, h := range notLocal {
		if IsLoopbackOrPrivate(h) {
			t.Errorf("IsLoopbackOrPrivate(%q) = true, want false (not provably local)", h)
		}
	}
}
