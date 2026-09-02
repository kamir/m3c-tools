// Package netguard holds the shared "is this host provably local?" egress
// predicate used to gate credentials and TLS-verification bypasses across the
// skillctl artifact backends (OCI, git) and the ER1 registry client.
//
// It is deliberately ONE audited definition (in the same spirit as
// trustcore.KindFromSignedEnvelope, FR-0090): a bearer/basic credential may only
// ride plain HTTP — and TLS verification may only be disabled — when the target
// host is provably loopback or on a private (RFC1918/ULA) network. If three
// backends each carried their own copy of this predicate they could drift, and a
// drift here is a credential-exfiltration / MITM hole. Keeping it in one place
// means the OCI plain-HTTP guard, the git write-token guard, and the ER1
// VerifySSL=false guard all fail closed on exactly the same host set.
package netguard

import "net"

// IsLoopbackOrPrivate reports whether host (which may be "host" or "host:port")
// is provably a loopback or RFC1918/ULA address.
//
// Fail-closed policy: a bare DNS name (anything that is not an IP literal, other
// than the special-cased "localhost") is treated as NON-local, because a name can
// resolve anywhere and we must not attach a secret / skip TLS verification on the
// strength of an unresolved hostname. Only "localhost" and literal
// loopback/private IPs return true.
func IsLoopbackOrPrivate(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false // a DNS name could resolve anywhere → not provably local
	}
	return ip.IsLoopback() || ip.IsPrivate()
}
