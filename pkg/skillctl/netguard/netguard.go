// Package netguard holds the shared "is this host provably local?" egress
// predicate used to gate credentials and TLS-verification bypasses across the
// skillctl artifact backends (OCI, git) and the ER1 registry client.
//
// It is deliberately ONE audited definition (in the same spirit as
// trustcore.KindFromSignedEnvelope, FR-0090): a bearer/basic credential may only
// ride plain HTTP, and TLS verification may only be disabled, when the target
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

// IsLoopback is the STRICTER sibling of IsLoopbackOrPrivate: it treats ONLY
// loopback addresses (127.0.0.0/8, ::1) and the name "localhost" as local: an
// RFC1918/ULA private address is NOT local here. It exists for the ER1
// TLS-verification-bypass guard, which must match pkg/er1.applyTLSVerificationPolicy
// exactly: that policy honors ER1_VERIFY_SSL=false only for 127.0.0.1/localhost and
// forces verification back on for every other host, RFC1918 LAN hosts included. A
// TLS-skip that the core ER1 client forbids must not be reachable through the
// registry client. (The git/OCI *credential* guards keep IsLoopbackOrPrivate: a
// LAN registry over plain HTTP is a legitimate, narrower risk than skipping cert
// verification against a routable-but-private host.)
func IsLoopback(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}
