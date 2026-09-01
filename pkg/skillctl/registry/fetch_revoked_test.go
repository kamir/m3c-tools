package registry

import (
	"crypto/ed25519"
	"testing"
)

// TestFetchRevokedDigests proves SPEC-0266 F1: a verified BundleRevokedEvent's
// digest is returned, and an UNSIGNED (forged) revoke is ignored — a forged
// revoke must not be usable to quarantine a good bundle.
func TestFetchRevokedDigests(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := newPullFake(t)
	_, digest := mintAdmitItem(t, priv, "x", "1.0.0", "skb")
	f.addItem(mintRevokeItem(t, priv, "x", "1.0.0", digest, "deprecated"))

	set, err := FetchRevokedDigests(f.cfg(), "skills", pub)
	if err != nil {
		t.Fatalf("FetchRevokedDigests: %v", err)
	}
	if _, ok := set[digest]; !ok {
		t.Errorf("verified revoke for %s not in set %v", digest, set)
	}
}

func TestFetchRevokedDigests_IgnoresUnsignedRevoke(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := newPullFake(t)
	_, digest := mintAdmitItem(t, priv, "x", "1.0.0", "skb")
	f.addItem(mintUnsignedRevokeItem(t, "x", "1.0.0", digest, "forged"))

	set, err := FetchRevokedDigests(f.cfg(), "skills", pub)
	if err != nil {
		t.Fatalf("FetchRevokedDigests: %v", err)
	}
	if _, ok := set[digest]; ok {
		t.Errorf("UNSIGNED revoke must be ignored (a forged revoke must not quarantine a good bundle); set=%v", set)
	}
}
