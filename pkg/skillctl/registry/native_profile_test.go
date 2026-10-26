package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func nativeFixtureRoots(t *testing.T) (*NativeRootsSnapshot, ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	raw := []byte("registry: self\npubkey_b64: " + base64.StdEncoding.EncodeToString(pub) + "\ngovernance_minimum: green\ngovernance_quorum: 1\n")
	snapshot, e := ParseNativeRootsSnapshot(raw)
	if e != nil {
		t.Fatal(e)
	}
	return snapshot, key, raw
}
func TestNativeRootRoleSnapshots(t *testing.T) {
	roots, _, raw := nativeFixtureRoots(t)
	r := roots.Roots()
	r.Registry = "foreign"
	r.PubKey()[0] ^= 255
	if roots.Roots().Registry != "self" || roots.Roots().PubKey()[0] == r.PubKey()[0] {
		t.Fatal("mutable roots escaped private snapshot")
	}
	for _, suffix := range []string{"cross_sign_path: unpinned.json\n", "governance_root_pubkey_b64: value\n"} {
		if _, e := ParseNativeRootsSnapshot(append(append([]byte{}, raw...), suffix...)); !errors.Is(e, ErrNativeUnsupported) {
			t.Fatal("crosssign selection read or accepted", e)
		}
	}
	for _, bad := range [][]byte{append(append([]byte{}, raw...), []byte("registry: self\n")...), append(append([]byte{}, raw...), []byte("---\nregistry: other\n")...), []byte("registry: &a self\npubkey_b64: *a\n"), []byte("null"), []byte(strings.Repeat(" ", 1<<20+1)), []byte(strings.Replace(string(raw), "governance_quorum: 1", "governance_quorum: 0", 1)), []byte(strings.Replace(string(raw), "registry:", "Registry:", 1))} {
		if _, e := ParseNativeRootsSnapshot(bad); e == nil {
			t.Fatal("invalid bounded native roots accepted")
		}
	}
	for _, zero := range []string{"0x0", "00", "+0", "null"} {
		candidate := strings.Replace(string(raw), "governance_quorum: 1", "governance_quorum: "+zero, 1)
		if _, e := ParseNativeRootsSnapshot([]byte(candidate)); e == nil {
			t.Fatal("alternate zero/null quorum accepted", zero)
		}
	}
	// A repeated physical reviewer key cannot count as two direct pins.
	pub := base64.StdEncoding.EncodeToString(roots.Roots().PubKey())
	duplicate := strings.Replace(string(raw), "governance_quorum: 1", "governance_quorum: 2", 1) + "signers:\n - reviewer_id: a\n   pubkey_b64: " + pub + "\n - reviewer_id: b\n   pubkey_b64: " + pub + "\n"
	if _, e := ParseNativeRootsSnapshot([]byte(duplicate)); e == nil {
		t.Fatal("duplicate reviewer key manufactured quorum")
	}
}
func nativeEvidenceBytes(t *testing.T, key ed25519.PrivateKey, issued time.Time, epoch int, set []string, modify func(map[string]any)) []byte {
	t.Helper()
	head, e := BuildRevocationHead(RevocationHeadInput{Epoch: epoch, IssuedAt: issued, Digests: set, Emergency: []string{}})
	if e != nil {
		t.Fatal(e)
	}
	if modify != nil {
		modify(head)
	}
	if _, e = SignEnvelopeSignature(key, head); e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(map[string]any{"schema": "m3c.native-revocation-evidence/v1", "head": head, "revoked_digests": set})
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestNativeRevocationEvidenceBounds(t *testing.T) {
	roots, key, _ := nativeFixtureRoots(t)
	authority, e := NewNativeRevocationAuthority("self", nil, roots)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Second)
	set := []string{"sha256:" + strings.Repeat("1", 64)}
	valid := nativeEvidenceBytes(t, key, now.Add(-time.Hour), 7, set, nil)
	snapshot, e := inspectNativeRevocationEvidence(valid, authority, now)
	if e != nil || snapshot.Observation().Epoch != 7 || snapshot.Observation().RevokedCount != 1 {
		t.Fatal("signed fullset positive", e)
	}
	_, wrongKey, _ := nativeFixtureRoots(t)
	if _, e = inspectNativeRevocationEvidence(nativeEvidenceBytes(t, wrongKey, now, 7, set, nil), authority, now); e == nil {
		t.Fatal("artifact/foreign role signed HEAD accepted")
	}
	for _, tc := range []struct {
		name   string
		modify func(map[string]any)
	}{
		{"fractional-epoch", func(h map[string]any) { h["epoch"] = json.Number("7.5") }},
		{"overflow-epoch", func(h map[string]any) { h["epoch"] = json.Number("9223372036854775808") }},
		{"zero-epoch", func(h map[string]any) { h["epoch"] = 0 }},
		{"null-emergency", func(h map[string]any) { h["emergency"] = nil }},
		{"wrong-count", func(h map[string]any) { h["revoked_count"] = 2 }},
		{"wrong-root", func(h map[string]any) { h["revoked_set_root"] = "sha256:" + strings.Repeat("0", 64) }},
		{"foreign-tenant", func(h map[string]any) { h["tenant_scope"] = "other" }},
		{"emergency-outside-set", func(h map[string]any) { h["emergency"] = []string{"sha256:" + strings.Repeat("2", 64)} }},
		{"alias", func(h map[string]any) { h["Epoch"] = 7 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := nativeEvidenceBytes(t, key, now.Add(-time.Hour), 7, set, tc.modify)
			if _, e := inspectNativeRevocationEvidence(raw, authority, now); e == nil {
				t.Fatal("invalid signed native evidence accepted")
			}
		})
	}
	for _, issued := range []time.Time{now.Add(time.Minute), now.Add(-24*time.Hour - time.Nanosecond)} {
		if _, e = inspectNativeRevocationEvidence(nativeEvidenceBytes(t, key, issued, 7, set, nil), authority, now); e == nil {
			t.Fatal("future/stale signed issue accepted")
		}
	}
	if _, e = inspectNativeRevocationEvidence(nativeEvidenceBytes(t, key, now.Add(-24*time.Hour), 7, set, nil), authority, now); e != nil {
		t.Fatal("exact24h boundary", e)
	}
	if _, e = inspectNativeRevocationEvidence([]byte(strings.Repeat(" ", 1<<20+1)), authority, now); e == nil {
		t.Fatal("oversize accepted")
	}
	capped := make([]string, 8192)
	for i := range capped {
		capped[i] = fmt.Sprintf("sha256:%064x", i)
	}
	if _, e = inspectNativeRevocationEvidence(nativeEvidenceBytes(t, key, now, 7, capped, nil), authority, now); e != nil {
		t.Fatal("8192 digest positive edge", e)
	}
	capped = append(capped, fmt.Sprintf("sha256:%064x", 8192))
	if _, e = inspectNativeRevocationEvidence(nativeEvidenceBytes(t, key, now, 7, capped, nil), authority, now); e == nil {
		t.Fatal("digest cap+1 accepted")
	}
	tenant := "selected"
	bound, e := NewNativeRevocationAuthority("self", &tenant, roots)
	if e != nil {
		t.Fatal(e)
	}
	tenant = "changed"
	if _, e = inspectNativeRevocationEvidence(nativeEvidenceBytes(t, key, now, 7, set, func(h map[string]any) { h["tenant_scope"] = "selected" }), bound, now); e != nil {
		t.Fatal("tenant was not snapshotted", e)
	}
	restricted, e := authority.WithPolicy(8, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	if restricted.HistoryAuthorityID() != authority.HistoryAuthorityID() {
		t.Fatal("policy tightening forked history identity")
	}
	if _, e = inspectNativeRevocationEvidence(valid, restricted, now); e == nil {
		t.Fatal("minimum epoch ignored")
	}
}
