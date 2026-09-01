package verify

// P1c hardening (SPEC-0246/0281 follow-ups): the key-confusion guard and
// case-normalized reviewer/author lookup.

import (
	"encoding/base64"
	"strings"
	"testing"
)

// A key pinned as BOTH an author and a reviewer in one root must be refused at
// Load — otherwise the author could sign an "independent" attestation under a
// reviewer id and launder reviewer≠author.
func TestTrustRoots_KeyConfusion_Refused(t *testing.T) {
	regKey := mustKeypair(t)
	shared := mustKeypair(t) // same key pinned as author AND reviewer
	body := "" +
		"trust_roots:\n" +
		"  - registry_url: https://reg.example/api/skills\n" +
		"    registry_keys:\n      - id: reg-key-1\n        pubkey: " + regKey.b64 + "\n" +
		"    identity_keys_authorized: pinned\n    governance_minimum: green\n" +
		"    require_independent_review: true\n" +
		"    authors:\n      - id: id:author@m3c\n        pubkey: " + shared.b64 + "\n" +
		"    reviewers:\n      - id: id:reviewer@m3c\n        pubkey: " + shared.b64 + "\n"
	_, err := Load(writeTrustRootsYAML(t, body))
	if err == nil {
		t.Fatal("a key pinned as both author and reviewer must be refused")
	}
	if !strings.Contains(err.Error(), "key-confusion") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Distinct keys for author vs reviewer load fine (the common, correct config).
func TestTrustRoots_DistinctAuthorReviewer_OK(t *testing.T) {
	regKey := mustKeypair(t)
	a := mustKeypair(t)
	r := mustKeypair(t)
	body := "" +
		"trust_roots:\n" +
		"  - registry_url: https://reg.example/api/skills\n" +
		"    registry_keys:\n      - id: reg-key-1\n        pubkey: " + regKey.b64 + "\n" +
		"    identity_keys_authorized: pinned\n    governance_minimum: green\n" +
		"    require_independent_review: true\n" +
		"    authors:\n      - id: id:author@m3c\n        pubkey: " + a.b64 + "\n" +
		"    reviewers:\n      - id: id:reviewer@m3c\n        pubkey: " + r.b64 + "\n"
	if _, err := Load(writeTrustRootsYAML(t, body)); err != nil {
		t.Fatalf("distinct author/reviewer keys should load: %v", err)
	}
}

// FindReviewer / FindAuthor match ids case-insensitively (no lookup vs equality
// asymmetry).
func TestFindReviewerAuthor_CaseNormalized(t *testing.T) {
	k := mustKeypair(t)
	root := &TrustRoot{
		Reviewers: []AuthorKey{{ID: "id:bob@m3c", Pubkey: []byte(k.pub), PubkeyB64: base64.StdEncoding.EncodeToString(k.pub)}},
		Authors:   []AuthorKey{{ID: "id:dana@m3c", Pubkey: []byte(k.pub), PubkeyB64: base64.StdEncoding.EncodeToString(k.pub)}},
	}
	if root.FindReviewer("  id:BOB@M3C ") == nil {
		t.Error("FindReviewer should match case/whitespace-variant id")
	}
	if root.FindAuthor("ID:Dana@m3c") == nil {
		t.Error("FindAuthor should match case-variant id")
	}
	if root.FindReviewer("id:someone-else@m3c") != nil {
		t.Error("FindReviewer must not match a different id")
	}
}
