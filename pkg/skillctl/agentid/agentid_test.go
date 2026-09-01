package agentid

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakePins is a tiny PinnedKeys implementation for tests: two maps, owner +
// approver, keyed by normalized id. No network, no files.
type fakePins struct {
	owners    map[string]*PinnedKey
	approvers map[string]*PinnedKey
}

func (f fakePins) FindOwner(id string) *PinnedKey    { return f.owners[NormalizeID(id)] }
func (f fakePins) FindApprover(id string) *PinnedKey { return f.approvers[NormalizeID(id)] }

func newFakePins() *fakePins {
	return &fakePins{owners: map[string]*PinnedKey{}, approvers: map[string]*PinnedKey{}}
}

func (f *fakePins) pinOwner(id string, pub ed25519.PublicKey) {
	f.owners[NormalizeID(id)] = &PinnedKey{ID: id, Pubkey: pub}
}
func (f *fakePins) pinApprover(id string, pub ed25519.PublicKey) {
	f.approvers[NormalizeID(id)] = &PinnedKey{ID: id, Pubkey: pub}
}

func mustKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return pub, priv
}

func samplePayload() Payload {
	return Payload{
		ID:                "agent:9f2c",
		Owner:             "id:kamir@m3c",
		DisplayName:       "ResearchAgent",
		AgentBundleDigest: "sha256:" + strings.Repeat("a", 64),
		CreatedAt:         "2026-06-22T10:00:00Z",
		NotAfter:          "2026-12-31T00:00:00Z",
		TrustRoot:         "https://onboarding.guide/api/skills",
		Grant: Grant{
			// Deliberately UNSORTED + duplicated to prove canon sorts/dedups.
			Skills:     []string{"fetch-contract@>=1.0.0", "alpha-skill", "fetch-contract@>=1.0.0"},
			Intents:    []string{"network:read", "fs:read"},
			DataScopes: []string{"ctx:107677460544181387647___skills"},
			Limits:     map[string]string{"spend_eur_max": "0", "calls_max": "100"},
		},
	}
}

// TestGoldenCanonicalBytes pins the EXACT canonical bytes. The domain separator
// must be the first line and DISTINCT from the other envelope families; the
// grant arrays must be sorted + de-duplicated; the limit keys sorted. A change
// here is a wire-breaking change and must be deliberate (version bump).
func TestGoldenCanonicalBytes(t *testing.T) {
	got, err := CanonicalAgentIDBytes(samplePayload())
	if err != nil {
		t.Fatalf("canon: %v", err)
	}
	want := `agentid_v1
{"type":"skillctl-agentid","version":1,"id":"agent:9f2c","owner":"id:kamir@m3c","display_name":"ResearchAgent","agent_bundle_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","created_at":"2026-06-22T10:00:00Z","not_after":"2026-12-31T00:00:00Z","trust_root":"https://onboarding.guide/api/skills","grant":{"skills":["alpha-skill","fetch-contract@>=1.0.0"],"intents":["fs:read","network:read"],"data_scopes":["ctx:107677460544181387647___skills"],"limits":[["calls_max","100"],["spend_eur_max","0"]]}}`
	if string(got) != want {
		t.Fatalf("canonical bytes drift:\n got=%q\nwant=%q", got, want)
	}
	// Domain separation: the first line MUST be the agentid domain and MUST NOT
	// collide with the other envelope domains.
	if !strings.HasPrefix(string(got), Domain+"\n") {
		t.Fatalf("canonical bytes must start with %q\\n", Domain)
	}
	for _, otherDomain := range []string{"capability_v1", "attestation", "invocation_event_v1", "revoke", "skillctl-revocation-list"} {
		if Domain == otherDomain {
			t.Fatalf("agentid Domain collides with %q", otherDomain)
		}
	}
}

// TestCanonicalDeterministic — the same logical payload yields the same bytes
// regardless of input array ordering (the property signer+verifier rely on).
func TestCanonicalDeterministic(t *testing.T) {
	p1 := samplePayload()
	p2 := samplePayload()
	p2.Grant.Skills = []string{"fetch-contract@>=1.0.0", "alpha-skill"} // different order
	p2.Grant.Intents = []string{"fs:read", "network:read"}
	b1, _ := CanonicalAgentIDBytes(p1)
	b2, _ := CanonicalAgentIDBytes(p2)
	if string(b1) != string(b2) {
		t.Fatalf("canonical bytes not order-independent:\n b1=%q\n b2=%q", b1, b2)
	}
}

func TestCanonicalRejectsNewlineSmuggling(t *testing.T) {
	p := samplePayload()
	p.ID = "agent:9f2c\nowner:id:attacker@evil"
	if _, err := CanonicalAgentIDBytes(p); err == nil {
		t.Fatal("expected error on newline-smuggled field")
	}
}

// TestSignVerifyRoundTrip — issue (sign) → verify against the pinned owner key.
func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := mustKey(t)
	p := samplePayload()
	sig, err := Sign(p, RoleOwner, p.Owner, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	a := &AgentID{Payload: p, Signatures: []Signature{sig}}

	pins := newFakePins()
	pins.pinOwner(p.Owner, pub)

	res, err := Verify(a, VerifyOpts{Pins: pins, Now: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.AgentID != p.ID || res.Owner != p.Owner {
		t.Fatalf("result mismatch: %+v", res)
	}
	if res.ApproverVerified {
		t.Fatal("no approver was signed; ApproverVerified should be false")
	}
}

// TestTamperPayloadFails — flip a grant entry after signing → owner sig fails.
func TestTamperPayloadFails(t *testing.T) {
	pub, priv := mustKey(t)
	p := samplePayload()
	sig, _ := Sign(p, RoleOwner, p.Owner, priv)
	a := &AgentID{Payload: p, Signatures: []Signature{sig}}
	// Tamper: escalate the grant after signing.
	a.Payload.Grant.Skills = append(a.Payload.Grant.Skills, "root-skill")

	pins := newFakePins()
	pins.pinOwner(p.Owner, pub)
	_, err := Verify(a, VerifyOpts{Pins: pins, Now: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)})
	if !errors.Is(err, ErrOwnerSigInvalid) {
		t.Fatalf("want ErrOwnerSigInvalid on tamper, got %v", err)
	}
}

// TestOwnerNotPinnedFails — a valid signature by an UNPINNED owner → exit-11 class.
func TestOwnerNotPinnedFails(t *testing.T) {
	_, priv := mustKey(t)
	p := samplePayload()
	sig, _ := Sign(p, RoleOwner, p.Owner, priv)
	a := &AgentID{Payload: p, Signatures: []Signature{sig}}

	pins := newFakePins() // owner NOT pinned
	_, err := Verify(a, VerifyOpts{Pins: pins, Now: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)})
	if !errors.Is(err, ErrOwnerSigInvalid) {
		t.Fatalf("want ErrOwnerSigInvalid on unpinned owner, got %v", err)
	}
}

// TestWrongKeyFails — owner pinned to a DIFFERENT key than signed → fail.
func TestWrongKeyFails(t *testing.T) {
	_, priv := mustKey(t)
	otherPub, _ := mustKey(t)
	p := samplePayload()
	sig, _ := Sign(p, RoleOwner, p.Owner, priv)
	a := &AgentID{Payload: p, Signatures: []Signature{sig}}

	pins := newFakePins()
	pins.pinOwner(p.Owner, otherPub) // wrong key
	_, err := Verify(a, VerifyOpts{Pins: pins, Now: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)})
	if !errors.Is(err, ErrOwnerSigInvalid) {
		t.Fatalf("want ErrOwnerSigInvalid on wrong key, got %v", err)
	}
}

// TestExpiredIsDistinct — an expired AgentID returns ErrExpired, NOT a sig error.
func TestExpiredIsDistinct(t *testing.T) {
	pub, priv := mustKey(t)
	p := samplePayload()
	p.NotAfter = "2026-01-01T00:00:00Z"
	sig, _ := Sign(p, RoleOwner, p.Owner, priv)
	a := &AgentID{Payload: p, Signatures: []Signature{sig}}

	pins := newFakePins()
	pins.pinOwner(p.Owner, pub)
	_, err := Verify(a, VerifyOpts{Pins: pins, Now: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)})
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
	if errors.Is(err, ErrOwnerSigInvalid) {
		t.Fatal("expired must be DISTINCT from a signature failure")
	}
}

func TestNotYetValid(t *testing.T) {
	pub, priv := mustKey(t)
	p := samplePayload()
	p.CreatedAt = "2027-01-01T00:00:00Z"
	p.NotAfter = ""
	sig, _ := Sign(p, RoleOwner, p.Owner, priv)
	a := &AgentID{Payload: p, Signatures: []Signature{sig}}
	pins := newFakePins()
	pins.pinOwner(p.Owner, pub)
	_, err := Verify(a, VerifyOpts{Pins: pins, Now: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)})
	if !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("want ErrNotYetValid, got %v", err)
	}
}

func TestNoExpiryNeverExpires(t *testing.T) {
	pub, priv := mustKey(t)
	p := samplePayload()
	p.NotAfter = "" // no expiry
	sig, _ := Sign(p, RoleOwner, p.Owner, priv)
	a := &AgentID{Payload: p, Signatures: []Signature{sig}}
	pins := newFakePins()
	pins.pinOwner(p.Owner, pub)
	if _, err := Verify(a, VerifyOpts{Pins: pins, Now: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatalf("no-expiry AgentID should verify far in the future, got %v", err)
	}
}

// TestRevokedOffline — an agent id in the revoked set → ErrRevoked, enforced
// purely from the in-memory set (offline).
func TestRevokedOffline(t *testing.T) {
	pub, priv := mustKey(t)
	p := samplePayload()
	sig, _ := Sign(p, RoleOwner, p.Owner, priv)
	a := &AgentID{Payload: p, Signatures: []Signature{sig}}
	pins := newFakePins()
	pins.pinOwner(p.Owner, pub)
	revoked := map[string]struct{}{NormalizeID(p.ID): {}}
	_, err := Verify(a, VerifyOpts{Pins: pins, Now: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), RevokedAgentIDs: revoked})
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("want ErrRevoked, got %v", err)
	}
}

// ---- approver floor (P1) ----

func signedWithApprover(t *testing.T, p Payload) (*AgentID, *fakePins, ed25519.PublicKey, ed25519.PublicKey) {
	t.Helper()
	ownerPub, ownerPriv := mustKey(t)
	approverPub, approverPriv := mustKey(t)
	ownerSig, _ := Sign(p, RoleOwner, p.Owner, ownerPriv)
	approverSig, _ := Sign(p, RoleApprover, "id:approver@m3c", approverPriv)
	a := &AgentID{Payload: p, Signatures: []Signature{ownerSig, approverSig}}
	pins := newFakePins()
	pins.pinOwner(p.Owner, ownerPub)
	pins.pinApprover("id:approver@m3c", approverPub)
	return a, pins, ownerPub, approverPub
}

func TestApproverFloorMet(t *testing.T) {
	p := samplePayload()
	a, pins, _, _ := signedWithApprover(t, p)
	res, err := Verify(a, VerifyOpts{Pins: pins, RequireApprover: true, Now: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("floor should be met, got %v", err)
	}
	if !res.ApproverVerified || res.Approver != "id:approver@m3c" {
		t.Fatalf("approver not recorded: %+v", res)
	}
}

func TestApproverFloorRefusesOwnerOnly(t *testing.T) {
	pub, priv := mustKey(t)
	p := samplePayload()
	sig, _ := Sign(p, RoleOwner, p.Owner, priv)
	a := &AgentID{Payload: p, Signatures: []Signature{sig}} // owner only
	pins := newFakePins()
	pins.pinOwner(p.Owner, pub)
	_, err := Verify(a, VerifyOpts{Pins: pins, RequireApprover: true, Now: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)})
	if !errors.Is(err, ErrApproverFloor) {
		t.Fatalf("want ErrApproverFloor on owner-only, got %v", err)
	}
}

// TestApproverFloorRefusesApproverEqualsOwner — separation of duty: the approver
// must be a DIFFERENT principal even if the owner signs a second "approver" row.
func TestApproverFloorRefusesApproverEqualsOwner(t *testing.T) {
	ownerPub, ownerPriv := mustKey(t)
	p := samplePayload()
	ownerSig, _ := Sign(p, RoleOwner, p.Owner, ownerPriv)
	// The owner ALSO signs an approver row under their own id.
	selfApprove, _ := Sign(p, RoleApprover, p.Owner, ownerPriv)
	a := &AgentID{Payload: p, Signatures: []Signature{ownerSig, selfApprove}}
	pins := newFakePins()
	pins.pinOwner(p.Owner, ownerPub)
	pins.pinApprover(p.Owner, ownerPub) // even if pinned as approver too
	_, err := Verify(a, VerifyOpts{Pins: pins, RequireApprover: true, Now: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)})
	if !errors.Is(err, ErrApproverFloor) {
		t.Fatalf("want ErrApproverFloor when approver==owner, got %v", err)
	}
}

// TestApproverFloorRefusesUnsignedApproverClaim — an approver row whose key is
// NOT pinned (or whose signature is forged) must NOT satisfy the floor. This is
// the red-team "bypass with an unsigned/self claim" case.
func TestApproverFloorRefusesUnsignedApproverClaim(t *testing.T) {
	ownerPub, ownerPriv := mustKey(t)
	p := samplePayload()
	ownerSig, _ := Sign(p, RoleOwner, p.Owner, ownerPriv)
	// Forge an approver row: claim id:approver@m3c but with a garbage signature.
	forged := Signature{Role: RoleApprover, IdentityID: "id:approver@m3c", SignatureB64: "AAAA"}
	a := &AgentID{Payload: p, Signatures: []Signature{ownerSig, forged}}
	pins := newFakePins()
	pins.pinOwner(p.Owner, ownerPub)
	// approver intentionally NOT pinned
	_, err := Verify(a, VerifyOpts{Pins: pins, RequireApprover: true, Now: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)})
	if !errors.Is(err, ErrApproverFloor) {
		t.Fatalf("want ErrApproverFloor on forged/unpinned approver, got %v", err)
	}
}

// ---- authorization predicate ----

func TestAuthorizeSkill(t *testing.T) {
	g := samplePayload().Grant
	if _, ok := g.AuthorizeSkill("fetch-contract", nil); !ok {
		t.Fatal("fetch-contract should be in grant (by name)")
	}
	if _, ok := g.AuthorizeSkill("fetch-contract@2.0.0", nil); !ok {
		t.Fatal("version-suffixed invoke should match by name")
	}
	if reason, ok := g.AuthorizeSkill("root-skill", nil); ok || reason != "skill_not_in_grant" {
		t.Fatalf("root-skill must be denied, got reason=%q ok=%v", reason, ok)
	}
	if _, ok := g.AuthorizeSkill("fetch-contract", []string{"network:read"}); !ok {
		t.Fatal("granted intent should pass")
	}
	if reason, ok := g.AuthorizeSkill("fetch-contract", []string{"network:write"}); ok || reason != "intent_not_in_grant" {
		t.Fatalf("ungranted intent must be denied, got reason=%q ok=%v", reason, ok)
	}
}

func TestEmptyGrantDeniesEverything(t *testing.T) {
	var g Grant
	if g.AllowsSkill("anything") {
		t.Fatal("empty grant must deny all skills (fail-closed)")
	}
}
