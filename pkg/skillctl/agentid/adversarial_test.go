package agentid

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

// adversarial_test.go — explicit red-team coverage for the SPEC-0277 challenge
// gate: forge/replay, grant escalation, approver-floor bypass, revocation
// evasion, and cross-domain signature reuse. Each is a property the design
// promises; each test pins it so a regression that re-opens the hole fails CI.

var fixedNow = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

// TestAdversarial_CrossDomainAttestationReplay — a signature produced over the
// SPEC-0188 ATTESTATION domain ("attestation\n<digest>\n<level>\n...") must NOT
// verify as an AgentID owner signature, even though the SAME key signs both. The
// distinct "agentid_v1" first line is the guard.
func TestAdversarial_CrossDomainAttestationReplay(t *testing.T) {
	pub, priv := mustKey(t)
	p := samplePayload()

	// Forge: sign the bytes of a DIFFERENT envelope family (an attestation-shaped
	// message) and splice that signature into the AgentID's owner row.
	attestationLikeBytes := []byte("attestation\nsha256:" +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\ngreen\n2026-06-22T10:00:00Z\nid:kamir@m3c\n")
	crossSig := ed25519.Sign(priv, attestationLikeBytes)
	a := &AgentID{
		Payload: p,
		Signatures: []Signature{{
			Role: RoleOwner, IdentityID: p.Owner,
			SignatureB64: base64.StdEncoding.EncodeToString(crossSig),
		}},
	}
	pins := newFakePins()
	pins.pinOwner(p.Owner, pub)
	if _, err := Verify(a, VerifyOpts{Pins: pins, Now: fixedNow}); !errors.Is(err, ErrOwnerSigInvalid) {
		t.Fatalf("cross-domain attestation signature must NOT verify as an AgentID owner sig, got %v", err)
	}
}

// TestAdversarial_CrossDomainRevocationReplay — a signature over the SPEC-0276
// revocation-list domain must not verify as an AgentID owner sig either.
func TestAdversarial_CrossDomainRevocationReplay(t *testing.T) {
	pub, priv := mustKey(t)
	p := samplePayload()
	revListLike := []byte(`{"type":"skillctl-revocation-list","version":1,"registry_url":"https://onboarding.guide/api/skills"}`)
	crossSig := ed25519.Sign(priv, revListLike)
	a := &AgentID{
		Payload: p,
		Signatures: []Signature{{
			Role: RoleOwner, IdentityID: p.Owner,
			SignatureB64: base64.StdEncoding.EncodeToString(crossSig),
		}},
	}
	pins := newFakePins()
	pins.pinOwner(p.Owner, pub)
	if _, err := Verify(a, VerifyOpts{Pins: pins, Now: fixedNow}); !errors.Is(err, ErrOwnerSigInvalid) {
		t.Fatalf("cross-domain revocation signature must NOT verify as an AgentID owner sig, got %v", err)
	}
}

// TestAdversarial_AgentIDSigDoesNotCollideWithOtherDomains — the inverse: the
// bytes a valid AgentID is signed over MUST start with the agentid domain and
// MUST NOT be reinterpretable as any other family's message (they all begin with
// a different first token). This is a structural assertion on the canonical bytes.
func TestAdversarial_DomainPrefixIsExclusive(t *testing.T) {
	b, err := CanonicalAgentIDBytes(samplePayload())
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if len(s) < len(Domain)+1 || s[:len(Domain)+1] != Domain+"\n" {
		t.Fatalf("canonical bytes must begin with the agentid domain line")
	}
	for _, foreign := range []string{"attestation\n", "capability_v1\n", "invocation_event_v1\n", "revoke\n"} {
		if len(s) >= len(foreign) && s[:len(foreign)] == foreign {
			t.Fatalf("agentid canonical bytes collide with foreign domain prefix %q", foreign)
		}
	}
}

// TestAdversarial_GrantEscalationDetected — adding ANY skill to the grant after
// signing breaks verification (the grant is inside the signed canonical bytes).
func TestAdversarial_GrantEscalationDetected(t *testing.T) {
	pub, priv := mustKey(t)
	p := samplePayload()
	sig, _ := Sign(p, RoleOwner, p.Owner, priv)
	a := &AgentID{Payload: p, Signatures: []Signature{sig}}
	pins := newFakePins()
	pins.pinOwner(p.Owner, pub)

	// Sanity: verifies before tampering.
	if _, err := Verify(a, VerifyOpts{Pins: pins, Now: fixedNow}); err != nil {
		t.Fatalf("baseline verify failed: %v", err)
	}
	// Escalate intents (a different field than the earlier grant.skills tamper test).
	a.Payload.Grant.Intents = append(a.Payload.Grant.Intents, "network:write")
	if _, err := Verify(a, VerifyOpts{Pins: pins, Now: fixedNow}); !errors.Is(err, ErrOwnerSigInvalid) {
		t.Fatalf("intent escalation must break the owner signature, got %v", err)
	}
}

// TestAdversarial_OwnerImpersonationViaRow — a signature row whose identity_id
// differs from the payload owner cannot launder a valid signature by a different
// pinned principal into "owner authorization".
func TestAdversarial_OwnerRowMustMatchPayloadOwner(t *testing.T) {
	pub, priv := mustKey(t)
	p := samplePayload()
	sig, _ := Sign(p, RoleOwner, "id:someone-else@m3c", priv)
	a := &AgentID{Payload: p, Signatures: []Signature{sig}}
	pins := newFakePins()
	pins.pinOwner("id:someone-else@m3c", pub) // a pinned principal, but NOT the payload owner
	if _, err := Verify(a, VerifyOpts{Pins: pins, Now: fixedNow}); !errors.Is(err, ErrOwnerSigInvalid) {
		t.Fatalf("owner row identity != payload owner must be refused, got %v", err)
	}
}

// TestAdversarial_RevocationEvasionByOmission — the offline revocation set is
// authoritative; an attacker cannot evade it by relying on the AgentID itself
// (which has no revocation field). The gate/CLI supplies the verified set.
func TestAdversarial_RevocationStillBindsWithValidSignature(t *testing.T) {
	pub, priv := mustKey(t)
	p := samplePayload()
	sig, _ := Sign(p, RoleOwner, p.Owner, priv)
	a := &AgentID{Payload: p, Signatures: []Signature{sig}}
	pins := newFakePins()
	pins.pinOwner(p.Owner, pub)
	// Even a perfectly valid mandate is denied once its id is in the revoked set.
	revoked := map[string]struct{}{NormalizeID(p.ID): {}}
	if _, err := Verify(a, VerifyOpts{Pins: pins, Now: fixedNow, RevokedAgentIDs: revoked}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("a validly-signed but revoked agent must be denied, got %v", err)
	}
}

// TestAdversarial_ApproverFloorCaseTwins — the approver != owner check is
// case-normalized, so an attacker cannot satisfy "approver != owner" by merely
// re-casing the owner id in the approver row (and signing with the owner key).
func TestAdversarial_ApproverFloorCaseTwins(t *testing.T) {
	ownerPub, ownerPriv := mustKey(t)
	p := samplePayload() // owner = id:kamir@m3c
	ownerSig, _ := Sign(p, RoleOwner, p.Owner, ownerPriv)
	// Re-cased "approver" that is really the owner.
	twin := "ID:KAMIR@M3C"
	approverSig, _ := Sign(p, RoleApprover, twin, ownerPriv)
	a := &AgentID{Payload: p, Signatures: []Signature{ownerSig, approverSig}}
	pins := newFakePins()
	pins.pinOwner(p.Owner, ownerPub)
	pins.pinApprover(twin, ownerPub) // even if the case-twin is pinned as approver
	if _, err := Verify(a, VerifyOpts{Pins: pins, RequireApprover: true, Now: fixedNow}); !errors.Is(err, ErrApproverFloor) {
		t.Fatalf("case-twin owner-as-approver must NOT satisfy the floor, got %v", err)
	}
}
