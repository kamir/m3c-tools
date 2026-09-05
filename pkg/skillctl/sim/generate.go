package sim

// generate.go builds the corpus: every scenario together with what the
// SPECIFICATION says must happen. The predictions below cite the rule they come
// from, and not one of them was read off the implementation. That is the whole
// point: if the binary disagrees, the report says CONFLICT and a human decides
// which of the two is wrong. Twice already the answer was "the code", and once it
// was "the manual".

import (
	"fmt"
	"sort"
)

// Cast is how many humans share the chain, and which roles they hold. Three is
// the ceiling because three is where the interesting question appears: whether
// the person who RELEASES is the person who WROTE.
type Cast string

const (
	CastSolo Cast = "solo" // one human: author, publisher and reviewer are the same, second machine consumes
	CastDuo  Cast = "duo"  // two humans: an author, and a publisher who also reviews
	CastTrio Cast = "trio" // three humans: author, publisher/reviewer, and a separate consumer
)

// Keying describes the reviewer key question, which is the seam that produced two
// real bugs: whether the reviewer's key differs from the publisher's, and whether
// the consumer pinned it.
type Keying string

const (
	KeyShared       Keying = "shared"        // publisher and reviewer are one key: separation is organisational only
	KeySeparateOpen Keying = "separate-open" // different reviewer key, NOT pinned by the consumer
	KeySeparatePin  Keying = "separate-pin"  // different reviewer key, pinned as a signer
)

// Gov is the governance state at pull time.
type Gov string

const (
	GovGreen  Gov = "green"  // attested at the floor
	GovYellow Gov = "yellow" // attested below a green floor
	GovNone   Gov = "none"   // never attested
)

// AdvKind is the capability exercised, and WHEN. Named AdvKind rather than
// Adversary because Adversary is already the PRINCIPAL: the person, not the move.
type AdvKind string

const (
	AdvNone            AdvKind = "none"
	AdvTransitChecked  AdvKind = "transit-checked"  // bytes flipped before admit, publisher DOES run verify-sig
	AdvTransitSkipped  AdvKind = "transit-skipped"  // same, but the publisher skips the check
	AdvStoredBundle    AdvKind = "stored-bundle"    // artifact swapped in the registry after a clean admit
	AdvForgeAttest     AdvKind = "forge-attest"     // attestation from a key nobody pinned
	AdvStripRevoke     AdvKind = "strip-revoke"     // hostile store deletes the revoke event
	AdvRelabelRevoke   AdvKind = "relabel-revoke"   // hostile store renames the revoke to look like an install
	AdvTamperInstalled AdvKind = "tamper-installed" // same-uid edit of an installed skill
	AdvStolenKey       AdvKind = "stolen-key"       // attacker holds the publisher's private key
	// AdvForgeEnvelope corrupts the ADMIT EVENT's envelope signature in the store.
	// Added because the theory check PROVED gate 1 was unreachable without it: the
	// action alphabet had no move that could set the envelope bit to zero, so no
	// number of scenarios could ever have demonstrated that gate.
	AdvForgeEnvelope AdvKind = "forge-envelope"
)

// Params is one point in the corpus.
type Params struct {
	Cast Cast
	Key  Keying
	Gov  Gov
	Adv  AdvKind
	// Revoke exercises the kill switch after a successful install.
	Revoke bool
}

// Generate enumerates the useful combinations. It is deliberately not the
// mathematical closure: a cross product over every flag would produce thousands
// of runs, most of them the same decision reached twice. The filter below keeps
// the points where a DIFFERENT gate decides, and drops the rest.
func Generate(limit int) []Scenario {
	var out []Scenario
	casts := []Cast{CastSolo, CastDuo, CastTrio}
	keys := []Keying{KeyShared, KeySeparateOpen, KeySeparatePin}
	govs := []Gov{GovGreen, GovYellow, GovNone}
	advs := []AdvKind{
		AdvNone, AdvTransitChecked, AdvTransitSkipped, AdvStoredBundle,
		AdvForgeAttest, AdvStripRevoke, AdvRelabelRevoke, AdvTamperInstalled, AdvStolenKey,
		AdvForgeEnvelope,
	}

	for _, c := range casts {
		for _, k := range keys {
			for _, g := range govs {
				for _, a := range advs {
					for _, rev := range []bool{false, true} {
						p := Params{Cast: c, Key: k, Gov: g, Adv: a, Revoke: rev}
						if !meaningful(p) {
							continue
						}
						out = append(out, build(p))
					}
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if limit > 0 && len(out) > limit {
		// Take a STRIDE, not a prefix. Truncating a sorted list would hand back
		// every scenario whose id starts with "duo" and none of the others, so the
		// sample would silently drop whole regions of the space while still
		// reporting the requested count.
		stride := float64(len(out)) / float64(limit)
		sampled := make([]Scenario, 0, limit)
		for i := 0; i < limit; i++ {
			sampled = append(sampled, out[int(float64(i)*stride)])
		}
		out = sampled
	}
	return out
}

// meaningful drops combinations that cannot teach anything new.
func meaningful(p Params) bool {
	// A revoke only says something once there is something to revoke, and the
	// revoke-suppression attacks only make sense together with a revoke.
	needsRevoke := p.Adv == AdvStripRevoke || p.Adv == AdvRelabelRevoke
	if needsRevoke && !p.Revoke {
		return false
	}
	// INVARIANT R1, decided by the operator on 2026-09-05: a revoke presupposes a
	// release. Nothing installs without governance, so a kill switch would have no
	// subject. This is a statement about the PROCESS, not a convenience: it is why
	// the three states 11001, 11011 and 11101 are never visited, and it belongs in
	// the model rather than in a footnote on a poster.
	if p.Revoke && p.Gov != GovGreen {
		return false
	}
	// A shared key cannot express "the reviewer key was not pinned": there is only
	// one key, and it is the registry pin.
	if p.Key == KeyShared && p.Adv == AdvForgeAttest {
		return true // still meaningful: a foreign key attests against a single-key pin
	}
	// The post-install tamper needs an install to exist.
	if p.Adv == AdvTamperInstalled && p.Gov != GovGreen {
		return false
	}
	// A stolen key with no governance never gets far enough to be interesting.
	if p.Adv == AdvStolenKey && p.Gov == GovNone {
		return false
	}
	// INVARIANT R2, a SEPARATE reason from R1 and often confused with it. The
	// envelope forgery is decided by the FIRST gate, so the other axes cannot change
	// the outcome and would only add duplicate rows. This, not R1, is why 00011 and
	// 01011 are never visited: those two are NOT revoked (their revoked bit is zero),
	// they carry a broken envelope together with broken governance. A reviewer caught
	// this being described as one reason on 2026-09-05, by recomputing the bits.
	if p.Adv == AdvForgeEnvelope && (p.Gov != GovGreen || p.Key != KeySeparatePin) {
		return false
	}
	// The transit attacks are about the publisher's own discipline; the governance
	// axis adds nothing there, so pin it to green and drop the rest.
	if (p.Adv == AdvTransitChecked || p.Adv == AdvTransitSkipped) && p.Gov != GovGreen {
		return false
	}
	// The cast only changes WHO holds which key; combined with KeyShared, duo and
	// trio collapse onto solo for every adversary except none.
	if p.Key == KeyShared && p.Cast != CastSolo && p.Adv != AdvNone {
		return false
	}
	// There used to be a rule here that dropped a revoke variant whenever the pull
	// was going to refuse anyway, on the grounds that the extra step is a duplicate.
	// It is removed, and the reason is worth keeping.
	//
	// That rule pruned by OUTCOME. The corpus is a state-coverage instrument, and
	// two points with the same outcome can sit in different states: a revoked bundle
	// with a broken envelope (01111) refuses exactly like an unrevoked one with a
	// broken envelope (00111), yet only the first one asks the question this whole
	// exercise is about, which is WHICH gate speaks first when two of them have
	// something to say. Pruning by outcome deleted the only point that can catch a
	// gate-ORDER regression, and the measurement showed it: state coverage fell from
	// 7 of 12 to 6 of 12 while the design got broader.
	//
	// So meaningful() now encodes only IMPOSSIBILITY: what the world cannot produce
	// (R1, R2, and the structural rules above). Economy is no longer its job, because
	// the covering array does that better and says out loud how much it dropped. That
	// division did not exist before the design was introduced; one function was doing
	// both, and the cheap half was quietly eating the expensive half.
	return true
}

// installExpected is the per-step prediction for a pull. It does NOT reimplement
// the decision; it ASKS the analytic model, so there is exactly one place where
// the theory lives.
//
// It used to be a second hand-written switch, and that cost a lesson worth keeping:
// when the envelope forgery was added to the state mapping, this function was not
// updated, and the two halves of the same theory quietly disagreed. Every scenario
// with that capability then predicted "accept" while the model said "gate 1". The
// covering array found all seven within a minute of being switched on, which is
// precisely what a designed experiment is for and what the hand-picked sample had
// missed. Deleting the duplicate is the actual fix; noticing it was luck.
func installExpected(p Params) (ok bool, gate string, why string) {
	accept, g := StateAt(p, false).Decide()
	if accept {
		return true, "", "SPEC-0188 §7: every gate passes"
	}
	return false, g, whyGate(g, p)
}

// whyGate names the SPEC clause behind a refusal, so a conflict report tells the
// reader which rule the prediction came from rather than only that it was wrong.
func whyGate(gate string, p Params) string {
	switch gate {
	case "gate 1":
		return "SPEC-0188 §7: the admit envelope no longer verifies against the pinned key"
	case "gate 5":
		return "SPEC-0188 §7: a revoked digest is refused before governance is even consulted"
	case "gate 4":
		switch {
		case p.Gov == GovNone:
			return "SPEC-0188 §7: no attestation at or above the governance floor"
		case p.Gov == GovYellow:
			return "SPEC-0252 §6: yellow is below a green floor; the floor is enforced, not advisory"
		case p.Key == KeySeparateOpen:
			return "SPEC-0359 D3: an attestation counts only from a PINNED signer"
		}
		return "the attestation is bound to the pre-tamper digest, so the admitted bytes have no governance"
	case "gate 2":
		return "SPEC-0188 §7: the digest is recomputed from the bytes, never taken from the store"
	case "gate 3":
		return "SPEC-0188 §7: the bundle signature rows do not verify"
	}
	return "SPEC-0188 §7"
}

func build(p Params) Scenario {
	id := fmt.Sprintf("S-%s-%s-%s-%s%s", p.Cast, p.Key, p.Gov, p.Adv, map[bool]string{true: "-rev", false: ""}[p.Revoke])
	sc := Scenario{
		ID:         id,
		Title:      title(p),
		Principals: castPrincipals(p.Cast),
		Tags:       []string{string(p.Cast), string(p.Key), string(p.Gov), string(p.Adv)},
		P:          p,
	}
	skill := "simskill"

	// 1. The author seals. Always accepted: sealing is a local act, nothing gates it.
	sc.Steps = append(sc.Steps, Step{
		Action: Action{Kind: ActPackSign, Actor: Author, Skill: skill},
		Expect: Expectation{Outcome: Accept, Exit: 0, Claimed: true,
			Why: "sealing is local; no trust decision is involved"},
	})

	// 2. Transit tampering happens between the author and the publisher.
	switch p.Adv {
	case AdvTransitChecked:
		sc.Steps = append(sc.Steps,
			Step{Action: Action{Kind: ActTamperTransit, Actor: Adversary, Skill: skill},
				Expect: Expectation{Outcome: NoEffect, Exit: -1, Claimed: true,
					Why: "the attacker controls the artifact, not the key"}},
			// The publisher's own check is the control here. Without a matching
			// signature file the verifier cannot even find one: exit 1, not 11.
			Step{Action: Action{Kind: ActVerifySig, Actor: Publisher, Skill: skill},
				Expect: Expectation{Outcome: Refuse, Exit: 1, Claimed: true,
					Why: "SPEC-0188 §11: the signature filename carries the digest, so altered bytes have no signature at all"}},
		)
	case AdvTransitSkipped:
		sc.Steps = append(sc.Steps,
			Step{Action: Action{Kind: ActTamperTransit, Actor: Adversary, Skill: skill},
				Expect: Expectation{Outcome: NoEffect, Exit: -1, Claimed: true,
					Why: "the attacker controls the artifact, not the key"}},
		)
	}

	// 3. Admit. With a stolen key the ATTACKER performs it, and the chain that
	// follows is internally consistent: this is the case the model does not claim
	// to stop, and saying so is the point of including it.
	admitActor := Publisher
	admitClaim := true
	admitWhy := "the publisher takes responsibility by admitting"
	if p.Adv == AdvStolenKey {
		admitActor = Adversary
		admitClaim = false
		admitWhy = "THREAT MODEL LIMIT: a stolen signing key produces a valid chain. The answer is revocation after detection, not prevention"
	}
	sc.Steps = append(sc.Steps, Step{
		Action: Action{Kind: ActAdmit, Actor: admitActor, Skill: skill},
		Expect: Expectation{Outcome: Accept, Exit: 0, Claimed: admitClaim, Why: admitWhy},
	})

	// 4. Governance.
	if p.Gov != GovNone {
		sc.Steps = append(sc.Steps, Step{
			Action: Action{Kind: ActAttest, Actor: Reviewer, Skill: skill,
				Params: map[string]string{"level": string(p.Gov)}},
			Expect: Expectation{Outcome: Accept, Exit: 0, Claimed: true,
				Why: "posting an attestation is not itself gated; what it is WORTH is decided at pull time"},
		})
	}
	if p.Adv == AdvForgeAttest {
		sc.Steps = append(sc.Steps, Step{
			Action: Action{Kind: ActForgeAttest, Actor: Adversary, Skill: skill},
			Expect: Expectation{Outcome: Accept, Exit: 0, Claimed: true,
				Why: "anyone may WRITE an attestation; only a pinned signer's counts"},
		})
	}

	// 5a. The envelope forgery: the store rewrites the signature on the admit event.
	if p.Adv == AdvForgeEnvelope {
		sc.Steps = append(sc.Steps, Step{
			Action: Action{Kind: ActForgeEnvelope, Actor: Adversary, Skill: skill},
			Expect: Expectation{Outcome: NoEffect, Exit: -1, Claimed: true,
				Why: "a hostile store can rewrite the bytes of an event; it cannot re-sign it"},
		})
	}

	// 5. The artifact swap happens after a clean admit.
	if p.Adv == AdvStoredBundle {
		sc.Steps = append(sc.Steps, Step{
			Action: Action{Kind: ActTamperTransit, Actor: Adversary, Skill: skill,
				Params: map[string]string{"where": "registry"}},
			Expect: Expectation{Outcome: NoEffect, Exit: -1, Claimed: true,
				Why: "a hostile store can swap bytes; it cannot make them hash to the signed digest"},
		})
	}

	// 6. The consumer pins, then pulls.
	sc.Steps = append(sc.Steps, Step{
		Action: Action{Kind: ActPin, Actor: Consumer, Skill: skill},
		Expect: Expectation{Outcome: Accept, Exit: 0, Claimed: true,
			Why: "SPEC-0359 D2: the pin is refused unless the fingerprint matches, so a successful pin is itself a check"},
	})

	ok, gate, why := installExpected(p)
	pullExpect := Expectation{Outcome: Accept, Exit: 0, Claimed: true, Why: why}
	if !ok {
		pullExpect = Expectation{Outcome: Refuse, Gate: gate, Exit: 1, Claimed: true, Why: why}
	}
	if p.Adv == AdvStolenKey && ok {
		pullExpect.Claimed = false
		pullExpect.Why = "THREAT MODEL LIMIT: the chain is valid because the attacker holds the key"
	}
	sc.Steps = append(sc.Steps, Step{
		Action: Action{Kind: ActPull, Actor: Consumer, Skill: skill},
		Expect: pullExpect,
	})

	// 7. Re-verification of what was installed.
	if ok {
		if p.Adv == AdvTamperInstalled {
			sc.Steps = append(sc.Steps,
				Step{Action: Action{Kind: ActTamperInstalled, Actor: Adversary, Skill: skill},
					Expect: Expectation{Outcome: NoEffect, Exit: -1, Claimed: true,
						Why: "a same-uid attacker can edit the files; the question is whether the next check notices"}},
				Step{Action: Action{Kind: ActVerify, Actor: Consumer, Skill: skill},
					Expect: Expectation{Outcome: Refuse, Exit: 10, Claimed: true,
						Why: "SPEC-0266: the installed body is bound to the signed bundle, so an edit is a digest mismatch"}},
			)
		} else {
			sc.Steps = append(sc.Steps, Step{
				Action: Action{Kind: ActVerify, Actor: Consumer, Skill: skill},
				Expect: Expectation{Outcome: Accept, Exit: 0, Claimed: true,
					Why: "a clean managed install re-verifies offline against the pinned key"},
			})
		}
	}

	// 8. The kill switch.
	if p.Revoke && ok {
		sc.Steps = append(sc.Steps, Step{
			Action: Action{Kind: ActRevoke, Actor: Publisher, Skill: skill},
			Expect: Expectation{Outcome: Accept, Exit: 0, Claimed: true,
				Why: "a revoke is bound to a digest and is issued by the registry key"},
		})
		switch p.Adv {
		case AdvStripRevoke:
			sc.Steps = append(sc.Steps,
				Step{Action: Action{Kind: ActStripRevoke, Actor: Adversary, Skill: skill},
					Expect: Expectation{Outcome: NoEffect, Exit: -1, Claimed: true,
						Why: "the store can withhold; whether that is detectable is the next line"}},
				Step{Action: Action{Kind: ActPull, Actor: Consumer, Skill: skill},
					Expect: Expectation{Outcome: Accept, Exit: 0, Claimed: false,
						Why: "THREAT MODEL LIMIT: withholding is not detectable on a plain git registry. Detection needs the transparency log (SPEC-0278 L1) or a freshness contract; neither is in this path"}},
			)
		case AdvRelabelRevoke:
			sc.Steps = append(sc.Steps,
				Step{Action: Action{Kind: ActRelabelRevoke, Actor: Adversary, Skill: skill},
					Expect: Expectation{Outcome: NoEffect, Exit: -1, Claimed: true,
						Why: "the filename is an unsigned projection the store controls"}},
				Step{Action: Action{Kind: ActPull, Actor: Consumer, Skill: skill},
					Expect: Expectation{Outcome: Refuse, Gate: "gate 5", Exit: 1, Claimed: true,
						Why: "FR-0090 IS-T1: identity comes from the SIGNED envelope, never from the path, so a relabelled revoke still revokes"}},
			)
		default:
			// Ask the model for the SECOND pull too, rather than assuming gate 5.
			// With a broken envelope, gate 1 speaks first and the revoke never gets
			// a turn: assuming otherwise is exactly the mistake this function used
			// to make.
			_, g2 := StateAt(p, true).Decide()
			sc.Steps = append(sc.Steps, Step{
				Action: Action{Kind: ActPull, Actor: Consumer, Skill: skill},
				Expect: Expectation{Outcome: Refuse, Gate: g2, Exit: 1, Claimed: true,
					Why: whyGate(g2, p)},
			})
		}
	}
	return sc
}

func title(p Params) string {
	return fmt.Sprintf("%s cast, %s reviewer key, governance %s, adversary %s", p.Cast, p.Key, p.Gov, p.Adv)
}

func castPrincipals(c Cast) []Principal {
	switch c {
	case CastSolo:
		return []Principal{Author, Consumer}
	case CastDuo:
		return []Principal{Author, Publisher, Consumer}
	default:
		return []Principal{Author, Publisher, Reviewer, Consumer}
	}
}
