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
	if p.Revoke && p.Gov != GovGreen {
		// Nothing installs without governance, so the kill switch has no subject.
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
	// A revoke only adds steps when something was installed to revoke. Where the
	// pull is expected to refuse anyway, the -rev variant is a byte-identical
	// duplicate of its sibling: pure corpus inflation, and exactly the kind of
	// padding that makes a benchmark look broader than it is.
	if p.Revoke {
		if ok, _, _ := installExpected(p); !ok {
			return false
		}
	}
	return true
}

// installExpected is the theory for the honest path: does the consumer end up
// with the skill installed, and if not, which gate refused?
//
// GATE ORDER matters and is easy to get wrong. The pull applies, in this order:
// envelope signature, revoked, governance floor, digest, bundle signatures
// (SPEC-0188 §7 as the gauntlet implements it). The FIRST gate that refuses is
// the one the report shows, so a scenario that would fail two gates only ever
// demonstrates the earlier one.
//
// This function was WRONG on its first draft in two ways, and the run said so.
// Both corrections are kept visible here rather than quietly patched, because the
// point of the exercise is that writing the theory is where you find out what you
// did not understand:
//
//  1. It predicted the digest gate for a swapped artifact even when governance
//     was also failing. Governance comes FIRST, so the digest gate is only
//     reachable when the attestation is otherwise sound.
//  2. It predicted that a forged attestation blocks the install. It does not: a
//     forgery from an unpinned key is simply not counted, and the GENUINE
//     attestation next to it still qualifies. A forgery removes nothing.
func installExpected(p Params) (ok bool, gate string, why string) {
	switch {
	// Governance is evaluated before the digest, so it wins whenever both fail.
	case p.Gov == GovNone:
		return false, "gate 4", "SPEC-0188 §7: no attestation at or above the governance floor"
	case p.Gov == GovYellow:
		return false, "gate 4", "SPEC-0252 §6: yellow is below a green floor; the floor is enforced, not advisory"
	case p.Key == KeySeparateOpen:
		return false, "gate 4", "SPEC-0359 D3: an attestation counts only from a PINNED signer"

	// Tampering in transit changes the bytes BEFORE the admit, so the publisher
	// admits a different digest than the one the reviewer attested. The refusal
	// therefore arrives at the governance gate, not at the digest gate: there is
	// no attestation for the digest that was actually admitted. Worth stating
	// plainly, because the intuitive answer ("digest mismatch") is wrong and the
	// real one is stronger, the binding between an attestation and a digest does
	// the work.
	case p.Adv == AdvTransitChecked || p.Adv == AdvTransitSkipped:
		return false, "gate 4", "the attestation is bound to the pre-tamper digest, so the admitted bytes have no governance"

	// A swapped artifact AFTER a clean admit is the digest gate's own case: the
	// events are sound, only the bytes are not.
	case p.Adv == AdvStoredBundle:
		return false, "gate 2", "SPEC-0188 §7: the digest is recomputed from the bytes, never taken from the store"
	}
	return true, "", "SPEC-0188 §7: every gate passes"
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
			sc.Steps = append(sc.Steps, Step{
				Action: Action{Kind: ActPull, Actor: Consumer, Skill: skill},
				Expect: Expectation{Outcome: Refuse, Gate: "gate 5", Exit: 1, Claimed: true,
					Why: "SPEC-0188 §7: a revoked digest is refused before governance is even consulted"},
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
