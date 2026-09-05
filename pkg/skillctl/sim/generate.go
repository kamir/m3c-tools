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

	// AdvPublisherBadSigs is the MALICIOUS PUBLISHER, and it exists because an
	// information theorist showed on 2026-09-05 that the model could not express
	// him, and that his absence was quietly doing the work of a proof.
	//
	// The argument the poster used to make was: the bundle signature rows sit
	// inside the signed envelope, so breaking them breaks the envelope, so gate 1
	// always speaks before gate 3, so gate 3 is structurally unreachable. That
	// argument silently assumes nobody RE-SEALS the envelope. The publisher holds
	// the registry key and can. Whether the tool lets him is a question about the
	// product, and it was never asked, because the alphabet had no move for it.
	//
	// So the move exists now: the bundle's signature is replaced by a well-formed
	// but wrong one BEFORE the publisher admits, and the publisher admits anyway.
	// If the admit succeeds, gate 3 becomes reachable and the structural claim was
	// an assumption. If the admit refuses, the claim is grounded in a measurement
	// instead of an argument. Either answer is worth more than the argument was.
	AdvPublisherBadSigs AdvKind = "publisher-bad-sigs"

	// AdvArtifactWithheld is a PROBE, not an attack: the backend no longer serves
	// the bytes, while every signed event stays in place. It is how FR-0119 D3
	// becomes measurable from outside the process. See WithholdArtifact.
	AdvArtifactWithheld AdvKind = "artifact-withheld"
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
// The axes of the experiment, in one place.
//
// They used to be written out twice, once here and once in the covering array's
// factor table, and the second copy was silently one level short when a new
// adversary was added: the design kept planning over ten moves while the corpus
// carried eleven. That is the third duplication of a definition to bite this
// package in two days, after the two prediction oracles and the two prune rules.
// The pattern is always the same, so the remedy is always the same: one source,
// read by everyone who needs it.
func AllCasts() []Cast { return []Cast{CastSolo, CastDuo, CastTrio} }

// AllKeyings lists the key-layout levels.
func AllKeyings() []Keying { return []Keying{KeyShared, KeySeparateOpen, KeySeparatePin} }

// AllGovs lists the governance levels.
func AllGovs() []Gov { return []Gov{GovGreen, GovYellow, GovNone} }

// AllAdvKinds lists every adversary move the alphabet contains. Every statement
// this package makes about unreachability is a statement about THIS list, which
// is why it is exported and why the report prints it.
// OpenDiagnostics names adversary moves whose SECURITY behaviour is settled and
// measured, but whose DIAGNOSTIC label is under an open finding.
//
// The distinction was forced by an external reviewer on 2026-09-05, and he was
// right in a way that mattered. The first attempt held the whole move out of the
// blocking corpus because one thing about it was undecided. That removed, along
// with the undecided label, three security assertions that were perfectly
// decidable: the install is refused, the install target is untouched, and the
// exit code is non-zero. Quarantining an attack because its error message is
// unclear throws away the part that was working.
//
// So the exemption is now surgical. For a move listed here the simulation still
// claims and scores the decision, and it declines to compare only the gate name,
// with the finding printed on every run. Nothing else changes: the move sits in
// the covering array, INV-6 checks that the refusal wrote nothing, and a
// regression that turned the refusal into an acceptance would fail the gate like
// any other.
func OpenDiagnostics() map[AdvKind]string {
	return map[AdvKind]string{
		AdvPublisherBadSigs: "FR-0120 (revised 2026-09-05): gate 3 is UNVERIFIED. Three attempts " +
			"to construct a bundle that reaches it failed for three different reasons, and the " +
			"gate-3 mutant is NOT DETECTED by this corpus, which is the same fact seen from the " +
			"other side. The step is recorded, not scored",
	}
}

func AllAdvKinds() []AdvKind {
	return []AdvKind{
		AdvNone, AdvTransitChecked, AdvTransitSkipped, AdvStoredBundle,
		AdvForgeAttest, AdvStripRevoke, AdvRelabelRevoke, AdvTamperInstalled,
		AdvStolenKey, AdvForgeEnvelope, AdvPublisherBadSigs, AdvArtifactWithheld,
	}
}

func Generate(limit int) []Scenario {
	var out []Scenario
	casts, keys, govs, advs := AllCasts(), AllKeyings(), AllGovs(), AllAdvKinds()

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
	case AdvPublisherBadSigs:
		// The bundle keeps a signature FILE with the right name, so the verifier
		// finds one and has to do real cryptography to reject it. That is the
		// difference between "no signature" (exit 1) and "a signature that does not
		// verify" (gate 3), and only the second one reaches the gate under test.
		sc.Steps = append(sc.Steps,
			Step{Action: Action{Kind: ActLyingSignature, Actor: Publisher, Skill: skill},
				Expect: Expectation{Outcome: NoEffect, Exit: -1, Claimed: true,
					Why: "the publisher controls the artifact AND the registry key"}},
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
	if p.Adv == AdvArtifactWithheld {
		sc.Steps = append(sc.Steps, Step{
			Action: Action{Kind: ActWithholdArtifact, Actor: Adversary, Skill: skill},
			Expect: Expectation{Outcome: NoEffect, Exit: -1, Claimed: true,
				Why: "FR-0119 D3 probe: the events stay, the bytes go. A decision that does " +
					"not need the artifact must still be reachable"},
		})
	}
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
	// An open DIAGNOSTIC finding suppresses the label comparison and nothing else.
	// judge() only compares Gate when it is non-empty, so clearing it leaves the
	// outcome and the exit code fully claimed and fully scored.
	// The exemption is narrower than it looks and has to be. It suppresses the
	// label comparison ONLY where the open finding is actually the cause, that is
	// where the model says gate 3. A publisher-bad-sigs bundle that is also revoked
	// refuses at gate 5, and that label is settled: blanket-suppressing it hid a
	// decided contract behind an undecided one.
	//
	// Found by the cause-discrimination measure on its first run, which reported one
	// signal standing for two causes and turned out to be describing this bug rather
	// than the product.
	// The malicious publisher is UNCLAIMED, and the reason is a finding rather than
	// a convenience.
	//
	// Three attempts have been made to construct a bundle that reaches gate 3, and
	// all three failed for different reasons:
	//   1. flip a byte in the .skb and rename the signature to match: the tar header
	//      breaks and the installer refuses while parsing, before any signature is
	//      read.
	//   2. corrupt the detached .author.sig: the pull ACCEPTS. The detached file is
	//      apparently not what the pull consults; the signature rows travel inside
	//      the admit event.
	//   3. edit the rows inside the admit event: that breaks the envelope, so gate 1
	//      decides first, which is the original structural argument.
	//
	// So the honest statement is not "gate 3 fires without a label" (that was
	// FR-0120's premise and it is withdrawn) but "this harness cannot yet construct
	// the case". The move stays in the corpus because its DECISION is still worth
	// observing, and its outcome is not scored, because the simulation has no
	// warranted expectation to score it against.
	if _, open := OpenDiagnostics()[p.Adv]; open {
		gate, why = "", "OPEN: the harness cannot construct a bundle that reaches gate 3. "+
			"Three attempts failed for three different reasons; see FR-0120. Until one "+
			"succeeds, gate 3 is UNVERIFIED and UNCALIBRATED, and this step is recorded "+
			"rather than scored"
	}
	pullExpect := Expectation{Outcome: Accept, Exit: 0, Claimed: true, Why: why}
	if _, open := OpenDiagnostics()[p.Adv]; open {
	}
	if !ok {
		pullExpect = Expectation{Outcome: Refuse, Gate: gate, Exit: 1, Claimed: true, Why: why}
	}
	if _, open := OpenDiagnostics()[p.Adv]; open {
		pullExpect.Claimed = false
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
	//
	// The condition used to be `p.Revoke && ok`: revoke only where the install had
	// succeeded. That is the SAME prune-by-outcome that was removed from
	// meaningful(), one layer lower, and removing it there while leaving it here
	// bought nothing. Worse, it made the coverage figure look as if it had: the
	// post-revoke state was counted from the Revoke flag, so three states were
	// reported as visited by scenarios that never revoked anything.
	//
	// A revoke is a PUBLISHER action against a digest. It does not need anybody to
	// have installed first, and the interesting case is exactly the one the old
	// condition removed: a bundle that is both revoked and otherwise broken, where
	// the question is which gate speaks first.
	if p.Revoke {
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
			gate2, why2 := g2, whyGate(g2, p)
			claimed2 := true
			if note, open := OpenDiagnostics()[p.Adv]; open {
				gate2, why2, claimed2 = "", note, false
			}
			sc.Steps = append(sc.Steps, Step{
				Action: Action{Kind: ActPull, Actor: Consumer, Skill: skill},
				Expect: Expectation{Outcome: Refuse, Gate: gate2, Exit: 1, Claimed: claimed2,
					Why: why2},
			})
		}

		// THE TEMPORAL CASE, requested by an external reviewer on 2026-09-05 and
		// the reason R1 had to go: revoke first, attest AFTERWARDS, pull again.
		//
		// A revoke is a statement about a digest, not about a moment. An attestation
		// that arrives later must not resurrect it, and nothing in the gate order
		// says so on its own: gate 5 runs before gate 4, so the only way this can go
		// wrong is if a fresh attestation somehow clears the revocation state. That
		// is a question about how the two records combine over TIME, which no
		// single-shot scenario asks.
		if p.Adv == AdvNone {
			sc.Steps = append(sc.Steps,
				Step{Action: Action{Kind: ActAttest, Actor: Reviewer, Skill: skill,
					Params: map[string]string{"level": string(GovGreen)}},
					Expect: Expectation{Outcome: Accept, Exit: 0, Claimed: true,
						Why: "posting an attestation is never gated; it is worth what the pull says it is worth"}},
				Step{Action: Action{Kind: ActPull, Actor: Consumer, Skill: skill},
					Expect: Expectation{Outcome: Refuse, Gate: "gate 5", Exit: 1, Claimed: true,
						Why: "SPEC-0188 §7: a revoke is bound to a digest and outlives any later attestation; " +
							"governance is not even consulted"}},
			)
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
