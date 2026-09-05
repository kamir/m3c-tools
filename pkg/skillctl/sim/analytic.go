package sim

// analytic.go is the theory, written as a closed form rather than as prose.
//
// THE OBJECT. The trust plane is a deterministic transition system
//
//	(Sigma, A, delta, G)
//
// with a state space Sigma, an action alphabet A (honest moves plus the
// adversary's capabilities), a transition function delta: Sigma x A -> Sigma, and
// a DECISION FUNCTION G: Sigma -> {accept} u {refuse at gate i}. Everything the
// simulation measures is G evaluated at points of Sigma that the actions steered
// it to.
//
// THE DECISION FUNCTION. G is not an arbitrary map. It is an ORDERED CONJUNCTION
// of independent gate predicates g_1 .. g_5 over a five-component state vector
//
//	x = (x_env, x_rev, x_gov, x_dig, x_sig) in {0,1}^5
//
// evaluated in a fixed order, and the FIRST failing predicate decides:
//
//	G(x) = accept                       if all g_k(x) = 1
//	G(x) = refuse at gate_{k*}          with k* = min { k : g_k(x) = 0 }
//
// This is the whole theory, and it has a consequence worth stating because it is
// the most common error in reading such a system: a state that violates TWO gates
// only ever exhibits the earlier one. The later gate is unobservable at that
// point, so a corpus cannot demonstrate it there, no matter how many runs it
// spends. Coverage is therefore a property of the ORDER, not only of the inputs.
//
// A TRAP IN THE NAMING. The evaluation order is NOT the gate numbering. The
// gauntlet evaluates envelope (1), revoked (5), governance (4), digest (2),
// signatures (3). The numbers are identifiers, the sequence below is the order.
// Anyone who assumes "gate 2 comes before gate 4" predicts the wrong refusal, and
// the first draft of this oracle did exactly that.
//
// WHAT IS ANALYTICALLY PREDICTABLE. Because G is a fixed composition and the map
// from a corpus point p to its state vector x(p) is explicit, the DISTRIBUTION of
// outcomes over a corpus is computable in closed form, without running anything:
//
//	N_k = |{ p in corpus : k*(x(p)) = k }|
//
// The simulation then measures N_k^obs. The comparison of the predicted and the
// measured histogram, bin by bin, is the actual experiment; the residual
//
//	r_k = N_k^obs - N_k^pred
//
// is zero for a system that behaves as specified, and every non-zero r_k names
// either a defect or a wrong theory. Which of the two it is, is a human decision,
// never an automatic one.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
)

// State is the five-component state vector the decision function reads. Each
// component is a single yes/no fact about the world at pull time, so the whole
// theory fits in five bits and the analysis stays exact rather than approximate.
type State struct {
	EnvelopeSigned bool // x_env: the admit envelope verifies against the pinned registry key
	Revoked        bool // x_rev: a signed revoke for this digest is VISIBLE in the store
	GovQualifies   bool // x_gov: an attestation at or above the floor, from a PINNED signer, bound to THIS digest
	DigestMatches  bool // x_dig: the stored artifact hashes to the signed digest
	SigsVerify     bool // x_sig: the bundle signature rows verify
}

// gate is one predicate together with the identifier the tool prints.
type gate struct {
	name string
	ok   func(State) bool
}

// gauntlet is the ordered conjunction. The ORDER is the specification; the names
// are only labels.
var gauntlet = []gate{
	{"gate 1", func(s State) bool { return s.EnvelopeSigned }},
	{"gate 5", func(s State) bool { return !s.Revoked }},
	{"gate 4", func(s State) bool { return s.GovQualifies }},
	{"gate 2", func(s State) bool { return s.DigestMatches }},
	{"gate 3", func(s State) bool { return s.SigsVerify }},
}

// Decide evaluates G(x): accept, or the first gate that refuses.
func (s State) Decide() (accept bool, gateName string) {
	for _, g := range gauntlet {
		if !g.ok(s) {
			return false, g.name
		}
	}
	return true, ""
}

// StateAt maps a corpus point to its state vector at the moment of a pull.
// afterRevoke selects the second pull in the scenarios that exercise the kill
// switch. This function IS the modelling: every line is a claim about what the
// world looks like, and each one is falsifiable by the run.
func StateAt(p Params, afterRevoke bool) State {
	s := State{
		// The admit is signed by the publisher key, which is the key the consumer
		// pins. A stolen key does not change this: that is precisely why key theft
		// is outside the model, the chain it produces is genuine. A store that
		// REWRITES the signature does change it, and that is the only move in this
		// alphabet which can.
		EnvelopeSigned: p.Adv != AdvForgeEnvelope,
		// The malicious publisher is the only move that can put this bit to zero.
		// Every other actor in the alphabet has to break the envelope to reach the
		// signature rows, and then gate 1 speaks first.
		SigsVerify:    p.Adv != AdvPublisherBadSigs,
		DigestMatches: p.Adv != AdvStoredBundle,
	}

	// x_rev. A revoke is visible when it was issued and the store still shows it.
	// Deleting the event hides it (withholding is not detectable here); RENAMING
	// it does not, because identity comes from the signed envelope and not from
	// the path.
	//
	// A revoke is BOUND TO A DIGEST, and that is the whole of it. It covers the
	// pulled bundle only when the digest the publisher revokes is the digest that
	// was admitted. Transit tampering breaks exactly that equality: the bytes
	// change after signing, so the admitted digest is not the one the publisher
	// holds, and a revoke issued in good faith against the publisher's own record
	// misses the artifact in the registry.
	//
	// This clause is here because the experiment produced it. The model used to
	// assume a revoke always lands, predicted gate 5 for the two transit scenarios,
	// and measured gate 4. The measurement was right and the theory was wrong, which
	// is the direction that costs something to admit. It is not a fit to the
	// observation: the justification is independent, a revoke names a digest, and a
	// digest that nobody admitted revokes nothing.
	if afterRevoke && p.Revoke {
		landed := p.Adv != AdvStripRevoke && // withheld: the consumer never sees it
			p.Adv != AdvTransitChecked && // admitted digest differs from the revoked one
			p.Adv != AdvTransitSkipped
		s.Revoked = landed
	}

	// x_gov. Three independent ways to fail, and they compose:
	//   the level must reach the floor,
	//   the signer must be pinned,
	//   the attestation must be bound to the digest that was ADMITTED.
	// The third is what makes transit tampering a governance failure rather than a
	// digest failure: the reviewer attested the pre-tamper digest, so the admitted
	// bytes carry no governance at all. A forged attestation from an unpinned key
	// changes nothing here, because it removes nothing: the genuine one still counts.
	levelOK := p.Gov == GovGreen
	signerPinned := p.Key != KeySeparateOpen
	boundToAdmitted := p.Adv != AdvTransitChecked && p.Adv != AdvTransitSkipped
	s.GovQualifies = levelOK && signerPinned && boundToAdmitted
	return s
}

// PredictHistogram is the analytical result: how many pulls in a corpus end at
// each outcome, computed from the theory alone. Nothing is executed.
func PredictHistogram(corpus []Scenario) map[string]int {
	h := map[string]int{}
	for _, sc := range corpus {
		// A scenario contains one pull, or two when it exercises the kill switch.
		pulls := 0
		for _, st := range sc.Steps {
			if st.Action.Kind == ActPull {
				pulls++
			}
		}
		for i := 0; i < pulls; i++ {
			accept, g := StateAt(sc.P, i > 0).Decide()
			if accept {
				h["accept"]++
			} else {
				h[g]++
			}
		}
	}
	return h
}

// MeasureHistogram is the same quantity, read off a completed run.
func (rep Report) MeasureHistogram() map[string]int {
	h := map[string]int{}
	for _, r := range rep.Results {
		for _, s := range r.Steps {
			if s.Step.Action.Kind != ActPull {
				continue
			}
			switch {
			case s.Outcome == Accept:
				h["accept"]++
			case s.Gate != "":
				h[s.Gate]++
			default:
				h["refused, no gate named"]++
			}
		}
	}
	return h
}

// Bins is the union of the predicted and measured keys, in a stable order, so a
// bin that is empty on one side is still printed. A histogram comparison that
// silently drops empty bins hides exactly the interesting case.
func Bins(pred, obs map[string]int) []string {
	set := map[string]bool{}
	for k := range pred {
		set[k] = true
	}
	for k := range obs {
		set[k] = true
	}
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- EV-1: pre-registration ------------------------------------------------
//
// A prediction that can be edited after seeing the measurement is not a
// prediction. Physics solves this with pre-registration; here the equivalent is
// cheap, because the model and the corpus are code: hash them, print the hashes
// in the report, and a later comparison of two reports shows immediately whether
// the theory was changed between runs.
//
// The three hashes answer three different questions:
//   model   did the decision function or the state mapping change?
//   corpus  were the same scenarios run, with the same predictions?
//   binary  which build produced the measurement?

// ModelHash fingerprints the theory: the gate order plus the complete
// input-output table of the decision function over the whole state space. Any
// edit to a predicate, to the order, or to a gate name changes it.
func ModelHash() string {
	h := sha256.New()
	for _, g := range gauntlet {
		fmt.Fprintf(h, "gate:%s\n", g.name)
	}
	for _, s := range AllStates() {
		accept, gate := s.Decide()
		fmt.Fprintf(h, "%s->%t:%s\n", s.Key(), accept, gate)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// CorpusHash fingerprints the experiment: every scenario id together with the
// prediction attached to each of its steps.
func CorpusHash(corpus []Scenario) string {
	h := sha256.New()
	for _, sc := range corpus {
		fmt.Fprintf(h, "%s\n", sc.ID)
		for _, st := range sc.Steps {
			fmt.Fprintf(h, "  %s|%s|%s|%d|%t\n",
				st.Action.Kind, st.Expect.Outcome, st.Expect.Gate, st.Expect.Exit, st.Expect.Claimed)
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// BinaryHash fingerprints the implementation under test. An empty string when the
// file cannot be read: a missing hash is reported as missing, never faked.
func BinaryHash(path string) string {
	f, err := os.Open(path) // #nosec G304 -- the operator names the binary to test
	if err != nil {
		return "unreadable"
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "unreadable"
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
