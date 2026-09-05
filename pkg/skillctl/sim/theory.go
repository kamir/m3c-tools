package sim

// theory.go checks the SPECIFICATION on its own, before any binary is involved.
//
// This is the step that matters most and is usually skipped. A simulation that
// only compares a model with an implementation can confirm that the two agree
// while both are wrong. Checking the model FIRST, against properties it must have
// by itself, is a different and stronger act: it can fail with no code running.
//
// It is possible here for one reason: the state vector is five bits, so the state
// space has 32 points and can be enumerated EXHAUSTIVELY. What follows are not
// samples and not estimates. They are complete statements over the whole space,
// which is as close to a proof as this kind of artifact gets.
//
// Four questions are asked, in the order in which a wrong answer would invalidate
// the rest:
//
//  1. TOTALITY. Does the decision function produce an answer in every state?
//     A state with no verdict is a specification hole: the system would have to
//     invent behaviour there, and every implementation would invent a different one.
//
//  2. ENTAILMENT. Do the safety invariants FOLLOW from the gate composition?
//     This is the question the whole trust story rests on. If accepting a state
//     does not imply "the digest matched", then the composition is missing a gate,
//     and no amount of testing an implementation would reveal that: the code would
//     faithfully implement an unsafe specification.
//
//  3. REACHABILITY. Which of the 32 states can the action alphabet actually
//     produce? An unreachable state is either a missing adversary capability (the
//     model claims a situation the corpus cannot create) or an over-parameterised
//     model (a bit that never varies independently).
//
//  4. CORPUS COVERAGE. Of the reachable states, which does the corpus visit?
//     This is the honest denominator for coverage, far better than counting gates:
//     it is measured against what is POSSIBLE, not against what happened.

import (
	"fmt"
	"io"
	"sort"
)

// AllStates enumerates the complete state space. Five independent bits, 32 points.
func AllStates() []State {
	var out []State
	for i := 0; i < 32; i++ {
		out = append(out, State{
			EnvelopeSigned: i&1 != 0,
			Revoked:        i&2 != 0,
			GovQualifies:   i&4 != 0,
			DigestMatches:  i&8 != 0,
			SigsVerify:     i&16 != 0,
		})
	}
	return out
}

// Key renders a state as a fixed-width bit string, so two reports can be diffed.
func (s State) Key() string {
	b := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	return b(s.EnvelopeSigned) + b(s.Revoked) + b(s.GovQualifies) + b(s.DigestMatches) + b(s.SigsVerify)
}

// StateLegend names the bit order once, so a reader of a report does not have to
// guess which column is which.
const StateLegend = "bits: envelope, revoked, governance, digest, signatures"

// TheoryFinding is one problem with the specification itself.
type TheoryFinding struct {
	Kind   string // "totality" | "entailment" | "reachability"
	State  string
	Detail string
}

// TheoryReport is the result of checking the model without any implementation.
type TheoryReport struct {
	Total       int
	Decided     int
	Accepting   []string
	Findings    []TheoryFinding
	Reachable   map[string]bool
	Unreachable []string
}

// CheckTheory runs the four questions over the complete state space.
func CheckTheory(corpus []Scenario) TheoryReport {
	rep := TheoryReport{Reachable: map[string]bool{}}

	for _, s := range AllStates() {
		rep.Total++
		accept, gate := s.Decide()

		// 1. TOTALITY. Every state must yield either an acceptance or a NAMED gate.
		// An unnamed refusal is as bad as no answer: the operator cannot act on it
		// and two implementations would report it differently.
		if !accept && gate == "" {
			rep.Findings = append(rep.Findings, TheoryFinding{"totality", s.Key(),
				"the state refuses but names no gate: the specification does not say why"})
			continue
		}
		rep.Decided++
		if !accept {
			continue
		}
		rep.Accepting = append(rep.Accepting, s.Key())

		// 2. ENTAILMENT. Acceptance must IMPLY each safety invariant. Checked here
		// against the state itself rather than against a run, because that is the
		// difference between "we did not observe a violation" and "a violation
		// cannot be expressed in this model".
		if !s.DigestMatches {
			rep.Findings = append(rep.Findings, TheoryFinding{"entailment", s.Key(),
				"INV-1: the composition accepts a state whose artifact does not match the signed digest"})
		}
		if s.Revoked {
			rep.Findings = append(rep.Findings, TheoryFinding{"entailment", s.Key(),
				"INV-2: the composition accepts a state that carries a visible revoke"})
		}
		if !s.GovQualifies {
			rep.Findings = append(rep.Findings, TheoryFinding{"entailment", s.Key(),
				"INV-3: the composition accepts a state with no qualifying attestation"})
		}
		if !s.EnvelopeSigned || !s.SigsVerify {
			rep.Findings = append(rep.Findings, TheoryFinding{"entailment", s.Key(),
				"INV-1: the composition accepts a state whose signatures do not verify"})
		}
	}

	// 3. REACHABILITY. Which states can the action alphabet produce at all?
	for _, p := range allParams() {
		rep.Reachable[StateAt(p, false).Key()] = true
		if p.Revoke {
			rep.Reachable[StateAt(p, true).Key()] = true
		}
	}
	for _, s := range AllStates() {
		if !rep.Reachable[s.Key()] {
			rep.Unreachable = append(rep.Unreachable, s.Key())
		}
	}
	sort.Strings(rep.Unreachable)
	return rep
}

// allParams is the full factor space, before the usefulness filter. Reachability
// has to be judged against everything the model CAN express, not against the
// subset a corpus happens to select.
func allParams() []Params {
	var out []Params
	for _, c := range []Cast{CastSolo, CastDuo, CastTrio} {
		for _, k := range []Keying{KeyShared, KeySeparateOpen, KeySeparatePin} {
			for _, g := range []Gov{GovGreen, GovYellow, GovNone} {
				for _, a := range []AdvKind{AdvNone, AdvTransitChecked, AdvTransitSkipped,
					AdvStoredBundle, AdvForgeAttest, AdvStripRevoke, AdvRelabelRevoke,
					AdvTamperInstalled, AdvStolenKey, AdvForgeEnvelope} {
					for _, r := range []bool{false, true} {
						out = append(out, Params{Cast: c, Key: k, Gov: g, Adv: a, Revoke: r})
					}
				}
			}
		}
	}
	return out
}

// CorpusStates is the set of states a given corpus actually visits.
func CorpusStates(corpus []Scenario) map[string]bool {
	seen := map[string]bool{}
	for _, sc := range corpus {
		seen[StateAt(sc.P, false).Key()] = true
		if sc.P.Revoke {
			seen[StateAt(sc.P, true).Key()] = true
		}
	}
	return seen
}

// WriteTheory renders the specification check. It runs with no binary present,
// which is the point: a broken specification should be caught before anybody
// writes code against it.
func (rep TheoryReport) WriteTheory(w io.Writer, corpus []Scenario) {
	fmt.Fprintf(w, "\ntheory check: the specification on its own, no implementation involved\n")
	fmt.Fprintf(w, "  state space  : %d states, exhaustively enumerated (%s)\n", rep.Total, StateLegend)
	fmt.Fprintf(w, "  totality     : %d of %d states yield a named verdict\n", rep.Decided, rep.Total)
	fmt.Fprintf(w, "  accepting    : %d states (%v)\n", len(rep.Accepting), rep.Accepting)

	entail := 0
	for _, f := range rep.Findings {
		if f.Kind == "entailment" {
			entail++
		}
	}
	if entail == 0 {
		fmt.Fprintf(w, "  entailment   : every accepting state satisfies INV-1, INV-2 and INV-3\n")
		fmt.Fprintf(w, "                 Proven over the whole space, not sampled: a violating state\n")
		fmt.Fprintf(w, "                 cannot be expressed by this composition.\n")
	} else {
		fmt.Fprintf(w, "  entailment   : %d VIOLATION(S). The specification itself is unsafe.\n", entail)
	}

	reach := len(rep.Reachable)
	fmt.Fprintf(w, "  reachability : %d of %d states are producible by the action alphabet\n", reach, rep.Total)
	if len(rep.Unreachable) > 0 {
		fmt.Fprintf(w, "                 unreachable: %v\n", rep.Unreachable)
		fmt.Fprintf(w, "                 Each one is either a missing adversary capability or a bit\n")
		fmt.Fprintf(w, "                 the model varies without the world being able to.\n")
	}

	if len(corpus) > 0 {
		seen := CorpusStates(corpus)
		covered, missing := 0, []string{}
		for k := range rep.Reachable {
			if seen[k] {
				covered++
			} else {
				missing = append(missing, k)
			}
		}
		sort.Strings(missing)
		fmt.Fprintf(w, "  corpus       : visits %d of %d reachable states (%.0f%%)\n",
			covered, reach, 100*float64(covered)/float64(max(reach, 1)))
		if len(missing) > 0 {
			fmt.Fprintf(w, "                 never visited: %v\n", missing)
		}
	}

	if len(rep.Findings) > 0 {
		fmt.Fprintf(w, "\n  SPECIFICATION FINDINGS\n")
		for _, f := range rep.Findings {
			fmt.Fprintf(w, "    [%s] state %s: %s\n", f.Kind, f.State, f.Detail)
		}
	}
	fmt.Fprintln(w)
}

// Sound reports whether the specification passed its own check. Entailment and
// totality are hard failures; unreachable states are reported, never fatal, since
// an over-parameterised model is a modelling smell rather than an unsafe one.
func (rep TheoryReport) Sound() bool {
	for _, f := range rep.Findings {
		if f.Kind == "entailment" || f.Kind == "totality" {
			return false
		}
	}
	return true
}
