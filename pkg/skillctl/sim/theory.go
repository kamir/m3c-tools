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
//  2. COMPOSITION COMPLETENESS. Does every safety-relevant predicate actually
//     appear in the accepting condition?
//
//     This check was originally called ENTAILMENT and announced as a proof that
//     the safety invariants follow from the composition. An external reviewer took
//     that claim apart on 2026-09-05 and was right: as long as the invariants are
//     stated in terms of the SAME five bits the gates test, "accepting implies the
//     invariants" reduces to "the conjunction of five conditions implies those five
//     conditions". Circular, and therefore worthless as a safety proof.
//
//     What the check really does, and all it may claim: it detects a MISSING GATE.
//     Delete the revoked predicate from the composition and some accepting state
//     will carry Revoked=true, and this check fires with no code running. That is
//     genuinely useful and it is genuinely not a proof of safety.
//
//     A real entailment proof needs invariants formulated over the WORLD (the bytes
//     on disk, the keys a human pinned, the events a registry holds), independent of
//     the predicates the gauntlet happens to read. That model does not exist yet;
//     saying so is more useful than a circular claim dressed as a theorem.
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

		// 2. COMPOSITION COMPLETENESS, not entailment. See the package comment: with
		// the invariants written over the same bits the gates read, this cannot prove
		// safety. It proves something narrower and still worth having: that no
		// safety-relevant predicate has fallen OUT of the accepting condition.
		if !s.DigestMatches {
			rep.Findings = append(rep.Findings, TheoryFinding{"completeness", s.Key(),
				"the accepting condition no longer contains the digest predicate"})
		}
		if s.Revoked {
			rep.Findings = append(rep.Findings, TheoryFinding{"completeness", s.Key(),
				"the accepting condition no longer contains the revoked predicate"})
		}
		if !s.GovQualifies {
			rep.Findings = append(rep.Findings, TheoryFinding{"completeness", s.Key(),
				"the accepting condition no longer contains the governance predicate"})
		}
		if !s.EnvelopeSigned || !s.SigsVerify {
			rep.Findings = append(rep.Findings, TheoryFinding{"completeness", s.Key(),
				"the accepting condition no longer contains a signature predicate"})
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
// allParams enumerates the whole factor space. It reads the shared axis lists,
// because it used to keep a fourth copy of them and that copy is how a newly added
// adversary reached the corpus, the design and the model while remaining invisible
// to the enumeration: the run reported eleven moves on its axis line and zero
// scenarios carrying the eleventh.
func allParams() []Params {
	var out []Params
	for _, c := range AllCasts() {
		for _, k := range AllKeyings() {
			for _, g := range AllGovs() {
				for _, a := range AllAdvKinds() {
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
		// The post-revoke state counts only when the scenario ACTUALLY pulls a
		// second time. It used to be counted whenever the revoke PARAMETER was
		// set, and that overstated the coverage: build() attaches the revoke steps
		// only where the first install succeeds, so a scenario whose pull is
		// refused carries Revoke=true and never revokes anything. Its post-revoke
		// state was reported as visited on the strength of a flag.
		//
		// A coverage figure has to be derived from what the corpus RUNS, never from
		// what its parameters imply, or it measures the generator's intentions.
		if pulls(sc) > 1 {
			seen[StateAt(sc.P, true).Key()] = true
		}
	}
	return seen
}

// pulls counts the pull steps in a scenario: the number of decisions it puts to
// the gauntlet, which is what a state visit is made of.
func pulls(sc Scenario) int {
	n := 0
	for _, st := range sc.Steps {
		if st.Action.Kind == ActPull {
			n++
		}
	}
	return n
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
		if f.Kind == "completeness" {
			entail++
		}
	}
	if entail == 0 {
		fmt.Fprintf(w, "  completeness : the accepting condition still contains all five predicates\n")
		fmt.Fprintf(w, "                 Checked over the whole space. This detects a DELETED gate; it is\n")
		fmt.Fprintf(w, "                 NOT a safety proof: the invariants are written over the same bits\n")
		fmt.Fprintf(w, "                 the gates read, so a stronger claim would be circular.\n")
	} else {
		fmt.Fprintf(w, "  completeness : %d PREDICATE(S) missing from the accepting condition.\n", entail)
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
		if f.Kind == "completeness" || f.Kind == "totality" {
			return false
		}
	}
	return true
}

// --- classifying the unreachable states -----------------------------------
//
// An external reviewer put the sharpest finding of 2026-09-05 like this: the
// poster calls the distinction between the two causes of unreachability "the
// actual work", then demonstrates it on two of twenty states and stops. Correct.
// A count of unreachable states is not an analysis; the analysis is the REASON,
// per state, and it has to be mechanical rather than anecdotal.
//
// Two causes, and they lead to opposite actions:
//
//	MISSING-MOVE     no action in the alphabet can set this bit combination.
//	                 The hole is in the CORPUS. Add the capability. This is how
//	                 forge-envelope came to exist.
//	STRUCTURAL       the combination cannot occur in the world at all, because
//	                 one fact forces another. Nothing to add, and nothing to
//	                 defend against on this path: the answer is that a different
//	                 ACTOR would be needed.
//
// THIS PARAGRAPH USED TO STATE A STRUCTURAL RULE, and it was wrong.
//
// It said: the signature rows live inside the signed envelope, so sig=0 implies
// env=0, so every state with sig=0 and env=1 is structurally impossible and gate 3
// sits entirely inside that region. The run refutes it. 10010 and 11010 are
// reachable with exactly that pattern, and 10110, the one state where gate 3
// speaks, is reachable and visited.
//
// The rule was true when it was written, before the alphabet contained a publisher
// who can re-seal what he altered, and nothing forced it to be re-derived when the
// alphabet grew. That is the whole lesson: a claim about the world, parked in a
// comment, does not notice when the world changes. Unreachability is now derived
// mechanically from the alphabet, and no structural claim is made here at all. If
// one is wanted, it belongs in a specification where it can be reviewed.

// UnreachReason classifies one unreachable state.
type UnreachReason struct {
	State  string
	Kind   string // "structural" | "missing-move"
	Detail string
}

// ClassifyUnreachable gives a reason for EVERY unreachable state, so the count
// becomes an argument. A state this function cannot explain is reported as
// missing-move with the bits that no action varies, which is the honest default:
// absence of an explanation is not evidence of impossibility.
// ClassifyUnreachable says WHY each unreachable state is unreachable, and it
// derives the answer from the action alphabet instead of asserting it.
//
// The previous version pattern-matched two bits and printed a sentence: any state
// with sig=0 and env=1 was called "structural", because breaking the signature
// rows was supposed to break the envelope with them. An IEEE 1012 reviewer showed
// on 2026-09-05 that the run refuted its own rule: 10010 and 11010 are REACHABLE
// with exactly that bit pattern, and 10110 is not only reachable but visited. The
// sentence had been true when written, before the malicious publisher existed as a
// move, and nothing forced it to be re-derived when the alphabet grew.
//
// So it is derived now. Every point of the FULL factor space is mapped to its
// state; a state nobody produces is a missing move, and a state produced only by
// points the corpus excludes is named with the rule that excluded it and with the
// KIND of that rule. That last distinction is the one that matters to a reader:
// "the world cannot produce this" and "we left it out" are different sentences,
// and only one of them is a property of the system.
//
// The class "structural" is gone. It claimed a property of the artifact format,
// which is a statement about the world that this enumeration cannot make. If such
// a claim is wanted it belongs in a specification, where it can be reviewed.
func ClassifyUnreachable(rep TheoryReport) []UnreachReason {
	// Which points of the full space produce which state, and whether any of them
	// is admissible.
	producedBy := map[string][]Params{}
	for _, p := range allParams() {
		producedBy[StateAt(p, false).Key()] = append(producedBy[StateAt(p, false).Key()], p)
		if p.Revoke {
			producedBy[StateAt(p, true).Key()] = append(producedBy[StateAt(p, true).Key()], p)
		}
	}

	var out []UnreachReason
	for _, k := range rep.Unreachable {
		points := producedBy[k]
		if len(points) == 0 {
			out = append(out, UnreachReason{k, "missing-move",
				"no point of the factor space maps to this state: the action alphabet " +
					"has no move that produces this combination"})
			continue
		}
		// Every producing point is excluded. Name the rule, and say which kind it is.
		rule, kind := "", ExclusionKind("")
		for _, p := range points {
			if ex := excludedBy(p); ex != nil {
				rule, kind = ex.Rule, ex.Kind
				if ex.Kind == KindImpossible {
					break // an impossibility outranks an economy cut as the reason
				}
			}
		}
		if kind == KindImpossible {
			out = append(out, UnreachReason{k, "rule-impossible",
				"produced only by points the world cannot realise: " + rule})
		} else {
			out = append(out, UnreachReason{k, "rule-economy",
				"produced by points the world CAN realise, left out of the corpus by: " + rule +
					". This is a judgement, not a property"})
		}
	}
	return out
}

// WriteUnreachable prints the classification. It leads with the counts because the
// ratio is the point: a space that is mostly STRUCTURAL is a system statement, one
// that is mostly MISSING-MOVE is a to-do list.
func (rep TheoryReport) WriteUnreachable(w io.Writer) {
	cls := ClassifyUnreachable(rep)
	byKind := map[string]int{}
	for _, c := range cls {
		byKind[c.Kind]++
	}
	fmt.Fprintf(w, "\nwhy the unreachable states are unreachable\n")
	fmt.Fprintf(w, "  %d no move in the alphabet, %d excluded as impossible, %d excluded for economy\n",
		byKind["missing-move"], byKind["rule-impossible"], byKind["rule-economy"])
	for _, c := range cls {
		fmt.Fprintf(w, "  %-6s %-13s %s\n", c.State, c.Kind, c.Detail)
	}
	fmt.Fprintf(w, "  A missing-move entry is a to-do, not a property. It stays provisional until\n")
	fmt.Fprintf(w, "  somebody either adds the capability or proves the combination impossible.\n")
}
