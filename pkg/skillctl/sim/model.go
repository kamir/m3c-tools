// Package sim is the skillctl trust-plane simulation: a generated set of
// multi-principal scenarios, each with a SPEC-derived prediction, executed
// against the REAL skillctl binary and a REAL git registry, and then compared.
//
// Why it exists, stated plainly so nobody mistakes it for a demo. Every gate in
// this system is individually tested. What no test covered is the SEAM: two
// features that are each correct and, together, open a hole. Two such holes were
// found by hand on 2026-09-04 (a revoke silently dropped once a reviewer key was
// pinned, and a false digest-mismatch alarm on a clean install). Both were
// invisible to unit tests because both parts behaved exactly as written. A
// simulation that walks realistic SEQUENCES is the cheapest way to keep finding
// that class of defect.
//
// Three design rules, each of them a correction to the obvious approach:
//
//  1. The oracle is derived from the SPECIFICATION, never from the implementation.
//     If the two disagree, the simulation reports a CONFLICT and a human decides
//     which is wrong. A benchmark whose expectations are read off the code can
//     only catch typos, never a design error.
//
//  2. Scenario COUNT is not the metric; decision COVERAGE is. A hundred runs
//     that exercise six gates prove less than twelve that exercise twenty. The
//     report therefore leads with which (gate, verdict) pairs were never reached.
//
//  3. Attacks we do NOT defend against are part of the corpus, and their expected
//     result is "not defended". A run that reports 100 percent success while
//     quietly omitting the attacks we lose to is marketing, not evidence.
package sim

import "fmt"

// Principal is one human in a scenario. Three is the ceiling on purpose: author,
// publisher/reviewer, consumer is the smallest cast that can express a real
// separation of duties, and every additional principal multiplies runtime without
// adding a new class of trust decision.
type Principal string

const (
	Author    Principal = "author"    // writes and signs the skill
	Publisher Principal = "publisher" // admits into the registry, issues revokes
	Reviewer  Principal = "reviewer"  // attests; may be the publisher or a third person
	Consumer  Principal = "consumer"  // pins, pulls, installs, verifies
	Adversary Principal = "adversary" // not a role in the system: a capability set
)

// ActionKind is one step in a scenario. This is the "useful combinations"
// vocabulary: it is deliberately NOT the closure of every CLI invocation, it is
// the set of moves that occur in the documented user scenarios plus the moves an
// attacker actually has.
type ActionKind string

const (
	// Honest lifecycle.
	ActPackSign  ActionKind = "pack+sign"  // author seals a bundle
	ActAdmit     ActionKind = "admit"      // publisher takes it into the registry
	ActAttest    ActionKind = "attest"     // reviewer signs a governance verdict
	ActPin       ActionKind = "pin"        // consumer pins the registry (and signers)
	ActPull      ActionKind = "pull"       // consumer runs the gauntlet, stages, installs
	ActVerify    ActionKind = "verify"     // consumer re-checks an installed skill
	ActRevoke    ActionKind = "revoke"     // publisher pulls the emergency brake
	ActVerifySig ActionKind = "verify-sig" // anyone checks an author signature offline

	// Adversary capabilities. Each one names what the attacker is assumed to
	// control, because "hacked" is not a threat model.
	ActTamperTransit   ActionKind = "adv:tamper-transit"   // flip bytes in the .skb before the victim sees it
	ActLyingSignature  ActionKind = "adv:lying-signature"  // flip bytes AND rename the sig to match the new digest
	ActForgeAttest     ActionKind = "adv:forge-attest"     // attest with a key nobody pinned
	ActTamperInstalled ActionKind = "adv:tamper-installed" // edit an installed file (same-uid, post-install)
	ActStripRevoke     ActionKind = "adv:strip-revoke"     // hostile registry deletes the revoke event
	ActRelabelRevoke   ActionKind = "adv:relabel-revoke"   // hostile registry renames a revoke to look like an install
	ActStolenKey       ActionKind = "adv:stolen-key"       // attacker holds the publisher's private key
	ActForgeEnvelope   ActionKind = "adv:forge-envelope"   // hostile store rewrites an event's envelope signature
)

// Action is one step with its parameters. Params stay stringly-typed: a scenario
// file has to be readable by a human reviewing what was actually attempted.
type Action struct {
	Kind   ActionKind
	Actor  Principal
	Skill  string
	Params map[string]string
}

func (a Action) String() string {
	if a.Skill == "" {
		return fmt.Sprintf("%s(%s)", a.Kind, a.Actor)
	}
	return fmt.Sprintf("%s(%s, %s)", a.Kind, a.Actor, a.Skill)
}

// Outcome is what the system is expected to do, at the level a human cares about.
type Outcome string

const (
	Accept     Outcome = "accept"      // the operation completes and state changes
	Refuse     Outcome = "refuse"      // the operation is denied, loudly, with a named reason
	NoEffect   Outcome = "no-effect"   // accepted but changes nothing a verdict depends on
	NotClaimed Outcome = "not-claimed" // outside what the trust model promises to stop
)

// Expectation is the SPEC-derived prediction for one action.
//
// Claimed is the honesty field. When false, this scenario exercises an attack the
// threat model does NOT promise to defeat (a stolen signing key, a same-uid edit
// of an unmanaged directory). The run still executes it, and the report lists it
// separately: a refusal there is a bonus, never evidence, and an acceptance is
// not a finding.
type Expectation struct {
	Outcome Outcome
	Gate    string // the gate expected to refuse, e.g. "gate 4"; empty when none
	Exit    int    // expected process exit; -1 means "not pinned by the spec"
	Claimed bool
	Why     string // the SPEC clause this prediction comes from
}

// Invariant is a property that must hold over the WHOLE scenario, checked after
// every step. Exit codes catch what a command says; invariants catch what the
// system became. The two failures found by hand on 2026-09-04 were both invariant
// violations that no single exit code revealed.
type Invariant string

const (
	// INV-1: nothing whose bytes differ from a signed digest is ever installed.
	InvIntegrity Invariant = "INV-1-integrity"
	// INV-2: once a signed revoke for a digest is visible in the registry, that
	// digest is never staged or installed again.
	InvRevocation Invariant = "INV-2-revocation"
	// INV-3: no install without a qualifying attestation from a PINNED signer.
	InvGovernance Invariant = "INV-3-governance"
	// INV-4: every refusal is loud: non-zero exit AND a named gate or reason.
	InvLoudRefusal Invariant = "INV-4-loud-refusal"
	// INV-5: an adversary action never IMPROVES the outcome for the attacker
	// compared with the same scenario without it (no silent downgrade).
	InvNoDowngrade Invariant = "INV-5-no-downgrade"
)

// Scenario is one generated experiment.
type Scenario struct {
	ID         string
	Title      string
	Principals []Principal
	Steps      []Step
	// Tags describe what the scenario is FOR, so the coverage report can group
	// them: "honest", "transit", "registry-hostile", "key-compromise", "post-install".
	Tags []string
	// P is the point in the corpus this scenario came from. The executor needs it
	// to know WHICH key plays which role; the report needs it to group.
	P Params
}

// Step pairs an action with its prediction. Generating the prediction at the same
// time as the action is what makes this a simulation rather than a test suite: the
// theory is written down BEFORE the run, and the run either confirms it or does not.
type Step struct {
	Action Action
	Expect Expectation
}

// StepResult is what actually happened.
type StepResult struct {
	Step     Step
	ExitCode int
	Stdout   string
	Stderr   string
	Gate     string // parsed from the output, e.g. "gate 4"
	Outcome  Outcome
}

// Verdict compares theory with observation.
type Verdict string

const (
	VerdictMatch     Verdict = "MATCH"     // theory and reality agree
	VerdictConflict  Verdict = "CONFLICT"  // they disagree: spec or code is wrong, a human decides
	VerdictUnclaimed Verdict = "UNCLAIMED" // an attack outside the model; recorded, never scored as a win
	VerdictSkipped   Verdict = "SKIPPED"   // the step could not run (missing precondition)
)

// ScenarioResult is one executed scenario.
type ScenarioResult struct {
	Scenario   Scenario
	Steps      []StepResult
	Verdicts   []Verdict
	Violations []InvariantViolation
	Err        string
}

// InvariantViolation is the finding type that matters most. An exit-code mismatch
// is usually a documentation drift; a violated invariant is a hole.
type InvariantViolation struct {
	Invariant Invariant
	Step      int
	Detail    string
}

// Conflicts counts steps where theory and reality disagreed.
func (r ScenarioResult) Conflicts() int {
	n := 0
	for _, v := range r.Verdicts {
		if v == VerdictConflict {
			n++
		}
	}
	return n
}
