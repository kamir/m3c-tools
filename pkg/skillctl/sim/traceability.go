package sim

// traceability.go answers the question an IEEE 1012 reviewer asks first and which
// this package could not answer until 2026-09-05: for every claim the run makes,
// WHERE DOES IT COME FROM, and how do you know?
//
// The standard calls for bidirectional traceability, requirement to test to
// result. What existed instead was a set of assertions whose provenance lived in
// comments and in the author's head. That is enough to find defects, which it
// did, and not enough for anybody else to judge what was actually checked.
//
// The matrix is GENERATED, not maintained. A traceability document that is edited
// by hand drifts from the code the same way the poster drifted from the corpus,
// and for the same reason: nothing forces it to stay true. Here the origin sits
// next to the assertion it describes, a test asserts that every gate and every
// invariant appears exactly once, and the report prints the whole table with the
// measured counts beside it.

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Provenance says how a rule got into the model. The four values are the ones the
// operator asked for on 2026-09-05, and the distinction between the middle two is
// the one that decides what a green run is worth.
type Provenance string

const (
	// ProvNormative: the rule is written in a specification. A failure is a defect
	// in the product.
	ProvNormative Provenance = "normativ"
	// ProvDerived: the rule follows from a stated property, with the derivation
	// written down. A failure is a defect, but the derivation is arguable and the
	// argument is part of the evidence.
	ProvDerived Provenance = "abgeleitet"
	// ProvObserved: the rule was read off the running system. A failure means the
	// behaviour CHANGED, not that it is wrong. This is a characterisation test and
	// it must never be reported as conformance.
	ProvObserved Provenance = "beobachtet"
	// ProvAdopted: accepted as a requirement on this project's own record, from a
	// review, and NOT yet written into any specification. It binds here and it has
	// no clause behind it, which is a different standing from both normativ and
	// abgeleitet. It existed as a category before it had a name: two invariants
	// carried the mark "normativ" while their own footnote said "not in SPEC-0188",
	// and an IEEE 1012 reviewer called that a category error on 2026-09-05.
	ProvAdopted Provenance = "uebernommen"
	// ProvOpen: the rule is under an undecided question. It is checked, and what
	// its result means is not yet settled.
	ProvOpen Provenance = "ungeklaert"
)

// TraceItem is one checkable claim with its origin.
type TraceItem struct {
	ID     string     // "gate 4", "INV-7"
	What   string     // what is asserted, in one line
	Source string     // the specification clause, the decision, or the observation
	Prov   Provenance // how it got here
	Note   string     // the caveat a reader needs, empty when there is none
}

// TraceMatrix is the whole set. Order is fixed so two reports are comparable.
//
// THE SOURCES WERE WRONG UNTIL 2026-09-05, and the correction is worth keeping.
// Every gate cited "SPEC-0188 §7". An adversarial review traced the actual path
// and found that §7 governs the ER1/HTTP install (`pkg/skillctl/install`), whose
// first two steps are literally `/api/skills/by-name` and `GET
// /api/skills/bundles/<digest>`. The path this simulation measures, `pull
// --trust-mode`, is specified in SPEC-0225 §9.1, "The verification gauntlet
// (every bundle, every install)", and that clause lists exactly these five
// checks and closes with "Only a bundle that clears all five gets written".
//
// The five gates were therefore never unspecified, as an earlier finding of mine
// claimed. They were specified in the other document, and the code comment
// "runs the SPEC-0188 §7 gauntlet" sent everybody, me included, to the wrong
// clause. A traceability matrix whose sources point at the wrong specification is
// worse than one with no sources: it looks checked.
//
// Every entry here was written by reading the clause or the decision it cites. An
// entry whose Source cannot be checked by a reader is worse than no entry, because
// it looks like provenance and is not.
func TraceMatrix() []TraceItem {
	return []TraceItem{
		{
			ID: "gate 1", What: "the admit envelope signature verifies against a key in trust-roots whose id matches the producing registry",
			Source: "SPEC-0225 §9.1 step 1", Prov: ProvNormative,
		},
		{
			ID: "gate 2", What: "SHA-256 of the fetched .skb equals the digest tag and the envelope's bundle_digest",
			Source: "SPEC-0225 §9.1 step 2", Prov: ProvNormative,
		},
		{
			ID: "gate 3", What: "the author AND registry signatures on the .skb each verify against trust-roots",
			Source: "SPEC-0225 §9.1 step 3", Prov: ProvNormative,
			Note: "observed once, by name, since 2026-09-06. Reaching it needs a publisher " +
				"holding the registry key: a store without it cannot edit a signature row " +
				"without breaking the envelope, so gate 1 would decide first",
		},
		{
			ID: "gate 4", What: "a quorum of attestations at or above the floor, from pinned signers, bound to the admitted digest",
			Source: "SPEC-0225 §9.1 step 4, SPEC-0359 D3", Prov: ProvNormative,
		},
		{
			ID: "gate 5", What: "no BundleRevokedEvent exists for this digest",
			Source: "SPEC-0225 §9.1 step 5", Prov: ProvNormative,
		},
		{
			ID: "order: phases", What: "authenticate, then decide from signed metadata, then decide from bytes",
			Source: "FR-0119 D1, derived from the data dependencies in backend_pull.go", Prov: ProvDerived,
			Note: "DECISION OPEN: proposed, not yet normative in SPEC-0188. Checked as characterisation until it is",
		},
		{
			ID: "order: 5 before 4", What: "a revoked bundle reports the revoke, not the missing governance",
			Source: "FR-0119 D2, decided 2026-09-05", Prov: ProvNormative,
			Note: "diagnosis contract; its justification (\"the more actionable statement\") is a " +
				"fitness-for-use argument, and it depends on the phase model still open under D1",
		},
		{
			ID: "order: 2 before 3", What: "wrong bytes are reported as the cause, not the signature that follows from them",
			Source: "FR-0119 D2, decided 2026-09-05", Prov: ProvNormative,
			Note: "diagnosis contract; depends on the phase model under D1",
		},
		{
			ID: "verb: verify", What: "re-verification of an installed skill detects post-install tampering",
			Source: "SPEC-0266", Prov: ProvNormative,
			Note: "observed as exit 10 twice; it was in the run and missing from this table until 2026-09-05",
		},
		{
			ID: "verb: verify-sig", What: "a detached signature over altered bytes cannot be found or does not verify",
			Source: "SPEC-0225 §9.1 step 3", Prov: ProvNormative,
			Note: "the publisher's own check before admit; observed as exit 10 four times. " +
				"PR #216 changed that code from 1 and updated this expectation in the same " +
				"commit, which is what a pinned expectation is for",
		},
		{
			ID: "INV-1", What: "bytes that do not match the signed digest are never installed",
			Source: "SPEC-0225 §9.1 step 2, restated as a run-wide property", Prov: ProvDerived,
		},
		{
			ID: "INV-2", What: "once a signed revoke is visible, that digest is never staged again",
			Source: "SPEC-0225 §9.1 step 5, restated as a run-wide property", Prov: ProvDerived,
		},
		{
			ID: "INV-3", What: "no install without a qualifying attestation from a pinned signer",
			Source: "SPEC-0225 §9.1 step 4, SPEC-0359 D3", Prov: ProvDerived,
		},
		{
			ID: "INV-4", What: "every refusal is loud: non-zero exit AND a named reason",
			Source: "no specification clause found", Prov: ProvObserved,
			Note: "the justification (\"a silent refusal is unusable\") is a FITNESS-FOR-USE argument, " +
				"which is validation reasoning in a verification report; it is asserted, not derived",
		},
		{
			ID: "INV-5", What: "an adversary move never improves the attacker's outcome",
			Source: "no specification clause found", Prov: ProvDerived,
			Note: "NEVER EVALUATED. Declared here and in model.go, checked by nothing. It " +
				"needs a pair of runs, with and without the move, and the harness runs each " +
				"scenario once. Reported as 0 evaluations rather than as a silent pass " +
				"(FR-0125); a monotonicity property of the model, not a product requirement",
		},
		{
			ID: "INV-6", What: "a refusal leaves the install target byte-identical",
			Source: "side-effect requirement, raised by external review 2026-09-05", Prov: ProvAdopted,
			Note: "binds here, has no specification clause behind it; that is what adopted means",
		},
		{
			ID: "INV-7", What: "an acceptance delivers exactly the packed file set",
			Source: "side-effect requirement, raised by external review 2026-09-05", Prov: ProvAdopted,
			Note: "no specification clause; and checked against the SOURCE tree, not the signed bundle manifest",
		},
		{
			ID: "INV-8", What: "a decision available from signed metadata does not fetch artifact bytes",
			Source: "FR-0119 D3, decided 2026-09-05", Prov: ProvNormative,
		},
	}
}

// Prio orders the provenance classes for printing: what binds first, what is only
// conserved last.
func (p Provenance) prio() int {
	switch p {
	case ProvNormative:
		return 0
	case ProvDerived:
		return 1
	case ProvAdopted:
		return 2
	case ProvOpen:
		return 3
	default:
		return 4
	}
}

// WriteTraceability prints the matrix with the measured counts beside it, so a
// reader sees in one place what was asserted, where it comes from, and whether
// this run actually exercised it.
//
// The last column is the one that stops the table from being decoration: a rule
// with a normative source and zero observations has been declared, not tested.
func (rep Report) WriteTraceability(w io.Writer) {
	gates, _ := rep.Coverage()
	viol := map[string]int{}
	for _, v := range rep.Violations() {
		if i := strings.Index(v, ": "); i > 0 {
			for _, item := range TraceMatrix() {
				if strings.Contains(v, item.ID) {
					viol[item.ID]++
					break
				}
			}
		}
	}

	// How often each invariant's precondition actually held. Keyed by the short id
	// the matrix uses ("INV-5"), which is the prefix of the runtime name.
	evaluated := map[string]int{}
	for _, r := range rep.Results {
		for _, e := range r.Evaluated {
			name := string(e)
			if i := strings.Index(name, "-"); i > 0 {
				if j := strings.Index(name[i+1:], "-"); j > 0 {
					name = name[:i+1+j]
				}
			}
			evaluated[name]++
		}
	}

	// How often each ORDER claim was exercised: the scenarios where BOTH gates it
	// orders had a reason to fire. A claim that no scenario can falsify is not a
	// verified claim, and until 2026-09-06 this column said "n/a" for all three,
	// which hid that "gate 2 before gate 3" was exercised zero times.
	order := map[string]int{}
	for _, r := range rep.Results {
		st := StateAt(r.Scenario.P, r.Scenario.P.Revoke)
		if st.Revoked && !st.GovQualifies {
			order["order: 5 before 4"]++
		}
		if !st.DigestMatches && !st.SigsVerify {
			order["order: 2 before 3"]++
		}
	}

	items := append([]TraceItem(nil), TraceMatrix()...)
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].Prov.prio() < items[j].Prov.prio()
	})

	fmt.Fprintf(w, "\ntraceability: every claim with its origin\n")
	fmt.Fprintf(w, "  %-18s %-12s %-9s %s\n", "claim", "provenance", "observed", "source")
	for _, it := range items {
		obs := "n/a"
		if n, ok := order[it.ID]; ok {
			if n == 0 {
				obs = "NEVER RUN"
			} else {
				obs = fmt.Sprintf("%d exerc", n)
			}
		} else if n, ok := gates[it.ID]; ok {
			obs = fmt.Sprintf("%d", n)
		} else if strings.HasPrefix(it.ID, "gate ") {
			obs = "0"
		} else if strings.HasPrefix(it.ID, "INV-") {
			// "0 viol" for an invariant nothing ever evaluated is the same false
			// green this column exists to prevent, so the two are printed
			// differently. The evaluation count comes from the run, not from the
			// declaration.
			if evaluated[it.ID] == 0 {
				obs = "NEVER RUN"
			} else {
				obs = fmt.Sprintf("%d viol/%d", viol[it.ID], evaluated[it.ID])
			}
		}
		fmt.Fprintf(w, "  %-18s %-12s %-9s %s\n", it.ID, it.Prov, obs, it.Source)
		if it.Note != "" {
			fmt.Fprintf(w, "  %-18s %-12s %-9s   ^ %s\n", "", "", "", it.Note)
		}
	}
	fmt.Fprintf(w, "  normativ = in einer SPEC; abgeleitet = hergeleitet, die Herleitung ist Teil\n")
	fmt.Fprintf(w, "  der Evidenz; uebernommen = bindet hier, hat aber keine Klausel hinter sich;\n")
	fmt.Fprintf(w, "  beobachtet = aus dem Verhalten gewonnen, ein Fehlschlag heisst\n")
	fmt.Fprintf(w, "  GEAENDERT und nicht FALSCH; ungeklaert = wird geprueft, Bedeutung offen.\n")
	fmt.Fprintf(w, "  Eine Zeile mit normativer Quelle und null Beobachtungen ist DEKLARIERT,\n")
	fmt.Fprintf(w, "  nicht geprueft.\n")
}
