package sim

// freeze.go pins a plan BEFORE it is measured against.
//
// The problem it solves was named by a reviewer and it cannot be repaired after
// the fact: several requirements this project checks carry the date of the run
// that discovered them. Evidence found while looking is worth having, and it is
// not the same as a prediction that was written down first. No amount of later
// documentation converts one into the other.
//
// So the sequence changes rather than the paperwork. A freeze manifest records
// what the next measurement WILL be compared against: the decision model, the
// corpus, the expectation attached to every step, and the plan document. Each is
// hashed. The manifest is then printed by a job on a pull request, so the moment
// of freezing is recorded by a system nobody here controls. A git commit date is
// not that: it is a field the committer sets.
//
// What a freeze does not do is make the earlier findings prospective. They stay
// labelled exploratory. The freeze is what makes the NEXT run a confirmation.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// FreezeManifest is the pinned description of a planned measurement.
type FreezeManifest struct {
	Strength   int
	Scenarios  int
	ModelHash  string
	CorpusHash string
	ExpectHash string
	PlanPath   string
	PlanHash   string
	Scope      []string
}

// BuildFreeze computes the manifest for a strength and a plan document.
func BuildFreeze(strength int, planPath string, scope []string) (FreezeManifest, error) {
	corpus, _ := GenerateCovering(strength)
	m := FreezeManifest{
		Strength:   strength,
		Scenarios:  len(corpus),
		ModelHash:  ModelHash(),
		CorpusHash: CorpusHash(corpus),
		ExpectHash: expectationHash(corpus),
		PlanPath:   planPath,
		Scope:      scope,
	}
	if planPath != "" {
		// #nosec G304 -- the plan path is supplied by the operator running the
		// freeze, on their own machine, and is read only to hash it.
		b, err := os.ReadFile(planPath)
		if err != nil {
			return m, fmt.Errorf("plan %q: %w", planPath, err)
		}
		sum := sha256.Sum256(b)
		m.PlanHash = hex.EncodeToString(sum[:])
	}
	return m, nil
}

// expectationHash covers what the run will DEMAND, separately from the corpus
// identity, so a change to a predicted outcome is visible even when the set of
// scenarios is unchanged. Those are different edits and they deserve different
// hashes: renaming a scenario is not the same as changing what it must produce.
func expectationHash(corpus []Scenario) string {
	h := sha256.New()
	for _, sc := range corpus {
		fmt.Fprintf(h, "%s\n", sc.ID)
		for _, st := range sc.Steps {
			fmt.Fprintf(h, "  %s|%s|%s|%d|%t|%s\n",
				st.Action.Kind, st.Expect.Outcome, st.Expect.Gate,
				st.Expect.Exit, st.Expect.Claimed, st.Expect.Why)
		}
	}
	// The waiver register is part of what is being frozen. A waiver added after
	// the freeze is a change to the acceptance criteria, and it must show.
	for _, w := range Waivers() {
		fmt.Fprintf(h, "waiver|%s|%s|%s|%s\n", w.Adv, w.Expected, w.Observed, w.Finding)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Write prints the manifest. The format is deliberately flat and greppable: a CI
// job prints it, a human reads it in a log, and a later run compares against it.
func (m FreezeManifest) Write(w io.Writer) {
	fmt.Fprintf(w, "FREEZE MANIFEST\n")
	fmt.Fprintf(w, "  strength          t=%d\n", m.Strength)
	fmt.Fprintf(w, "  scenarios         %d\n", m.Scenarios)
	fmt.Fprintf(w, "  model hash        %s\n", m.ModelHash)
	fmt.Fprintf(w, "  corpus hash       %s\n", m.CorpusHash)
	fmt.Fprintf(w, "  expectation hash  %s\n", m.ExpectHash)
	if m.PlanPath != "" {
		fmt.Fprintf(w, "  plan              %s\n", m.PlanPath)
		fmt.Fprintf(w, "  plan hash         %s\n", m.PlanHash)
	}
	if len(m.Scope) > 0 {
		s := append([]string(nil), m.Scope...)
		sort.Strings(s)
		fmt.Fprintf(w, "  scope             %s\n", strings.Join(s, ", "))
	}
	fmt.Fprintf(w, "\n  This manifest is the plan, not a result. Print it from a job whose start\n")
	fmt.Fprintf(w, "  time is recorded by somebody other than the author: that recording, and\n")
	fmt.Fprintf(w, "  not a commit date, is what makes the next run a confirmation rather than\n")
	fmt.Fprintf(w, "  a discovery. Earlier findings stay labelled exploratory.\n")
}

// Matches reports whether a later manifest is the same plan.
func (m FreezeManifest) Matches(o FreezeManifest) (bool, []string) {
	var diff []string
	if m.ModelHash != o.ModelHash {
		diff = append(diff, "model changed")
	}
	if m.CorpusHash != o.CorpusHash {
		diff = append(diff, "corpus changed")
	}
	if m.ExpectHash != o.ExpectHash {
		diff = append(diff, "expectations or waivers changed")
	}
	if m.PlanHash != o.PlanHash {
		diff = append(diff, "plan document changed")
	}
	return len(diff) == 0, diff
}
