package evaluation

// E4 — Behaviour-scan TP/FP on the REAL committed corpus (SPEC-0280 §2; SPEC-0246 §4.6).
//
// This is the ONE metric measured on REAL, not synthetic, data: the committed
// adversarial/benign corpus at pkg/skillctl/bodyscan/testdata/corpus (40
// adversarial + 32 benign SKILL.md bodies). We run the SHIPPED bodyscan.Scan over
// every sample and compute:
//
//   - True-positive rate  = (adversarial samples caught) / (adversarial samples).
//     "Caught" = aggregate verdict reaches the sample's expected min_verdict AND
//     every expected category/rule the sidecar names is present — the SAME
//     correctness bar the shipped corpus gate uses, so E4 is an honest
//     re-measurement of the production acceptance criterion.
//   - False-positive rate = (benign samples scored RED) / (benign samples). Yellow
//     on a benign sample is an allowed "needs-rationale" outcome (SPEC-0246 R4.6)
//     and is NOT a false positive.
//
// Threshold (SPEC-0280): TP ≥ 95%, FP ≤ 5%. We report the REAL measured numbers.
// This test runs in plain CI too (no RUN_EVAL gate) so a regression below the
// threshold fails the build; it only records a result row in a measured run.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/bodyscan"
	"github.com/kamir/m3c-tools/pkg/skillctl/parser"
)

// corpusRoot is the committed corpus, relative to the evaluation package dir.
const corpusRoot = "../pkg/skillctl/bodyscan/testdata/corpus"

// e4Expectation mirrors the sidecar .expected.json the corpus ships for each
// adversarial sample (same shape the bodyscan corpus test uses).
type e4Expectation struct {
	Categories []string `json:"categories"`
	RuleIDs    []string `json:"rule_ids,omitempty"`
	MinVerdict string   `json:"min_verdict,omitempty"`
	Note       string   `json:"note,omitempty"`
}

// e4Scan parses a corpus SKILL.md and scans its body with the shipped scanner.
func e4Scan(t *testing.T, path string) bodyscan.BodyScanReport {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fm, body, perr := parser.Parse(data)
	if perr != nil {
		t.Fatalf("parse %s: %v", path, perr)
	}
	in := bodyscan.Input{Body: body}
	if fm != nil {
		in.AllowedTools = fm.AllowedTools
		in.Intent = fm.Intent
	}
	return bodyscan.Scan(in)
}

func e4Glob(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil {
		t.Fatalf("glob %s: %v", dir, err)
	}
	sort.Strings(matches)
	return matches
}

func e4VerdictRank(v string) int {
	switch bodyscan.Verdict(v) {
	case bodyscan.VerdictRed:
		return 2
	case bodyscan.VerdictYellow:
		return 1
	default:
		return 0
	}
}

// TestE4BodyscanCorpus measures TP/FP on the real corpus and records both rates.
func TestE4BodyscanCorpus(t *testing.T) {
	benignDir := filepath.Join(corpusRoot, "benign")
	advDir := filepath.Join(corpusRoot, "adversarial")
	benign := e4Glob(t, benignDir)
	adv := e4Glob(t, advDir)

	if len(benign) == 0 || len(adv) == 0 {
		t.Fatalf("corpus not found at %s (benign=%d adversarial=%d)", corpusRoot, len(benign), len(adv))
	}

	// False positives: a benign sample is a false positive iff it scores RED.
	var fp int
	for _, f := range benign {
		rep := e4Scan(t, f)
		if rep.Verdict == bodyscan.VerdictRed {
			fp++
			t.Logf("E4 FALSE POSITIVE (red on benign): %s", filepath.Base(f))
		}
	}
	fpRate := 100 * float64(fp) / float64(len(benign))

	// True positives: an adversarial sample is caught iff the verdict reaches its
	// expected min_verdict AND every expected category/rule is present.
	var tp int
	for _, f := range adv {
		rep := e4Scan(t, f)
		exp := e4LoadExpectation(t, f)

		minV := exp.MinVerdict
		if minV == "" {
			minV = string(bodyscan.VerdictYellow)
		}
		caught := e4VerdictRank(string(rep.Verdict)) >= e4VerdictRank(minV)

		gotCats := map[string]bool{}
		gotRules := map[string]bool{}
		for _, fnd := range rep.Findings {
			gotCats[string(fnd.Category)] = true
			gotRules[fnd.RuleID] = true
		}
		for _, c := range exp.Categories {
			if !gotCats[c] {
				caught = false
			}
		}
		for _, r := range exp.RuleIDs {
			if !gotRules[r] {
				caught = false
			}
		}
		if caught {
			tp++
		} else {
			t.Logf("E4 MISS (adversarial not caught): %s want cats=%v rules=%v minVerdict=%s got=%s",
				filepath.Base(f), exp.Categories, exp.RuleIDs, minV, rep.Verdict)
		}
	}
	tpRate := 100 * float64(tp) / float64(len(adv))

	t.Logf("E4 corpus: %d adversarial, %d benign", len(adv), len(benign))
	t.Logf("E4 true-positive  rate = %.1f%% (%d/%d) [threshold >= 95%%]", tpRate, tp, len(adv))
	t.Logf("E4 false-positive rate = %.1f%% (%d/%d) [threshold <= 5%%]", fpRate, fp, len(benign))

	if tpRate < 95.0 {
		t.Errorf("E4 true-positive rate %.1f%% < 95%% threshold", tpRate)
	}
	if fpRate > 5.0 {
		t.Errorf("E4 false-positive rate %.1f%% > 5%% threshold", fpRate)
	}

	if testingRunEval {
		recordPop(t, "E4", "bodyscan-corpus", "true_positive_pct", round4(tpRate), "real",
			"shipped bodyscan.Scan over the committed SPEC-0246 corpus, %d adversarial samples, threshold>=95%%", len(adv))
		recordPop(t, "E4", "bodyscan-corpus", "false_positive_pct", round4(fpRate), "real",
			"shipped bodyscan.Scan over the committed SPEC-0246 corpus, %d benign samples, threshold<=5%%", len(benign))
	}
}

// e4LoadExpectation reads the .expected.json sidecar for an adversarial sample.
func e4LoadExpectation(t *testing.T, mdPath string) e4Expectation {
	t.Helper()
	expPath := strings.TrimSuffix(mdPath, ".md") + ".expected.json"
	data, err := os.ReadFile(expPath)
	if err != nil {
		t.Fatalf("adversarial %s has no expected.json: %v", filepath.Base(mdPath), err)
	}
	var exp e4Expectation
	if err := json.Unmarshal(data, &exp); err != nil {
		t.Fatalf("parse %s: %v", expPath, err)
	}
	return exp
}
