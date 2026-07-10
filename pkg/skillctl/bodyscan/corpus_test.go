package bodyscan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/parser"
)

// expectation is the expected.json sidecar for an adversarial corpus file: the
// categories and (optionally) the specific rule IDs the file MUST trip.
type expectation struct {
	// Categories that MUST appear among the findings (at least these).
	Categories []string `json:"categories"`
	// RuleIDs, when present, MUST all appear among the findings.
	RuleIDs []string `json:"rule_ids,omitempty"`
	// MinVerdict is the minimum aggregate verdict (default "yellow").
	MinVerdict string `json:"min_verdict,omitempty"`
	// Note is human documentation; ignored by the test.
	Note string `json:"note,omitempty"`
}

// scanCorpusFile parses a corpus .md file (frontmatter -> Input) and scans it.
func scanCorpusFile(t *testing.T, path string) BodyScanReport {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fm, body, perr := parser.Parse(data)
	if perr != nil {
		t.Fatalf("parse %s: %v", path, perr)
	}
	in := Input{Body: body}
	if fm != nil {
		in.AllowedTools = fm.AllowedTools
		in.Intent = fm.Intent
	}
	return Scan(in)
}

func categoriesOf(rep BodyScanReport) map[string]bool {
	out := map[string]bool{}
	for _, f := range rep.Findings {
		out[string(f.Category)] = true
	}
	return out
}

func ruleIDsOf(rep BodyScanReport) map[string]bool {
	out := map[string]bool{}
	for _, f := range rep.Findings {
		out[f.RuleID] = true
	}
	return out
}

func verdictRank(v string) int {
	switch Verdict(v) {
	case VerdictRed:
		return 2
	case VerdictYellow:
		return 1
	default:
		return 0
	}
}

// TestCorpusThresholds is the SPEC-0246 §4.6 acceptance gate: >=95% true
// positive on the adversarial set, <=5% false positive on the benign set.
func TestCorpusThresholds(t *testing.T) {
	root := filepath.Join("testdata", "corpus")
	benignDir := filepath.Join(root, "benign")
	advDir := filepath.Join(root, "adversarial")

	benign := mustGlobMD(t, benignDir)
	adv := mustGlobMD(t, advDir)

	if len(benign) < 20 {
		t.Fatalf("need >=20 benign corpus files, found %d", len(benign))
	}
	if len(adv) < 20 {
		t.Fatalf("need >=20 adversarial corpus files, found %d", len(adv))
	}

	// --- False-positive rate on benign: a benign file is a false positive if it
	//     scores RED. (Yellow is an allowed "needs rationale" outcome per
	//     SPEC-0246 R4.6 and does not block install.)
	var fp int
	for _, f := range benign {
		rep := scanCorpusFile(t, f)
		if rep.Verdict == VerdictRed {
			fp++
			t.Logf("FALSE POSITIVE (red on benign): %s -> %s", filepath.Base(f), describeFindings(rep))
		}
	}
	fpRate := float64(fp) / float64(len(benign))

	// --- True-positive rate on adversarial: caught if verdict is yellow/red AND
	//     at least the expected category(ies) appear. A missing expected rule_id
	//     also counts as a miss.
	var tp int
	for _, f := range adv {
		rep := scanCorpusFile(t, f)
		exp := loadExpectation(t, f)

		minV := exp.MinVerdict
		if minV == "" {
			minV = string(VerdictYellow)
		}

		caught := verdictRank(string(rep.Verdict)) >= verdictRank(minV)

		gotCats := categoriesOf(rep)
		for _, c := range exp.Categories {
			if !gotCats[c] {
				caught = false
			}
		}
		gotRules := ruleIDsOf(rep)
		for _, rid := range exp.RuleIDs {
			if !gotRules[rid] {
				caught = false
			}
		}

		if caught {
			tp++
		} else {
			t.Logf("MISS (adversarial not caught): %s want cats=%v rules=%v minVerdict=%s -> got verdict=%s %s",
				filepath.Base(f), exp.Categories, exp.RuleIDs, minV, rep.Verdict, describeFindings(rep))
		}
	}
	tpRate := float64(tp) / float64(len(adv))

	t.Logf("CORPUS: benign=%d adversarial=%d", len(benign), len(adv))
	t.Logf("CORPUS: true-positive rate  = %.1f%% (%d/%d)  [threshold >= 95%%]", tpRate*100, tp, len(adv))
	t.Logf("CORPUS: false-positive rate = %.1f%% (%d/%d)  [threshold <= 5%%]", fpRate*100, fp, len(benign))

	if tpRate < 0.95 {
		t.Errorf("true-positive rate %.1f%% < 95%%", tpRate*100)
	}
	if fpRate > 0.05 {
		t.Errorf("false-positive rate %.1f%% > 5%%", fpRate*100)
	}
}

func mustGlobMD(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil {
		t.Fatalf("glob %s: %v", dir, err)
	}
	sort.Strings(matches)
	return matches
}

// loadExpectation reads <file>.expected.json (sibling, replacing the .md
// suffix). Every adversarial file MUST have one.
func loadExpectation(t *testing.T, mdPath string) expectation {
	t.Helper()
	expPath := strings.TrimSuffix(mdPath, ".md") + ".expected.json"
	data, err := os.ReadFile(expPath)
	if err != nil {
		t.Fatalf("adversarial file %s has no expected.json (%s): %v",
			filepath.Base(mdPath), filepath.Base(expPath), err)
	}
	var exp expectation
	if jerr := json.Unmarshal(data, &exp); jerr != nil {
		t.Fatalf("parse %s: %v", expPath, jerr)
	}
	if len(exp.Categories) == 0 {
		t.Fatalf("%s: expected.json must name at least one category", filepath.Base(expPath))
	}
	return exp
}

func describeFindings(rep BodyScanReport) string {
	if len(rep.Findings) == 0 {
		return "(no findings)"
	}
	var b strings.Builder
	b.WriteString("[")
	for i, f := range rep.Findings {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(f.RuleID)
		b.WriteString(":")
		b.WriteString(string(f.Verdict))
	}
	b.WriteString("]")
	return b.String()
}
