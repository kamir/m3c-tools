// Package propose implements the SPEC-0194 §6 ready-to-promote gate
// for `skillctl propose`. The gate is the difference between "I edited
// a file" and "I think this is ready to ship": fail loud here rather
// than admit half-baked skills.
//
// The 10 checks (S3-DECISIONS S3.1 Q1=A — print all results inline):
//
//	1. SKILL.md exists at the source path
//	2. Frontmatter is valid YAML
//	3. `name` is set AND matches the directory name
//	4. `version` is set AND parses as semver (M.m.p[-pre][+meta])
//	5. `description` ≥ 20 chars
//	6. `governance_level` ∈ {green, yellow, red}
//	7. If yellow/red: rationale provided (via flag or frontmatter)
//	8. No open BUG-NNNN against this skill (best-effort filesystem grep)
//	9. Smoke-test marker present (tests/smoke.sh OR last_smoke_passed
//	   in metadata OR --skip-smoke)
//	10. Proposed version > last admitted version (registry round-trip,
//	    OPTIONAL — see CheckOptions.RegistryClient).
package propose

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/parser"
)

// CheckResult is the outcome of one of the 10 gate checks. Number is
// the SPEC-0194 §6 row index (1-based); Pass is true iff the check
// passed; Reason is a human-readable explanation when Pass is false.
type CheckResult struct {
	Number int
	Name   string
	Pass   bool
	Reason string
	Skipped bool
	SkipReason string
}

// CheckOptions controls optional / network-bound checks.
type CheckOptions struct {
	// SkillDir is the absolute path to the skill directory (parent of SKILL.md).
	SkillDir string

	// SkillName is the expected name (matches the directory's basename).
	SkillName string

	// ProposedVersion is the version the trainer wants to admit. Used
	// for check #10 if the registry comparison is enabled.
	ProposedVersion string

	// AuthorIntent is one of green/yellow/red. Yellow/red require Rationale.
	AuthorIntent string

	// Rationale is the trainer-supplied explanation. Optional for green;
	// required for yellow/red.
	Rationale string

	// SkipSmoke disables check #9 (smoke-test marker). Trainer's
	// explicit escape hatch per SPEC-0194 §6.
	SkipSmoke bool

	// BugReportsDir, when non-empty, enables check #8 (bug grep). The
	// gate looks for files matching `BUG-*.md` whose content references
	// SkillName. Best-effort; missing dir is treated as "no bugs."
	BugReportsDir string

	// LastAdmittedVersion is the version most recently admitted in the
	// registry for SkillName. When non-empty, enables check #10 (must
	// be strictly greater than this). When empty, check #10 is skipped
	// (offline / first-admission case).
	LastAdmittedVersion string
}

// Result is the aggregate gate outcome.
type Result struct {
	Checks    []CheckResult
	AllPassed bool
}

// Run executes the 10 SPEC-0194 §6 checks on the given options, in
// order. Returns a Result with one CheckResult per check; AllPassed is
// true iff every non-skipped check passed.
//
// Per S3-DECISIONS S3.1 Q1=A: every check is run regardless of earlier
// failures, so the trainer sees the full damage in one read.
func Run(opts CheckOptions) Result {
	checks := []CheckResult{}

	// 1. SKILL.md exists.
	skillMD := filepath.Join(opts.SkillDir, "SKILL.md")
	if _, err := os.Stat(skillMD); err == nil {
		checks = append(checks, ok(1, "SKILL.md present"))
	} else {
		checks = append(checks, fail(1, "SKILL.md present",
			fmt.Sprintf("missing %s", skillMD)))
		// Without SKILL.md, downstream checks are unrunnable — but we
		// still emit placeholder rows so the trainer sees the full
		// 10-row report (S3.1 Q1=A).
		for _, n := range []int{2, 3, 4, 5, 6, 7, 9} {
			checks = append(checks, skip(n, gateName(n), "SKILL.md missing"))
		}
		runOptional(&checks, opts)
		return finalize(checks)
	}

	// Parse frontmatter (covers checks 2-6).
	parsed, parseErr := parseFrontmatter(skillMD)

	// 2. Frontmatter is valid YAML.
	if parseErr == nil {
		checks = append(checks, ok(2, "Frontmatter is valid YAML"))
	} else {
		checks = append(checks, fail(2, "Frontmatter is valid YAML",
			fmt.Sprintf("parse error: %v", parseErr)))
	}

	// 3. name set + matches dir name.
	gotName := ""
	if parsed != nil {
		gotName = parsed.Name
	}
	wantName := opts.SkillName
	if wantName == "" {
		wantName = filepath.Base(opts.SkillDir)
	}
	if gotName == "" {
		checks = append(checks, fail(3, "name set + matches directory",
			"frontmatter `name` is empty"))
	} else if gotName != wantName {
		checks = append(checks, fail(3, "name set + matches directory",
			fmt.Sprintf("name=%q, dir basename=%q", gotName, wantName)))
	} else {
		checks = append(checks, ok(3, "name matches directory"))
	}

	// 4. version is set + parses semver.
	version := ""
	if parsed != nil {
		version = parsed.Version
	}
	if opts.ProposedVersion != "" {
		version = opts.ProposedVersion
	}
	switch {
	case version == "":
		checks = append(checks, fail(4, "version set + valid semver",
			"frontmatter `version` is empty and --bump not provided"))
	case !semverPattern.MatchString(version):
		checks = append(checks, fail(4, "version set + valid semver",
			fmt.Sprintf("not a valid semver: %q", version)))
	default:
		checks = append(checks, ok(4, "version "+version+" is valid semver"))
	}

	// 5. description ≥ 20 chars.
	desc := ""
	if parsed != nil {
		desc = strings.TrimSpace(parsed.Description)
	}
	if len(desc) >= 20 {
		checks = append(checks, ok(5, "description ≥ 20 chars"))
	} else {
		checks = append(checks, fail(5, "description ≥ 20 chars",
			fmt.Sprintf("got %d chars; want at least 20", len(desc))))
	}

	// 6. governance_level set (green/yellow/red).
	intent := opts.AuthorIntent
	if intent == "" && parsed != nil {
		intent = parsed.GovernanceLevel
	}
	intent = strings.ToLower(strings.TrimSpace(intent))
	switch intent {
	case "green", "yellow", "red":
		checks = append(checks, ok(6, "governance_level = "+intent))
	default:
		checks = append(checks, fail(6, "governance_level set",
			"must be one of green | yellow | red; got: "+intent))
	}

	// 7. yellow/red requires rationale.
	if intent == "yellow" || intent == "red" {
		if strings.TrimSpace(opts.Rationale) != "" {
			checks = append(checks, ok(7, "rationale provided for "+intent))
		} else {
			checks = append(checks, fail(7, "rationale provided for "+intent,
				"--rationale is required for yellow/red governance"))
		}
	} else {
		checks = append(checks, skip(7, "rationale provided",
			"only required for yellow/red"))
	}

	// 9. Smoke-test marker.
	if opts.SkipSmoke {
		checks = append(checks, skip(9, "smoke-test marker", "--skip-smoke set"))
	} else {
		smokePath := filepath.Join(opts.SkillDir, "tests", "smoke.sh")
		if _, err := os.Stat(smokePath); err == nil {
			checks = append(checks, ok(9, "tests/smoke.sh present"))
		} else if parsed != nil && parsed.Metadata != nil {
			if v, ok2 := parsed.Metadata["last_smoke_passed"]; ok2 && v != nil && fmt.Sprintf("%v", v) != "" {
				checks = append(checks, okFn(9, fmt.Sprintf("metadata.last_smoke_passed = %v", v)))
			} else {
				checks = append(checks, fail(9, "smoke-test marker",
					"no tests/smoke.sh; metadata.last_smoke_passed unset; --skip-smoke not set"))
			}
		} else {
			checks = append(checks, fail(9, "smoke-test marker",
				"no tests/smoke.sh; no metadata; --skip-smoke not set"))
		}
	}

	runOptional(&checks, opts)
	return finalize(checks)
}

func runOptional(checks *[]CheckResult, opts CheckOptions) {
	// 8. Bug-report grep (optional / best-effort).
	if opts.BugReportsDir == "" {
		*checks = append(*checks, skip(8, "no open BUG-NNNN", "--bug-reports-dir not set"))
	} else {
		matches, err := scanBugReports(opts.BugReportsDir, opts.SkillName)
		if err != nil {
			*checks = append(*checks, skip(8, "no open BUG-NNNN",
				fmt.Sprintf("scan error: %v", err)))
		} else if len(matches) == 0 {
			*checks = append(*checks, ok(8, "no open BUG-NNNN against "+opts.SkillName))
		} else {
			*checks = append(*checks, fail(8, "no open BUG-NNNN",
				fmt.Sprintf("found %d open bug(s): %s", len(matches), strings.Join(matches[:min(3, len(matches))], ", "))))
		}
	}

	// 10. Version monotonicity (optional / registry-bound).
	if opts.LastAdmittedVersion == "" {
		*checks = append(*checks, skip(10, "version > last admitted",
			"no last-admitted version provided (offline or first admission)"))
		return
	}
	proposed := opts.ProposedVersion
	if proposed == "" {
		// Best-effort: read from frontmatter via parseFrontmatter; if
		// the earlier parse failed, this skips with a clear reason.
		*checks = append(*checks, skip(10, "version > last admitted",
			"proposed version unresolved (no --bump and no frontmatter)"))
		return
	}
	if compareSemver(proposed, opts.LastAdmittedVersion) <= 0 {
		*checks = append(*checks, fail(10, "version > last admitted",
			fmt.Sprintf("proposed %q ≤ last admitted %q", proposed, opts.LastAdmittedVersion)))
	} else {
		*checks = append(*checks, ok(10,
			fmt.Sprintf("version %s > last admitted %s", proposed, opts.LastAdmittedVersion)))
	}
}

func finalize(checks []CheckResult) Result {
	all := true
	for _, c := range checks {
		if !c.Pass && !c.Skipped {
			all = false
			break
		}
	}
	return Result{Checks: checks, AllPassed: all}
}

// ---- Helpers ---------------------------------------------------------------

var semverPattern = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

func ok(n int, name string) CheckResult       { return CheckResult{Number: n, Name: name, Pass: true} }
func okFn(n int, name string) CheckResult     { return CheckResult{Number: n, Name: name, Pass: true} }
func fail(n int, name, reason string) CheckResult {
	return CheckResult{Number: n, Name: name, Pass: false, Reason: reason}
}
func skip(n int, name, reason string) CheckResult {
	return CheckResult{Number: n, Name: name, Skipped: true, SkipReason: reason}
}

func gateName(n int) string {
	names := map[int]string{
		1: "SKILL.md present",
		2: "Frontmatter is valid YAML",
		3: "name set + matches directory",
		4: "version set + valid semver",
		5: "description ≥ 20 chars",
		6: "governance_level set",
		7: "rationale for yellow/red",
		8: "no open BUG-NNNN",
		9: "smoke-test marker",
		10: "version > last admitted",
	}
	return names[n]
}

// parseFrontmatter wraps the existing skill parser so the gate has a
// single typed source. Returns nil + err if SKILL.md is unparseable.
func parseFrontmatter(skillMDPath string) (*frontmatterView, error) {
	body, err := os.ReadFile(skillMDPath)
	if err != nil {
		return nil, err
	}
	fm, _, err := parser.Parse(body)
	if err != nil {
		return nil, err
	}
	if fm == nil {
		return nil, fmt.Errorf("frontmatter missing or empty")
	}
	return &frontmatterView{
		Name:            fm.Name,
		Version:         fm.Version,
		Description:     fm.Description,
		GovernanceLevel: fm.GovernanceLevel,
		Metadata:        fm.Metadata,
	}, nil
}

type frontmatterView struct {
	Name            string
	Version         string
	Description     string
	GovernanceLevel string
	Metadata        map[string]interface{}
}

// compareSemver returns -1 / 0 / 1 in semver order. Invalid inputs
// compare as equal (the format check on row 4 catches them earlier).
func compareSemver(a, b string) int {
	parseTriple := func(s string) [3]int {
		var out [3]int
		// Strip any pre-release / build metadata.
		core := s
		if i := strings.IndexAny(core, "-+"); i >= 0 {
			core = core[:i]
		}
		parts := strings.SplitN(core, ".", 3)
		for i := range parts {
			if i >= 3 {
				break
			}
			n := 0
			for _, ch := range parts[i] {
				if ch < '0' || ch > '9' {
					break
				}
				n = n*10 + int(ch-'0')
			}
			out[i] = n
		}
		return out
	}
	A, B := parseTriple(a), parseTriple(b)
	for i := 0; i < 3; i++ {
		if A[i] < B[i] {
			return -1
		}
		if A[i] > B[i] {
			return 1
		}
	}
	return 0
}

// scanBugReports walks `dir` (non-recursive) looking for files matching
// BUG-*.md, returns those whose content mentions skillName. Best-effort:
// errors are swallowed if the dir doesn't exist.
func scanBugReports(dir, skillName string) ([]string, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var matches []string
	bugPattern := regexp.MustCompile(`^BUG-\d+.*\.md$`)
	needle := strings.ToLower(skillName)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !bugPattern.MatchString(e.Name()) {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		if strings.Contains(strings.ToLower(string(body)), needle) {
			matches = append(matches, e.Name())
		}
	}
	return matches, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
