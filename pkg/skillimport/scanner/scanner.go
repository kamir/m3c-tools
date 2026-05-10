// Package scanner implements the SPEC-0201 §5 pre-flight static scanner for
// staged upstream skill bundles.
//
// The MVP P1-P4 surface implements these rules from the SPEC §5 table:
//
//	R-101 (high)     governance frontmatter field declared & non-empty
//	R-102 (medium)   description ≤ 200 chars
//	R-201 (critical) intent.side_effects requires explicit allowlist
//	R-202 (critical) suspicious dependency pinned in package.json
//	R-301 (medium)   data_dependencies references unregistered capability/source
//
// Verdict mapping:
//
//	any "critical"  → "refuse"
//	any "high"      → "warn"
//	otherwise       → "clean"
//
// All file I/O is stdlib. Frontmatter parsing is a small line-oriented YAML
// reader keyed only on the schema fields the rules need; the scanner does not
// require a full YAML implementation.
package scanner

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Severity levels (stable strings — surfaced verbatim in JSON reports).
const (
	SevLow      = "low"
	SevMedium   = "medium"
	SevHigh     = "high"
	SevCritical = "critical"
)

// Verdicts.
const (
	VerdictClean  = "clean"
	VerdictWarn   = "warn"
	VerdictRefuse = "refuse"
)

// Finding is a single rule hit.
type Finding struct {
	Rule     string `json:"rule"`     // e.g. "R-101"
	Severity string `json:"severity"` // SevLow..SevCritical
	Path     string `json:"path"`     // file inside the staged bundle (relative to stagingDir)
	Message  string `json:"message"`
}

// Report is the structured scan result.
type Report struct {
	Findings []Finding `json:"findings"`
	Verdict  string    `json:"verdict"` // VerdictClean / VerdictWarn / VerdictRefuse
}

// HasRefuse returns true if any finding has Critical severity.
func (r *Report) HasRefuse() bool { return r.Verdict == VerdictRefuse }

// HasWarn returns true if any finding has High severity (but no Critical).
func (r *Report) HasWarn() bool { return r.Verdict == VerdictWarn }

// suspiciousDeps: any package.json dependency name that contains one of these
// substrings (case-insensitive) is flagged R-202.
var suspiciousDeps = []string{
	"@skillhub/mcp-server",
	"eval-anything",
	"shell-pipe",
}

// allowedSideEffects: side-effect names that may appear in intent.side_effects
// only when paired with an explicit allowlist (intent.side_effect_allowlist).
var dangerousSideEffects = []string{
	"exec",
	"fs:write",
	"net:egress",
}

// Scan walks stagingDir and applies the rule set. The returned Report is
// always non-nil; an error is only returned for unrecoverable I/O failures
// (the dir doesn't exist, etc.). A staging dir that's empty produces a
// "clean" verdict with no findings.
func Scan(stagingDir string) (*Report, error) {
	if stagingDir == "" {
		return nil, fmt.Errorf("scanner.Scan: empty stagingDir")
	}
	info, err := os.Stat(stagingDir)
	if err != nil {
		return nil, fmt.Errorf("scanner.Scan: stat %s: %w", stagingDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("scanner.Scan: %s is not a directory", stagingDir)
	}

	rep := &Report{Findings: []Finding{}, Verdict: VerdictClean}

	// Locate target files by walking once (the scanner is rule-driven, not
	// file-driven, but a single walk is cheap and the staging dir is small).
	var skillMD, bundleJSON, packageJSON string
	err = filepath.WalkDir(stagingDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // soft-skip unreadable nodes
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(stagingDir, path)
		switch {
		case strings.EqualFold(rel, filepath.Join(".claude", "skill.md")):
			skillMD = path
		case strings.EqualFold(filepath.Base(rel), "skill.md") && skillMD == "":
			// Some upstream packs ship skill.md at the root.
			skillMD = path
		case strings.EqualFold(filepath.Base(rel), "bundle.json"):
			bundleJSON = path
		case strings.EqualFold(filepath.Base(rel), "package.json"):
			packageJSON = path
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// R-101 / R-102 — frontmatter rules.
	if skillMD != "" {
		fm, fmErr := readFrontmatter(skillMD)
		rel, _ := filepath.Rel(stagingDir, skillMD)
		if fmErr != nil {
			rep.add(Finding{
				Rule: "R-101", Severity: SevHigh, Path: rel,
				Message: fmt.Sprintf("could not parse frontmatter: %v", fmErr),
			})
		} else {
			gov := strings.TrimSpace(fm["governance"])
			if gov == "" {
				rep.add(Finding{
					Rule: "R-101", Severity: SevHigh, Path: rel,
					Message: "missing or empty 'governance' field in frontmatter",
				})
			} else if !validGovernance(gov) {
				rep.add(Finding{
					Rule: "R-101", Severity: SevHigh, Path: rel,
					Message: fmt.Sprintf("invalid 'governance' value %q (expected green/yellow/red)", gov),
				})
			}
			desc := strings.TrimSpace(fm["description"])
			if len(desc) > 200 {
				rep.add(Finding{
					Rule: "R-102", Severity: SevMedium, Path: rel,
					Message: fmt.Sprintf("description too long (%d chars; cap is 200)", len(desc)),
				})
			}
		}
	}

	// R-201 / R-301 — bundle.json semantics.
	if bundleJSON != "" {
		rel, _ := filepath.Rel(stagingDir, bundleJSON)
		bdata, rerr := os.ReadFile(bundleJSON)
		if rerr != nil {
			rep.add(Finding{
				Rule: "R-201", Severity: SevHigh, Path: rel,
				Message: fmt.Sprintf("could not read bundle.json: %v", rerr),
			})
		} else {
			var b bundleManifest
			if jerr := json.Unmarshal(bdata, &b); jerr != nil {
				rep.add(Finding{
					Rule: "R-201", Severity: SevHigh, Path: rel,
					Message: fmt.Sprintf("could not parse bundle.json: %v", jerr),
				})
			} else {
				// R-201: dangerous side-effect without allowlist → critical.
				for _, se := range b.Intent.SideEffects {
					if isDangerousSideEffect(se) && len(b.Intent.SideEffectAllowlist) == 0 {
						rep.add(Finding{
							Rule: "R-201", Severity: SevCritical, Path: rel,
							Message: fmt.Sprintf("intent.side_effects declares %q without intent.side_effect_allowlist", se),
						})
					}
				}
				// R-301: data_dependency references with no registered_sources entry → warn.
				registered := map[string]bool{}
				for _, src := range b.RegisteredSources {
					registered[src] = true
				}
				for _, dep := range b.DataDependencies {
					if dep.Source == "" {
						rep.add(Finding{
							Rule: "R-301", Severity: SevMedium, Path: rel,
							Message: fmt.Sprintf("data_dependency %q has no source", dep.Name),
						})
						continue
					}
					if !registered[dep.Source] {
						rep.add(Finding{
							Rule: "R-301", Severity: SevMedium, Path: rel,
							Message: fmt.Sprintf("data_dependency %q references unregistered source %q", dep.Name, dep.Source),
						})
					}
				}
			}
		}
	}

	// R-202 — package.json suspicious deps.
	if packageJSON != "" {
		rel, _ := filepath.Rel(stagingDir, packageJSON)
		pdata, rerr := os.ReadFile(packageJSON)
		if rerr == nil {
			var pkg packageJSONShape
			if jerr := json.Unmarshal(pdata, &pkg); jerr == nil {
				for name := range pkg.Dependencies {
					if matchesSuspiciousDep(name) {
						rep.add(Finding{
							Rule: "R-202", Severity: SevCritical, Path: rel,
							Message: fmt.Sprintf("dependency %q matches a known-suspicious pattern", name),
						})
					}
				}
				for name := range pkg.DevDependencies {
					if matchesSuspiciousDep(name) {
						rep.add(Finding{
							Rule: "R-202", Severity: SevCritical, Path: rel,
							Message: fmt.Sprintf("devDependency %q matches a known-suspicious pattern", name),
						})
					}
				}
			}
		}
	}

	rep.Verdict = computeVerdict(rep.Findings)
	return rep, nil
}

func (r *Report) add(f Finding) {
	r.Findings = append(r.Findings, f)
}

func computeVerdict(findings []Finding) string {
	hasHigh := false
	for _, f := range findings {
		if f.Severity == SevCritical {
			return VerdictRefuse
		}
		if f.Severity == SevHigh {
			hasHigh = true
		}
	}
	if hasHigh {
		return VerdictWarn
	}
	return VerdictClean
}

func validGovernance(g string) bool {
	switch strings.ToLower(g) {
	case "green", "yellow", "red":
		return true
	default:
		return false
	}
}

func isDangerousSideEffect(se string) bool {
	for _, s := range dangerousSideEffects {
		if s == se {
			return true
		}
	}
	return false
}

func matchesSuspiciousDep(name string) bool {
	low := strings.ToLower(name)
	for _, sus := range suspiciousDeps {
		if strings.Contains(low, strings.ToLower(sus)) {
			return true
		}
	}
	return false
}

// ───────────────────────────────────────────────────────────────────────────
// Helper types
// ───────────────────────────────────────────────────────────────────────────

type bundleIntent struct {
	SideEffects         []string `json:"side_effects"`
	SideEffectAllowlist []string `json:"side_effect_allowlist"`
}

type bundleDataDep struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

type bundleManifest struct {
	Intent            bundleIntent    `json:"intent"`
	DataDependencies  []bundleDataDep `json:"data_dependencies"`
	RegisteredSources []string        `json:"registered_sources"`
}

type packageJSONShape struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// readFrontmatter reads a file that begins with a YAML frontmatter block:
//
//	---
//	governance: green
//	description: foo bar baz
//	---
//	body...
//
// Returns a map[key]value of the frontmatter scalars (no nested mappings).
func readFrontmatter(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return out, nil
	}
	// File must start with `---` (after possible BOM/whitespace).
	if strings.TrimSpace(lines[0]) != "---" {
		return out, nil // no frontmatter; not an error per se
	}
	for i := 1; i < len(lines); i++ {
		l := strings.TrimRight(lines[i], "\r")
		if strings.TrimSpace(l) == "---" {
			break
		}
		// Strip trailing comments.
		if idx := strings.Index(l, "#"); idx >= 0 {
			// Only strip if not inside a quoted string. Our schema has no '#'
			// in values, so this is safe.
			l = l[:idx]
		}
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		colon := strings.Index(l, ":")
		if colon < 0 {
			continue
		}
		key := strings.TrimSpace(l[:colon])
		val := strings.TrimSpace(l[colon+1:])
		// Unquote.
		if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[len(val)-1] == val[0] {
			val = val[1 : len(val)-1]
		}
		out[key] = val
	}
	return out, nil
}
