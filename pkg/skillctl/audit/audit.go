// Package audit computes per-skill verdicts for `skillctl audit`
// (SPEC-0189 §14, S3.3 closure 2026-05-06). The verdict surface is
// derivable from a scanner.Inventory annotated with --with-trust;
// this package does NOT touch the filesystem or network.
//
// The verdict set is closed, four states:
//
//	StateOK         — sibling .skb present, digest matches, governance ≥ floor
//	StateUnverified — no sibling .skb (hand-authored or awareness-only)
//	StateBroken     — sibling .skb present but digest/sig integrity failed
//	StateBelowMin   — bundle present, valid, but governance below the
//	                  pinned minimum (e.g. 🟡 yellow when floor is 🟢)
//
// Exit-code mapping per SPEC-0189 §14.2 / S3-DECISIONS S3.3 Q4:
//
//	0  — every active skill is OK
//	2  — at least one UNVERIFIED or BELOW_MIN
//	3  — at least one BROKEN (stronger signal; structurally tampered)
//
// Cleanup eligibility per SPEC-0189 §14.4 / S3-DECISIONS S3.4 Q1:
//
//	BROKEN     → always cleanup-eligible
//	UNVERIFIED → cleanup-eligible unless --keep-unverified
//	BELOW_MIN  → never cleaned up (operator may install with --allow-yellow)
//	OK         → never cleaned up
package audit

import (
	"sort"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
	"github.com/kamir/m3c-tools/pkg/skillctl/scanner"
)

// State is one of the four closed verdict values.
type State string

const (
	StateOK         State = "OK"
	StateUnverified State = "UNVERIFIED"
	StateBroken     State = "BROKEN"
	StateBelowMin   State = "BELOW_MIN"
)

// Severity ordering for cross-rule "worst state wins" computations.
// Higher severity numbers win.
var severity = map[State]int{
	StateOK:         0,
	StateBelowMin:   1,
	StateUnverified: 2,
	StateBroken:     3,
}

// MinimumLevel is the SPEC-0130 Ampel-system enum.
type MinimumLevel string

const (
	MinGreen  MinimumLevel = "green"
	MinYellow MinimumLevel = "yellow"
	MinRed    MinimumLevel = "red"
	MinAny    MinimumLevel = "" // explicit "no floor"
)

// minRank ordering: the floor is met iff skill_level rank ≥ minimum rank.
var minRank = map[string]int{
	"green":  3,
	"yellow": 2,
	"red":    1,
	"":       0,
}

// Verdict is the per-skill audit row. The table renderer in
// cmd/skillctl/audit_cmds.go emits one row per Verdict; the cleanup
// path filters this slice by Eligible.
type Verdict struct {
	Name             string
	Tier             string
	State            State
	GovernanceLevel  string // "" when no frontmatter or no governance_level field
	Reason           string // human-readable; rendered in the REASON column
	SourcePath       string // ~/.claude/skills/<name> — what cleanup would delete
	BundleDigest     string // canonical sha256:... when known
	VerifierExitCode int    // forwarded from scanner.BundleAttestation when nonzero
}

// CleanupEligible returns true iff this verdict is a cleanup target
// under the current --keep-unverified policy.
func (v Verdict) CleanupEligible(keepUnverified bool) bool {
	switch v.State {
	case StateBroken:
		return true
	case StateUnverified:
		return !keepUnverified
	}
	return false
}

// Report is the audit's full result set: per-skill verdicts plus
// aggregate counters and the resolved exit code.
type Report struct {
	Verdicts []Verdict
	Counts   map[State]int
	Total    int
	ExitCode int
}

// Compute walks every claude_code_skill in the inventory and returns
// a Report. The inventory MUST already be annotated by --with-trust
// (scanner.AnnotateTrust); skills with a nil Bundle pointer are
// treated as UNVERIFIED.
//
// Skills not of type claude_code_skill (commands, agents, MCP servers,
// etc.) are excluded — the audit's verdict surface only covers skills,
// per the SPEC-0189 §14.1 framing.
func Compute(inv *model.Inventory, minimum MinimumLevel) Report {
	if inv == nil {
		return Report{
			Verdicts: nil,
			Counts:   map[State]int{},
			ExitCode: 0,
		}
	}
	r := Report{
		Verdicts: make([]Verdict, 0, len(inv.Skills)),
		Counts:   map[State]int{},
	}
	for i := range inv.Skills {
		sk := &inv.Skills[i]
		if sk.Type != model.SkillTypeClaudeCodeSkill {
			continue
		}
		if sk.Tier == "" {
			// Legacy SPEC-0115 skills without tier annotation aren't
			// part of the audit surface — they show up under
			// `skillctl scan --source projects` only. SPEC-0189 §14
			// scope is "what Claude Code can load on this machine",
			// which is tier-aware.
			continue
		}
		v := classify(sk, minimum)
		r.Verdicts = append(r.Verdicts, v)
		r.Counts[v.State]++
	}
	r.Total = len(r.Verdicts)
	r.ExitCode = exitCodeFor(r.Counts)
	// Stable order for renderer determinism.
	sort.SliceStable(r.Verdicts, func(i, j int) bool {
		if severity[r.Verdicts[i].State] != severity[r.Verdicts[j].State] {
			return severity[r.Verdicts[i].State] > severity[r.Verdicts[j].State]
		}
		return r.Verdicts[i].Name < r.Verdicts[j].Name
	})
	return r
}

func classify(sk *model.SkillDescriptor, minimum MinimumLevel) Verdict {
	v := Verdict{
		Name:       sk.Name,
		Tier:       sk.Tier,
		SourcePath: sk.SourcePath,
	}
	if sk.Frontmatter != nil {
		v.GovernanceLevel = sk.Frontmatter.GovernanceLevel
	}

	// Trust-chain branch first: BROKEN dominates everything.
	if sk.Bundle != nil {
		v.BundleDigest = sk.Bundle.BundleDigest
		v.VerifierExitCode = sk.Bundle.VerifierExitCode
		switch sk.Bundle.TrustChain {
		case scanner.TrustBroken:
			v.State = StateBroken
			v.Reason = sk.Bundle.VerifierError
			if v.Reason == "" {
				v.Reason = "trust chain broken"
			}
			return v
		case scanner.TrustUnverified:
			v.State = StateUnverified
			v.Reason = "no sibling .skb on disk"
			return v
		case scanner.TrustVerified:
			// Bundle is good; fall through to governance check.
		}
	} else {
		v.State = StateUnverified
		v.Reason = "no sibling .skb on disk"
		return v
	}

	// Bundle is verified; check governance floor.
	if !meetsFloor(v.GovernanceLevel, minimum) {
		v.State = StateBelowMin
		if v.GovernanceLevel == "" {
			v.Reason = "governance_level missing; floor=" + string(minimum)
		} else {
			v.Reason = "governance " + v.GovernanceLevel + " < floor " + string(minimum)
		}
		return v
	}

	v.State = StateOK
	return v
}

// meetsFloor returns true iff skillLevel satisfies the minimum.
// Empty minimum means "no floor"; everything passes.
func meetsFloor(skillLevel string, minimum MinimumLevel) bool {
	if minimum == "" || minimum == MinAny {
		return true
	}
	return minRank[skillLevel] >= minRank[string(minimum)]
}

// exitCodeFor implements the S3.3 Q4 mapping. Broken dominates;
// unverified or below_min surface 2; clean returns 0.
func exitCodeFor(counts map[State]int) int {
	if counts[StateBroken] > 0 {
		return 3
	}
	if counts[StateUnverified] > 0 || counts[StateBelowMin] > 0 {
		return 2
	}
	return 0
}
