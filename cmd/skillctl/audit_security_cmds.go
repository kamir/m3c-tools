package main

// SPEC-0246 §4.5 / §5.3 sub-verb: `skillctl audit security <name>`.
//
// Resolves an INSTALLED skill (~/.claude/skills/<name>/ by default), runs the
// behavioural bodyscan over its SKILL.md body, prints the report, and surfaces
// `self_attested` (SPEC-0246 §5.3 — "signed by author, reviewed by author" vs.
// independent review) by inspecting the install provenance:
//
//   - the signed attestation stash (.skillctl-attest.json): self_attested is
//     true when the governance attestation's reviewer_id equals the admit
//     event's author identity (normalized);
//   - failing that, the .m3c-provenance.json sidecar's per-role signatures.
//
// Exit codes:
//
//	0  bodyscan 🟢 green
//	2  bodyscan 🟡/🔴 (a finding is present) OR usage error
//	1  generic (skill not found, unreadable)

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/bodyscan"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// selfAttestState is the tri-state self_attested signal for an installed skill.
type selfAttestState int

const (
	selfAttestUnknown     selfAttestState = iota // no provenance recorded
	selfAttestIndependent                        // reviewer_id != author_id
	selfAttestSelf                               // reviewer_id == author_id
)

func (s selfAttestState) String() string {
	switch s {
	case selfAttestSelf:
		return "true (signed by author, reviewed by author)"
	case selfAttestIndependent:
		return "false (independent review)"
	default:
		return "unknown (no install provenance)"
	}
}

// runAuditSecurity implements `skillctl audit security <name> [--skills-dir DIR] [--json]`.
func runAuditSecurity(args []string, stdout, stderr io.Writer) int {
	var (
		name      string
		skillsDir string
		jsonOut   bool
	)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--json":
			jsonOut = true
		case "--skills-dir":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "skillctl audit security: --skills-dir requires an argument")
				return exitUsage
			}
			i++
			skillsDir = args[i]
		case "-h", "--help":
			fmt.Fprintln(stderr, "Usage: skillctl audit security <name> [--skills-dir DIR] [--json]")
			fmt.Fprintln(stderr, "")
			fmt.Fprintln(stderr, "Behavioural bodyscan over an installed skill + self_attested surfacing.")
			fmt.Fprintln(stderr, "Exit: 0 = 🟢 clean, 2 = 🟡/🔴 findings.")
			return exitOK
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(stderr, "skillctl audit security: unknown flag %q\n", a)
				return exitUsage
			}
			if name != "" {
				fmt.Fprintf(stderr, "skillctl audit security: unexpected second positional %q\n", a)
				return exitUsage
			}
			name = a
		}
	}
	if name == "" {
		fmt.Fprintln(stderr, "skillctl audit security: <name> is required")
		return exitUsage
	}

	if skillsDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(stderr, "skillctl audit security: home dir: %v\n", err)
			return exitGeneric
		}
		skillsDir = filepath.Join(home, ".claude", "skills")
	}
	skillDir := filepath.Join(skillsDir, name)
	if info, err := os.Stat(skillDir); err != nil || !info.IsDir() {
		fmt.Fprintf(stderr, "skillctl audit security: skill %q not installed at %s\n", name, skillDir)
		return exitGeneric
	}

	skillMD, err := resolveSkillMD(skillDir)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl audit security: %v\n", err)
		return exitGeneric
	}
	rep, err := scanBodyFile(skillMD)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl audit security: %v\n", err)
		return exitGeneric
	}

	state, reviewer, author := resolveSelfAttested(skillDir)

	if jsonOut {
		out := struct {
			Skill        string                  `json:"skill"`
			SkillMD      string                  `json:"skill_md"`
			BodyScan     bodyscan.BodyScanReport `json:"bodyscan"`
			NotScanned   bool                    `json:"not_scanned"`
			SelfAttested *bool                   `json:"self_attested"`
			ReviewerID   string                  `json:"reviewer_id,omitempty"`
			AuthorID     string                  `json:"author_id,omitempty"`
		}{
			Skill:      name,
			SkillMD:    skillMD,
			BodyScan:   rep,
			NotScanned: bodyscan.NotScanned(rep),
			ReviewerID: reviewer,
			AuthorID:   author,
		}
		switch state {
		case selfAttestSelf:
			t := true
			out.SelfAttested = &t
		case selfAttestIndependent:
			f := false
			out.SelfAttested = &f
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(stderr, "skillctl audit security: encode json: %v\n", err)
			return exitGeneric
		}
		return bodyScanExitCode(rep.Verdict)
	}

	fmt.Fprintf(stdout, "skill:         %s\n", name)
	fmt.Fprintf(stdout, "self_attested: %s\n", state)
	if reviewer != "" || author != "" {
		fmt.Fprintf(stdout, "  reviewer_id: %s\n", emptyDash(reviewer))
		fmt.Fprintf(stdout, "  author_id:   %s\n", emptyDash(author))
	}
	if bodyscan.NotScanned(rep) {
		fmt.Fprintln(stdout, "note:          body NOT scanned (oversized) — verdict is advisory, not a clean signal")
	}
	fmt.Fprintln(stdout, "")
	renderBodyScanTable(stdout, skillMD, rep)
	return bodyScanExitCode(rep.Verdict)
}

// resolveSelfAttested derives the self_attested signal for an installed skill,
// preferring the signed attestation stash, then the provenance sidecar. Returns
// the tri-state plus the reviewer_id and author_id it compared (for display).
func resolveSelfAttested(skillDir string) (state selfAttestState, reviewerID, authorID string) {
	// 1. Signed attestation stash (.skillctl-attest.json): the most authoritative
	//    source — reviewer_id from the governance attestation, author from the
	//    admit event.
	if ctx, err := registry.ReadAttestationStash(skillDir); err == nil && ctx != nil {
		reviewerID = mapString(ctx.GovernanceAttestation, "reviewer_id")
		authorID = mapString(ctx.AdmitEvent, "admitted_by_identity")
		if authorID == "" {
			authorID = firstSignatureIdentity(ctx.AdmitEvent, "author")
		}
		if reviewerID != "" && authorID != "" {
			if normalizeIdentity(reviewerID) == normalizeIdentity(authorID) {
				return selfAttestSelf, reviewerID, authorID
			}
			return selfAttestIndependent, reviewerID, authorID
		}
	}

	// 2. Provenance sidecar (.m3c-provenance.json): per-role signatures. In the
	//    self tenant the author and registry roles share one identity — that IS
	//    a self-attestation signal (no independent reviewer recorded).
	sidecarPath := filepath.Join(skillDir, registry.ProvenanceSidecarName)
	if data, err := os.ReadFile(sidecarPath); err == nil {
		var sc registry.ProvenanceSidecar
		if json.Unmarshal(data, &sc) == nil {
			var auth, reg string
			for _, s := range sc.Signatures {
				switch s.Role {
				case "author":
					auth = s.IdentityID
				case "registry", "governance", "reviewer":
					reg = s.IdentityID
				}
			}
			authorID = auth
			reviewerID = reg
			if auth != "" && reg != "" {
				if normalizeIdentity(auth) == normalizeIdentity(reg) {
					return selfAttestSelf, reviewerID, authorID
				}
				return selfAttestIndependent, reviewerID, authorID
			}
		}
	}

	return selfAttestUnknown, reviewerID, authorID
}

// mapString fetches a string value from a map[string]any, "" when absent.
func mapString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// firstSignatureIdentity pulls the identity_id of the first signature with the
// given role from an admit event's signatures[] array.
func firstSignatureIdentity(ev map[string]any, role string) string {
	if ev == nil {
		return ""
	}
	sigs, ok := ev["signatures"].([]any)
	if !ok {
		return ""
	}
	for _, s := range sigs {
		m, ok := s.(map[string]any)
		if !ok {
			continue
		}
		if mapString(m, "role") == role {
			return mapString(m, "identity_id")
		}
	}
	return ""
}

func emptyDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
