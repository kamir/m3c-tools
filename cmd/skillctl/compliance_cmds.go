package main

// SPEC-0276 R5 — `skillctl compliance report --framework <eu-ai-act|nist-ai-rmf|soc2>`.
//
// An offline evidence pack: it enumerates installed skills and their trust
// posture (governance level, author, offline-verifiable, provenance) from the
// metadata we already keep, and maps our controls to the named framework. It is
// an EVIDENCE AID for an auditor — NOT a certification (that is precisely the
// overreach we flagged in the hosted-CA rival's "we built it"). Closes the one
// productised asset that rival ships and we did not (R5).

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/install"
)

type complianceSkill struct {
	Name              string `json:"name"`
	Version           string `json:"version,omitempty"`
	Governance        string `json:"governance"` // green|yellow|red|unknown
	Author            string `json:"author,omitempty"`
	OfflineVerifiable bool   `json:"offline_verifiable"`
	HasProvenance     bool   `json:"has_provenance"`
}

type complianceControl struct {
	Control     string `json:"control"`
	Requirement string `json:"requirement"`
	Evidence    string `json:"evidence"`
}

type complianceReport struct {
	Framework  string              `json:"framework"`
	SkillsDir  string              `json:"skills_dir"`
	Summary    map[string]int      `json:"summary"`
	Skills     []complianceSkill   `json:"skills"`
	ControlMap []complianceControl `json:"control_map"`
	Trail      *trailVerification  `json:"invocation_trail,omitempty"`
	Disclaimer string              `json:"disclaimer"`
}

// withTrailEvidence returns a copy of the control map in which the EU AI Act
// Art.12 "Evidence" cell is replaced with the concrete, verified figures from
// the signed invocation trail. Non-Art.12 rows and other frameworks are
// untouched. Pure — never mutates the package-level complianceFrameworks map.
func withTrailEvidence(controls []complianceControl, tv trailVerification) []complianceControl {
	out := make([]complianceControl, len(controls))
	copy(out, controls)
	for i := range out {
		if strings.HasPrefix(out[i].Control, "Art. 12") {
			out[i].Evidence = trailEvidenceSentence(tv)
		}
	}
	return out
}

// trailEvidenceSentence renders a one-line, auditor-readable summary of the
// signed-trail state for the Art.12 evidence cell.
func trailEvidenceSentence(tv trailVerification) string {
	if !tv.Present {
		return "Per-invocation signed events (SPEC-0202): no invocation-trail.jsonl yet on this host (no skill invocations recorded). Trail is created on first gated invocation."
	}
	key := tv.DeviceKeyID
	if key == "" {
		key = "(device key unavailable — cannot verify)"
	}
	// Honest framing (P2 challenge-gate F-5.1): the device key is LOCALLY ANCHORED
	// — verification proves integrity-since-signing on THIS host, not authenticity
	// against an external root (registry attestation of the device key is a
	// follow-up). Do not let an auditor read self-referential verification as
	// external attestation.
	return fmt.Sprintf("Per-invocation signed events (SPEC-0202): %d/%d invocation records pass local device-key integrity verification (%d unverified, %d replays). Device key %s is locally anchored (integrity-since-signing on this host; not yet registry-attested). Append-only ~/.claude/skillctl/invocation-trail.jsonl.",
		tv.Verified, tv.Total, tv.Unverified, tv.Replays, key)
}

const complianceDisclaimer = "Evidence aid for an auditor — NOT a certification or attestation of compliance. " +
	"It summarises technical controls and maps them to the named framework; it does not assert conformance."

// complianceFrameworks embeds a concise, real control→evidence map per
// framework. The CISO owns the authoritative mapping (m3c-tools-maintenance/
// CISO-WORK/compliance-maps/); this is the machine-collected projection.
var complianceFrameworks = map[string][]complianceControl{
	"eu-ai-act": {
		{"Art. 12 — Record-keeping", "Automatic logging over the lifetime", "Per-invocation signed events (SPEC-0202) + admit/attest/revoke audit trail"},
		{"Art. 13 — Transparency", "Information to deployers", "Declared intent + data-scope per skill (SPEC-0196); provenance edges"},
		{"Art. 14 — Human oversight", "Enable human oversight", "Governance Ampel 🟢🟡🔴 + human checkpoints; reviewer≠author (SPEC-0246)"},
		{"Art. 15 — Accuracy/robustness/security", "Resilience to tampering", "ed25519 signed bundles + content-binding; offline verify + revocation (SPEC-0276)"},
	},
	"nist-ai-rmf": {
		{"GOVERN", "Policies, accountability, roles", "Trust-roots policy + skill:author RBAC; governance handbook"},
		{"MAP", "Context + provenance of components", "derived_from provenance; pinned authorship; skill inventory"},
		{"MEASURE", "Assess trustworthiness", "bodyscan behavioural inspection; the §7 verify chain; governance levels"},
		{"MANAGE", "Respond, recover, revoke", "Signed revocation list enforced offline (SPEC-0276 R4.4)"},
	},
	"soc2": {
		{"CC6.x — Logical access", "Restrict access to assets", "Pinned trust-roots; capability/data-scope declarations"},
		{"CC7.x — System operations", "Detect & respond to anomalies", "Audit trail of admit/attest/revoke + invocation events"},
		{"CC8.1 — Change management", "Authorize & track changes", "Signed bundles, reviewer≠author, version/digest pinning"},
	},
}

func runCompliance(args []string, stdout, stderr io.Writer) int {
	// Optional leading "report" verb (the only mode in v1).
	if len(args) > 0 && args[0] == "report" {
		args = args[1:]
	}
	fs := flag.NewFlagSet("compliance", flag.ContinueOnError)
	fs.SetOutput(stderr)
	framework := fs.String("framework", "", "Compliance framework: eu-ai-act | nist-ai-rmf | soc2 (required).")
	format := fs.String("format", "md", "Output format: md | json.")
	skillsDir := fs.String("skills-dir", "", "Skills directory to inventory (default: <home>/.claude/skills).")
	homeOverride := fs.String("home", "", "Home dir override used to locate the skills directory.")
	outPath := fs.String("out", "", "Write the report to this file instead of stdout.")
	_ = fs.Bool("offline", true, "Offline mode (default and only mode in v1).")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl compliance report --framework <eu-ai-act|nist-ai-rmf|soc2> [--format md|json] [--out file]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Offline evidence aid (SPEC-0276 R5). NOT a certification.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	controls, ok := complianceFrameworks[strings.ToLower(strings.TrimSpace(*framework))]
	if !ok {
		fmt.Fprintf(stderr, "compliance: unknown --framework %q (want eu-ai-act | nist-ai-rmf | soc2)\n", *framework)
		return exitUsage
	}
	if *format != "md" && *format != "json" {
		fmt.Fprintf(stderr, "compliance: unknown --format %q (want md | json)\n", *format)
		return exitUsage
	}

	// Resolve home first — needed both for the default skills dir AND for the
	// signed invocation trail (the Art.12 evidence).
	home := *homeOverride
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(stderr, "compliance: resolve home: %v\n", err)
			return exitGeneric
		}
		home = h
	}
	dir := *skillsDir
	if dir == "" {
		dir = filepath.Join(home, ".claude", "skills")
	}

	skills, err := collectComplianceSkills(dir)
	if err != nil {
		fmt.Fprintf(stderr, "compliance: inventory %s: %v\n", dir, err)
		return exitGeneric
	}

	// SPEC-0202 §9 — read + verify the device-signed invocation trail. This is
	// the concrete, offline-verifiable evidence for the EU AI Act Art.12
	// record-keeping control: the report now reports HOW MANY invocation records
	// are signed and verifiable, by which device key — not just a forward-ref.
	tv := readAndVerifyTrail(home)

	// For the EU AI Act framework, replace the static Art.12 "Evidence" cell
	// with the concrete trail figures. Copy the slice so we don't mutate the
	// package-level map.
	controls = withTrailEvidence(controls, tv)

	rep := complianceReport{
		Framework:  strings.ToLower(strings.TrimSpace(*framework)),
		SkillsDir:  dir,
		Summary:    summarizeCompliance(skills),
		Skills:     skills,
		ControlMap: controls,
		Trail:      &tv,
		Disclaimer: complianceDisclaimer,
	}

	var rendered string
	if *format == "json" {
		b, _ := json.MarshalIndent(rep, "", "  ")
		rendered = string(b) + "\n"
	} else {
		rendered = renderComplianceMD(rep)
	}

	if *outPath != "" {
		if err := os.WriteFile(*outPath, []byte(rendered), 0o644); err != nil {
			fmt.Fprintf(stderr, "compliance: write %s: %v\n", *outPath, err)
			return exitGeneric
		}
		fmt.Fprintf(stdout, "wrote %s (%d skills, framework %s)\n", *outPath, len(skills), rep.Framework)
		return exitOK
	}
	fmt.Fprint(stdout, rendered)
	return exitOK
}

// collectComplianceSkills inventories <skillsDir>/*/ and reads each skill's
// trust metadata best-effort. A directory without SKILL.md is skipped.
func collectComplianceSkills(skillsDir string) ([]complianceSkill, error) {
	entries, err := os.ReadDir(skillsDir)
	if err != nil {
		// A missing skills dir is a valid empty inventory (a host that has not
		// installed any skill yet) — not an error. Other read errors propagate.
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []complianceSkill
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		d := filepath.Join(skillsDir, e.Name())
		if _, err := os.Stat(filepath.Join(d, "SKILL.md")); err != nil {
			continue
		}
		cs := complianceSkill{Name: e.Name(), Governance: "unknown"}

		if om := readOfflineMetaForCompliance(d); om != nil && om.BundleMeta != nil {
			cs.OfflineVerifiable = true
			if g := strings.TrimSpace(om.BundleMeta.CurrentGovernance); g != "" {
				cs.Governance = g
			}
			if v, ok := om.BundleMeta.Bundle["version"].(string); ok {
				cs.Version = v
			}
			cs.Author = authorIDOf(om.BundleMeta)
		}
		if prov := readProvenanceForCompliance(d); prov != nil {
			cs.HasProvenance = true
			if cs.Governance == "unknown" {
				if g, _ := prov["governance_level"].(string); g != "" {
					cs.Governance = g
				}
			}
			if cs.Version == "" {
				if v, _ := prov["version"].(string); v != "" {
					cs.Version = v
				}
			}
			if cs.Author == "" {
				if a, _ := prov["author"].(string); a != "" {
					cs.Author = a
				}
			}
		}
		out = append(out, cs)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func readOfflineMetaForCompliance(dir string) *install.OfflineMeta {
	b, err := os.ReadFile(filepath.Join(dir, ".skillctl-offline.json"))
	if err != nil {
		return nil
	}
	var om install.OfflineMeta
	if err := json.Unmarshal(b, &om); err != nil {
		return nil
	}
	return &om
}

func readProvenanceForCompliance(dir string) map[string]any {
	b, err := os.ReadFile(filepath.Join(dir, ".m3c-provenance.json"))
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return m
}

func summarizeCompliance(skills []complianceSkill) map[string]int {
	s := map[string]int{"total": len(skills), "green": 0, "yellow": 0, "red": 0, "unknown": 0, "offline_verifiable": 0, "with_provenance": 0}
	for _, sk := range skills {
		switch sk.Governance {
		case "green", "yellow", "red":
			s[sk.Governance]++
		default:
			s["unknown"]++
		}
		if sk.OfflineVerifiable {
			s["offline_verifiable"]++
		}
		if sk.HasProvenance {
			s["with_provenance"]++
		}
	}
	return s
}

func renderComplianceMD(r complianceReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Compliance evidence — %s\n\n", strings.ToUpper(r.Framework))
	fmt.Fprintf(&b, "> %s\n\n", r.Disclaimer)
	fmt.Fprintf(&b, "Skills directory: `%s`\n\n", r.SkillsDir)

	b.WriteString("## Posture summary\n\n")
	fmt.Fprintf(&b, "- Total skills: %d\n", r.Summary["total"])
	fmt.Fprintf(&b, "- Governance: %d green · %d yellow · %d red · %d unknown\n", r.Summary["green"], r.Summary["yellow"], r.Summary["red"], r.Summary["unknown"])
	fmt.Fprintf(&b, "- Offline-verifiable (stashed metadata): %d\n", r.Summary["offline_verifiable"])
	fmt.Fprintf(&b, "- With provenance: %d\n", r.Summary["with_provenance"])
	if r.Trail != nil {
		t := r.Trail
		if !t.Present {
			fmt.Fprintf(&b, "- Signed invocation trail (SPEC-0202): none yet (no recorded invocations)\n")
		} else {
			key := t.DeviceKeyID
			if key == "" {
				key = "(unavailable)"
			}
			fmt.Fprintf(&b, "- Signed invocation trail (SPEC-0202): %d/%d records verified · %d unverified · %d replays · device key %s\n",
				t.Verified, t.Total, t.Unverified, t.Replays, key)
		}
	}
	b.WriteString("\n")

	b.WriteString("## Inventory\n\n")
	b.WriteString("| Skill | Version | Governance | Author | Offline | Provenance |\n")
	b.WriteString("|---|---|---|---|:-:|:-:|\n")
	for _, s := range r.Skills {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n",
			s.Name, dash(s.Version), s.Governance, dash(s.Author), yn(s.OfflineVerifiable), yn(s.HasProvenance))
	}
	if len(r.Skills) == 0 {
		b.WriteString("| _(no skills found)_ | | | | | |\n")
	}
	b.WriteString("\n## Control map\n\n")
	b.WriteString("| Control | Requirement | Evidence in this system |\n|---|---|---|\n")
	for _, c := range r.ControlMap {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", c.Control, c.Requirement, c.Evidence)
	}
	b.WriteString("\n---\nGenerated by `skillctl compliance report` (SPEC-0276 R5).\n")
	return b.String()
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func yn(b bool) string {
	if b {
		return "✓"
	}
	return "—"
}
