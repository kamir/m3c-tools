package main

// SPEC-0194 (S3.1 closure 2026-05-06). CLI runner for `skillctl propose`.
//
// The trainer's daily flow:
//
//	skillctl propose <skill-name>
//	    --intent green|yellow|red
//	    [--rationale "..."]               required for yellow/red
//	    [--source PATH]                   defaults to ~/.claude/skills/<name>/
//	    [--bump major|minor|patch]        auto-bump SKILL.md frontmatter version
//	    [--proposal-id <ulid>]            override; default is locally generated
//	    [--registry URL]
//	    [--bug-reports-dir PATH]          enables gate check #8
//	    [--last-admitted-version SEMVER]  enables gate check #10
//	    [--skip-smoke]
//	    [--dry-run]                       gate only; no registry POST
//
// Flow:
//   1. Resolve skill dir.
//   2. Run propose.Run() → 10-check gate. Print results inline.
//   3. If --dry-run OR gate failed → exit (2 on fail, 0 on dry-run).
//   4. Otherwise: POST a SkillProposal record to /api/skills/proposals.
//      The bundle's actual pack+sign+admit happens via `skillctl pack/sign/install`
//      (existing SPEC-0188 chain); on admission the server's admit-hook
//      (skill_service._flip_proposal_state_on_admission) flips this
//      proposal's state pending → admitted.
//   5. Append a row to ~/.m3c-tools/notify-queue.jsonl so the menubar
//      tray app surfaces the loop-close when the proposal goes live.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/propose"
)

// proposalRequest is the wire shape POSTed to /api/skills/proposals.
type proposalRequest struct {
	ProposalID         string   `json:"proposal_id"`
	ProposedByIdentity string   `json:"proposed_by_identity"`
	SkillName          string   `json:"skill_name"`
	SkillVersion       string   `json:"skill_version"`
	AuthorIntent       string   `json:"author_intent"`
	Rationale          string   `json:"rationale,omitempty"`
	DiffSummary        string   `json:"diff_summary,omitempty"`
	NotifyTargets      []string `json:"notify_targets,omitempty"`
	BundleDigest       string   `json:"bundle_digest,omitempty"`
}

// proposalResponse is the success body from the server.
type proposalResponse struct {
	ProposalID   string `json:"proposal_id"`
	State        string `json:"state"`
	BundleDigest string `json:"bundle_digest,omitempty"`
	ProposedAt   string `json:"proposed_at"`
}

// runPropose is main's dispatch entry point. Returns a numeric exit code.
func runPropose(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("propose", flag.ContinueOnError)
	fs.SetOutput(stderr)

	source := fs.String("source", "", "Skill directory; default ~/.claude/skills/<skill-name>/.")
	intent := fs.String("intent", "", "Author governance intent: green | yellow | red.")
	rationale := fs.String("rationale", "", "Required for yellow/red intent.")
	bump := fs.String("bump", "", "Auto-bump SKILL.md version: major | minor | patch (TODO: not yet wired in v1).")
	proposalID := fs.String("proposal-id", "", "Client-generated proposal id (ULID). Default: locally generated.")
	registryURL := fs.String("registry", defaultRegistryURL, "Registry base URL.")
	bugReportsDir := fs.String("bug-reports-dir", "", "Enable gate check #8 (open BUG-NNNN against this skill).")
	lastAdmitted := fs.String("last-admitted-version", "", "Enable gate check #10 (proposed version > last admitted).")
	skipSmoke := fs.Bool("skip-smoke", false, "Skip gate check #9 (smoke-test marker).")
	bodyscanRationale := fs.String("bodyscan-rationale", "", "Justification for a 🟡 bodyscan verdict (gate check #11). A 🔴 verdict cannot be overridden.")
	dryRun := fs.Bool("dry-run", false, "Run the gate only; do not POST a proposal record.")
	timeout := fs.Duration("timeout", defaultHTTPTimeout, "HTTP timeout for the registry POST.")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl propose <skill-name> [flags]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Run the SPEC-0194 §6 ready-to-promote gate against a local skill,")
		fmt.Fprintln(stderr, "and (on pass) register a proposal record so the post-admission")
		fmt.Fprintln(stderr, "hook can flip pending → admitted when the bundle is admitted.")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Exit codes:")
		fmt.Fprintln(stderr, "  0  gate passed (or --dry-run)")
		fmt.Fprintln(stderr, "  2  gate failed; one or more rows print FAIL")
		fmt.Fprintln(stderr, "")
		fs.PrintDefaults()
	}

	skillName, rest := extractFirstPositional(args)
	if err := fs.Parse(rest); err != nil {
		return exitUsage
	}
	if skillName == "" {
		fmt.Fprintln(stderr, "skillctl propose: <skill-name> is required (positional, before flags).")
		return exitUsage
	}

	skillDir := *source
	if skillDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(stderr, "skillctl propose: home dir: %v\n", err)
			return exitGeneric
		}
		skillDir = filepath.Join(home, ".claude", "skills", skillName)
	}

	// Run the gate.
	gateOpts := propose.CheckOptions{
		SkillDir:            skillDir,
		SkillName:           skillName,
		ProposedVersion:     "", // honor frontmatter version unless --bump implemented
		AuthorIntent:        strings.ToLower(strings.TrimSpace(*intent)),
		Rationale:           *rationale,
		SkipSmoke:           *skipSmoke,
		BugReportsDir:       *bugReportsDir,
		LastAdmittedVersion: *lastAdmitted,
		BodyScanRationale:   *bodyscanRationale,
	}
	if *bump != "" {
		fmt.Fprintln(stderr, "warning: --bump is not yet wired in v1; using SKILL.md version verbatim.")
	}
	report := propose.Run(gateOpts)
	printGateReport(stdout, report)

	if !report.AllPassed {
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "Gate failed. Fix the items marked FAIL and re-run.")
		return exitUsage
	}

	if *dryRun {
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "All gate checks passed. (--dry-run: no proposal record posted.)")
		return exitOK
	}

	// Resolve proposal_id: explicit flag wins; else generate locally.
	pid := *proposalID
	if pid == "" {
		var err error
		pid, err = newProposalID()
		if err != nil {
			fmt.Fprintf(stderr, "skillctl propose: id gen: %v\n", err)
			return exitGeneric
		}
	}

	// Resolve version (best-effort; gate already validated frontmatter).
	version := "" // populated from frontmatter via parser
	if v, err := readSkillVersion(skillDir); err == nil {
		version = v
	}

	if err := validateRegistryURL(*registryURL); err != nil {
		fmt.Fprintf(stderr, "skillctl propose: %v\n", err)
		return exitUsage
	}

	body := proposalRequest{
		ProposalID:         pid,
		ProposedByIdentity: defaultAuthorIdentity(),
		SkillName:          skillName,
		SkillVersion:       version,
		AuthorIntent:       gateOpts.AuthorIntent,
		Rationale:          *rationale,
	}

	if err := postProposal(*registryURL, body, *timeout, stdout, stderr); err != nil {
		// Network / server failure surfaces here; gate already passed.
		// Exit code is generic-1 so CI distinguishes "gate failed (2)"
		// from "registry unreachable (1)."
		fmt.Fprintf(stderr, "skillctl propose: %v\n", err)
		return exitGeneric
	}

	if err := appendNotifyQueue(pid, skillName, gateOpts.AuthorIntent); err != nil {
		// Not fatal: the proposal is registered server-side; the
		// notify queue is convenience.
		fmt.Fprintf(stderr, "warning: notify queue append failed: %v\n", err)
	}

	fmt.Fprintln(stdout, "")
	fmt.Fprintf(stdout, "Proposal %s registered (state=pending).\n", pid)
	fmt.Fprintln(stdout, "Next: run `skillctl pack` + `skillctl sign` + the admission flow;")
	fmt.Fprintln(stdout, "the registry's admit-hook will flip the proposal to admitted.")
	return exitOK
}

func printGateReport(w io.Writer, r propose.Result) {
	fmt.Fprintln(w, "SPEC-0194 §6 ready-to-promote gate:")
	fmt.Fprintln(w, "")
	for _, c := range r.Checks {
		var status string
		switch {
		case c.Skipped:
			status = "SKIP"
		case c.Pass:
			status = "PASS"
		default:
			status = "FAIL"
		}
		if c.Skipped {
			fmt.Fprintf(w, "  %s  #%-2d %s — %s\n", status, c.Number, c.Name, c.SkipReason)
		} else if c.Pass {
			fmt.Fprintf(w, "  %s  #%-2d %s\n", status, c.Number, c.Name)
		} else {
			fmt.Fprintf(w, "  %s  #%-2d %s — %s\n", status, c.Number, c.Name, c.Reason)
		}
	}
}

func postProposal(registryURL string, body proposalRequest, timeout time.Duration, stdout, stderr io.Writer) error {
	endpoint := strings.TrimRight(registryURL, "/") + "/proposals"
	payload, err := json.Marshal(&body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "skillctl/spec-0194-s3.1")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("registry returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	var ok proposalResponse
	if err := json.Unmarshal(respBody, &ok); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// readSkillVersion parses SKILL.md and returns the frontmatter version.
// Returns "" + error when SKILL.md is unreadable or has no version.
func readSkillVersion(skillDir string) (string, error) {
	skillMD := filepath.Join(skillDir, "SKILL.md")
	body, err := os.ReadFile(skillMD)
	if err != nil {
		return "", err
	}
	// Tiny YAML scan — same shape as audit_cmds.go's trust-roots reader.
	// We don't pull a yaml dep here; the frontmatter parser would work
	// but we want a focused single-field read.
	in := false
	for _, line := range strings.Split(string(body), "\n") {
		if line == "---" {
			if in {
				break
			}
			in = true
			continue
		}
		if !in {
			continue
		}
		if !strings.HasPrefix(line, "version:") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(line, "version:"))
		v = strings.Trim(v, `"' `)
		if v != "" {
			return v, nil
		}
	}
	return "", errors.New("frontmatter version not found")
}

// newProposalID returns a 26-char ULID-shaped string suitable for an
// idempotent proposal_id. Format: "01H" prefix + 23 uppercase hex chars
// derived from a timestamp + 12 bytes of randomness. Server treats it
// as opaque, so byte-perfect ULID compliance isn't required — we only
// need uniqueness within the registry's lifetime.
func newProposalID() (string, error) {
	rnd := make([]byte, 12)
	if _, err := rand.Read(rnd); err != nil {
		return "", err
	}
	now := time.Now().UnixMilli()
	tsHex := strings.ToUpper(hex.EncodeToString([]byte{
		byte(now >> 40), byte(now >> 32), byte(now >> 24),
		byte(now >> 16), byte(now >> 8), byte(now),
	}))
	rndHex := strings.ToUpper(hex.EncodeToString(rnd))
	out := "01H" + tsHex + rndHex
	if len(out) > 26 {
		out = out[:26]
	}
	return out, nil
}

// appendNotifyQueue writes a JSONL row to ~/.m3c-tools/notify-queue.jsonl.
// SPEC-0194 §9 lock: lightweight, no external dependency.
func appendNotifyQueue(proposalID, skillName, intent string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".m3c-tools")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, "notify-queue.jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	entry := map[string]any{
		"proposal_id":   proposalID,
		"skill_name":    skillName,
		"author_intent": intent,
		"created_at":    time.Now().UTC().Format(time.RFC3339),
		"state":         "pending",
		"acked":         false,
	}
	enc, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	enc = append(enc, '\n')
	_, err = f.Write(enc)
	return err
}

// extractFirstPositional pulls the first non-flag arg before any flags.
// Mirrors extractDigestPositional but returns a generic name string.
func extractFirstPositional(args []string) (first string, rest []string) {
	// The first positional must come before any flag: if args[0] is a flag (or
	// args is empty) there is no leading positional and the whole slice is rest.
	if len(args) == 0 {
		return "", nil
	}
	if strings.HasPrefix(args[0], "-") {
		return "", args
	}
	return args[0], args[1:]
}
