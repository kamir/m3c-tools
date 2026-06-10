package main

// verify_all_cmds.go — `skillctl verify --all [--quarantine] [--json]`
// (SPEC-0247 P0.2: the SessionStart sweep).
//
// Iterates every ~/.claude/skills/<name>/ and re-runs the SPEC-0188 §7 chain.
// Wired as a SessionStart hook, it runs BEFORE skill discovery — so a skill it
// quarantines (moves out of ~/.claude/skills/) never has its description
// injected into the model's context this session (SPEC-0247 R-3.1). It is also
// the structural fallback for the /slash path, which PreToolUse cannot gate
// (§3.4): a skill that isn't on disk cannot be /slash-invoked.
//
// SAFETY — three dispositions, not one:
//   - managed (has a stashed .skb) + TRUST failure (§7 exit ≥10) → quarantine
//     (only with --quarantine). These are real signature/digest/governance/
//     revocation failures.
//   - managed + AVAILABILITY failure (network down, registry unreachable, trust
//     roots absent, budget exceeded → exit <10) → reported "unverified
//     (freshness unknown)" and LEFT IN PLACE. Quarantining on a flaky network
//     would nuke every skill; the cost is that a revocation can't be confirmed
//     offline until the P1 offline-stashed verifier lands.
//   - unmanaged (no .skb: plugins, hand-installed skills like `browse`) → follows
//     the gate-policy unmanaged disposition (§9): allow/warn → skipped; deny →
//     quarantined. Default `allow` means the sweep never touches non-skillctl
//     skills unless the operator opts into strict mode.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/install"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// --- seams (stubbed in tests so the sweep runs offline) ---

// loadRootsFn resolves the trust roots + the single pinned root. Production
// uses loadAndPickRoot; tests stub it so the sweep needs no real trust-roots
// file.
var loadRootsFn = loadAndPickRoot

// sweepVerifyManagedFn verifies one installed managed skill and returns
// (exitCode, chainSummary, err). Production = sweepVerifyManaged (talks to the
// registry); tests stub it to return a chosen verdict without a network.
var sweepVerifyManagedFn = sweepVerifyManaged

// sweepClockFn returns "now"; pulled out so a test can drive the time budget.
var sweepClockFn = time.Now

type sweepCtx struct {
	client *registry.Client
	root   *verify.TrustRoot
	tenant string
	govMin string
	home   string
}

// --- report shape ---

type sweepEntry struct {
	Skill          string `json:"skill"`
	State          string `json:"state"` // verified | quarantined | unverified | skipped
	Exit           int    `json:"exit,omitempty"`
	Reason         string `json:"reason,omitempty"`
	QuarantinePath string `json:"quarantine_path,omitempty"`
}

type sweepReport struct {
	SkillsDir   string       `json:"skills_dir"`
	Total       int          `json:"total"`
	Verified    int          `json:"verified"`
	Quarantined int          `json:"quarantined"`
	Unverified  int          `json:"unverified"`
	Skipped     int          `json:"skipped"`
	RootsError  string       `json:"roots_error,omitempty"`
	Entries     []sweepEntry `json:"entries"`
}

// runVerifyAll implements `skillctl verify --all`.
func runVerifyAll(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify --all", flag.ContinueOnError)
	fs.SetOutput(stderr)
	_ = fs.Bool("all", false, "Sweep every installed skill (this mode).")
	quarantine := fs.Bool("quarantine", false, "Move TRUST-failing managed skills out of ~/.claude/skills/ into the quarantine dir.")
	jsonOut := fs.Bool("json", false, "Emit a machine-readable JSON report on stdout.")
	budget := fs.Duration("budget", 60*time.Second, "Total wall-clock budget for the sweep; skills not reached are 'unverified', never quarantined.")
	homeOverride := fs.String("home", "", "Override the install root (advanced; defaults to $HOME).")
	registryURL := fs.String("registry", "", "Registry base URL (only if trust-roots pins multiple registries).")
	governanceMin := fs.String("governance-min", "", "Override the trust-root governance minimum (green | yellow).")
	sessionID := fs.String("session-id", "", "Stamp recorded verdict-cache rows with this session id (from the SessionStart event).")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	home := *homeOverride
	if home == "" {
		h, err := userHome()
		if err != nil {
			fmt.Fprintf(stderr, "verify --all: resolve home dir: %v\n", err)
			return exitGeneric
		}
		home = h
	}
	skillsDir := filepath.Join(home, ".claude", "skills")

	rep := sweepReport{SkillsDir: skillsDir}

	entries, err := os.ReadDir(skillsDir)
	if err != nil {
		// No skills dir → nothing to sweep. Not an error.
		fmt.Fprintf(stdout, "skillctl verify --all: no installed skills at %s (nothing to sweep)\n", skillsDir)
		if *jsonOut {
			emitSweepJSON(stdout, rep)
		}
		return exitOK
	}

	// Resolve trust roots once. If unavailable, managed skills cannot be
	// verified — report that clearly and DO NOT quarantine anything.
	tr, root, rootErr := loadRootsFn(*registryURL)
	var sc sweepCtx
	if rootErr == nil {
		sc = sweepCtx{
			client: registry.New(root.RegistryURL, install.HTTPClientOf(verifyHookTimeout)),
			root:   root,
			tenant: resolveTenant("", tr),
			govMin: *governanceMin,
			home:   home,
		}
	} else {
		rep.RootsError = rootErr.Error()
	}

	pol := loadGatePolicy()
	start := sweepClockFn()

	for _, e := range entries {
		name := e.Name()
		dir := filepath.Join(skillsDir, name)
		// os.Stat FOLLOWS symlinks. A symlinked skill dir (common here:
		// gstack symlinks like `browse → gstack/browse`) still has its
		// description loaded into context, so the sweep MUST see it.
		// e.IsDir() is lstat-based and would silently skip every symlink —
		// an evasion gap for a security sweep.
		info, statErr := os.Stat(dir)
		if statErr != nil || !info.IsDir() {
			continue
		}
		rep.Total++

		// Unmanaged (no .skb) → gate-policy disposition.
		if !dirHasSkb(dir) {
			switch pol.Unmanaged {
			case "deny":
				rep.Entries = append(rep.Entries, quarantineOrReport(home, name, *quarantine, "unmanaged (no .skb) and policy unmanaged_skills=deny", 0, &rep))
			default: // allow | warn
				rep.Skipped++
				rep.Entries = append(rep.Entries, sweepEntry{Skill: name, State: "skipped", Reason: "unmanaged (no .skb) — not skillctl-installed"})
			}
			continue
		}

		// Managed, but no SPEC-0188 trust roots. The online chain needs them;
		// the offline/sidecar tiers (self/ER1 pull format) do NOT — so try
		// those before giving up. Without this, a pure self/ER1 machine (no
		// SPEC-0188 roots, the common case) would never verify or quarantine
		// any pull-installed skill.
		if rootErr != nil {
			if !applyOfflineSweep(&rep, home, name, *sessionID, pol, *quarantine) {
				rep.Unverified++
				rep.Entries = append(rep.Entries, sweepEntry{Skill: name, State: "unverified",
					Reason: "trust roots unavailable + no offline metadata — left in place"})
			}
			continue
		}

		// Budget: a skill we cannot reach in time is unverified, never quarantined.
		remaining := *budget - sweepClockFn().Sub(start)
		if remaining <= 0 {
			rep.Unverified++
			rep.Entries = append(rep.Entries, sweepEntry{Skill: name, State: "unverified", Reason: "sweep budget exceeded (freshness unknown) — left in place"})
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), remaining)
		code, summary, vErr := sweepVerifyManagedFn(ctx, name, sc)
		cancel()

		switch {
		case vErr == nil:
			rep.Verified++
			// Record a PASS so per-invocation hooks can allow offline (§8).
			recordVerdict(home, name, *sessionID, exitOK, summary, sweepClockFn())
			rep.Entries = append(rep.Entries, sweepEntry{Skill: name, State: "verified", Exit: 0, Reason: summary})
		case code >= verify.ExitDigestMismatch: // ≥10 → a genuine §7 TRUST failure
			reason := reasonForExit(code, vErr)
			rep.Entries = append(rep.Entries, quarantineOrReport(home, name, *quarantine, reason, code, &rep))
			// Evict any stale PASS so the hook can't allow it offline.
			recordVerdict(home, name, *sessionID, code, "", sweepClockFn())
		default: // <10 → the online chain could not decide (availability).
			// Try the network-free path: stashed metadata / sidecar +
			// content-binding. Catches a tampered/bad-sig skill even when the
			// registry is down (only live revocation is unconfirmed).
			if !applyOfflineSweep(&rep, home, name, *sessionID, pol, *quarantine) {
				// No offline stash → leave the cache row in place; a prior PASS
				// on unchanged bytes remains the offline-resilience path (§8).
				rep.Unverified++
				rep.Entries = append(rep.Entries, sweepEntry{Skill: name, State: "unverified", Exit: code,
					Reason: "could not verify (registry unreachable; no offline stash): " + vErr.Error() + " — left in place"})
			}
		}
	}

	if *jsonOut {
		emitSweepJSON(stdout, rep)
	} else {
		printSweepHuman(stdout, rep, *quarantine)
	}
	return exitOK
}

// applyOfflineSweep runs the network-free verify ladder (offline-meta → sidecar
// + content-binding) for one managed skill and records the outcome in rep.
// Returns true if it produced a decision; false when there is no offline
// metadata at all (caller then marks the skill unverified). Independent of
// SPEC-0188 trust roots, so it serves the self/ER1 (sidecar) format.
func applyOfflineSweep(rep *sweepReport, home, name, sessionID string, pol gatePolicy, doQuarantine bool) bool {
	oc, oreason, ok := verifyManagedOfflineFn(name, pol, home)
	if !ok {
		return false
	}
	switch {
	case oc == exitOK:
		rep.Verified++
		recordVerdict(home, name, sessionID, exitOK, "verified offline", sweepClockFn())
		rep.Entries = append(rep.Entries, sweepEntry{Skill: name, State: "verified", Exit: 0,
			Reason: "verified offline (no registry; revocation not confirmed)"})
	case oc >= verify.ExitDigestMismatch:
		rep.Entries = append(rep.Entries, quarantineOrReport(home, name, doQuarantine, "offline: "+oreason, oc, rep))
		recordVerdict(home, name, sessionID, oc, "", sweepClockFn())
	default:
		rep.Unverified++
		rep.Entries = append(rep.Entries, sweepEntry{Skill: name, State: "unverified", Exit: oc,
			Reason: "offline verify inconclusive — left in place"})
	}
	return true
}

// quarantineOrReport moves the skill out when doQuarantine is set, else reports
// it as a pending quarantine. It bumps rep.Quarantined and returns the entry.
func quarantineOrReport(home, name string, doQuarantine bool, reason string, code int, rep *sweepReport) sweepEntry {
	rep.Quarantined++
	if !doQuarantine {
		return sweepEntry{Skill: name, State: "quarantined", Exit: code,
			Reason: reason + " (report-only; pass --quarantine to move it out)"}
	}
	dest, err := quarantineSkill(home, name, reason, code)
	if err != nil {
		return sweepEntry{Skill: name, State: "quarantined", Exit: code,
			Reason: "FAILED to quarantine: " + err.Error() + " (" + reason + ")"}
	}
	return sweepEntry{Skill: name, State: "quarantined", Exit: code, Reason: reason, QuarantinePath: dest}
}

// quarantineSkill moves ~/.claude/skills/<name>/ to
// ~/.claude/skillctl/quarantine/<name>.<unix-ts>/ and drops a QUARANTINE.md
// recording why. The move is an os.Rename (same filesystem under ~/.claude).
func quarantineSkill(home, name, reason string, code int) (string, error) {
	src := filepath.Join(home, ".claude", "skills", name)
	qbase := filepath.Join(home, ".claude", "skillctl", "quarantine")
	if err := os.MkdirAll(qbase, 0o755); err != nil {
		return "", err
	}
	dest := filepath.Join(qbase, fmt.Sprintf("%s.%d", name, sweepClockFn().Unix()))
	if err := os.Rename(src, dest); err != nil {
		return "", err
	}
	note := fmt.Sprintf(`# QUARANTINED: %s

This skill failed the SPEC-0188 §7 trust chain during a `+"`skillctl verify --all`"+` sweep
and was moved out of ~/.claude/skills/ so Claude Code will not load it.

- reason:    %s
- exit code: %d
- original:  %s
- moved at:  %s

To restore (only after you trust it again): move this directory back to
~/.claude/skills/%s/ and re-run `+"`skillctl verify %s`"+`, or re-install with
`+"`skillctl install %s`"+`.
`, name, reason, code, src, sweepClockFn().UTC().Format(time.RFC3339), name, name, name)
	// Sibling, NOT inside dest: if the quarantined skill was a symlink, writing
	// inside it would land in the shared target (e.g. gstack/browse). The note
	// sits next to the moved item as <name>.<ts>.QUARANTINE.md.
	_ = os.WriteFile(dest+".QUARANTINE.md", []byte(note), 0o644)
	return dest, nil
}

// sweepVerifyManaged is the production verification of one managed skill.
func sweepVerifyManaged(ctx context.Context, name string, sc sweepCtx) (int, string, error) {
	res, err := install.VerifyInstalled(install.Opts{
		Name:          name,
		Client:        sc.client,
		TrustRoot:     sc.root,
		HomeDir:       sc.home,
		GovernanceMin: sc.govMin,
		Tenant:        sc.tenant,
		Ctx:           ctx,
	})
	if err != nil {
		return verify.ExitCode(err), "", err
	}
	return exitOK, res.ChainSummary, nil
}

// dirHasSkb reports whether dir contains a top-level *.skb (i.e. it was
// installed by `skillctl install`).
func dirHasSkb(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".skb") {
			return true
		}
	}
	return false
}

func emitSweepJSON(w io.Writer, rep sweepReport) {
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Fprintf(w, `{"error":%q}`+"\n", err.Error())
		return
	}
	fmt.Fprintln(w, string(b))
}

func printSweepHuman(w io.Writer, rep sweepReport, doQuarantine bool) {
	if rep.RootsError != "" {
		fmt.Fprintf(w, "⚠ trust roots unavailable: %s\n  → managed skills reported 'unverified' (not quarantined).\n", rep.RootsError)
	}
	for _, e := range rep.Entries {
		var mark string
		switch e.State {
		case "verified":
			mark = "✓"
		case "quarantined":
			mark = "⛔"
		case "unverified":
			mark = "?"
		default:
			mark = "–"
		}
		line := fmt.Sprintf("  %s %-28s %s", mark, e.Skill, e.State)
		if e.Reason != "" {
			line += " — " + e.Reason
		}
		fmt.Fprintln(w, line)
	}
	verb := "would quarantine"
	if doQuarantine {
		verb = "quarantined"
	}
	fmt.Fprintf(w, "\nswept %d skill(s): %d verified · %d %s · %d unverified · %d skipped\n",
		rep.Total, rep.Verified, rep.Quarantined, verb, rep.Unverified, rep.Skipped)
}
