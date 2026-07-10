package main

// session_baseline_cmds.go — SPEC-0317 R-7 (P2) `skillctl session-baseline`.
//
// SessionStart INFORMATIONAL context: it prints the current named offline state
// (online / degraded / offline / locked — pkg/skillctl/statemachine) computed
// from (connectivity × cache ages × anchor presence × trust-basis presence), and
// — the AC-8 fallback — a RED "advisory-only until SPEC-0247 P1.3 pinned" banner
// whenever the managed-settings gate is NOT pinned.
//
// It is a PURE READ. It gates NOTHING, blocks NOTHING, and (by default) reaches
// NO network — a SessionStart hook must be fast and must never wedge a session.
// The state it prints only NAMES the posture; the authoritative decision ladder
// still lives in verify-hook (R-7.4). Because it is off the hot path it is not
// fail-closed: an IO/usage error is exit 1, never a gate deny.
//
// The three never-brick invariants are inherited from the statemachine package:
// trust-basis breadth (self/ER1 roots + .m3c-provenance sidecar, not only the
// SPEC-0188 roots), locked is enterprise-opt-in only, and the emergency channel
// is exempt — this verb only DISPLAYS them.

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/pin"
	"github.com/kamir/m3c-tools/pkg/skillctl/statemachine"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// advisoryUntilPinnedMsg is the exact AC-8 banner text (kept as a const so the
// test and the operator see the same string).
const advisoryUntilPinnedMsg = "advisory-only until SPEC-0247 P1.3 pinned"

// --- test seams -------------------------------------------------------------

// sessionBaselineNow is the injectable clock. The statemachine is a pure
// function of an injected clock; this is where production injects time.Now.
var sessionBaselineNow = time.Now

// sessionBaselineGather assembles the statemachine.Inputs snapshot from the local
// filesystem. It is a package var so tests can drive any state without a real
// home. forceOnline reflects the operator's --online assertion (SessionStart must
// not do a blocking network probe by default).
var sessionBaselineGather = defaultSessionBaselineGather

// sessionBaselinePinStatus reads the managed-settings file and reports the pin
// level. Seam so tests exercise the pinned / not-pinned banner branches without
// touching the platform path.
var sessionBaselinePinStatus = defaultSessionBaselinePinStatus

// ---------------------------------------------------------------------------

func runSessionBaseline(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("session-baseline", flag.ContinueOnError)
	fs.SetOutput(stderr)
	homeOverride := fs.String("home", "", "home dir override (default: $HOME)")
	msPath := fs.String("managed-settings", "", "managed-settings.json path override (default: platform path)")
	trustRootsPath := fs.String("trust-roots", "", "trust-roots.yaml path override (default: ~/.claude/skill-trust-roots.yaml)")
	online := fs.Bool("online", false, "assert the registry is reachable (SessionStart does NOT probe the network by default)")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	home := *homeOverride
	if home == "" {
		h, err := userHome()
		if err != nil {
			fmt.Fprintf(stderr, "skillctl session-baseline: resolve home: %v\n", err)
			return 1
		}
		home = h
	}

	// Resolve the offline policy from the trust roots (best-effort — a missing or
	// malformed trust-roots file must not wedge SessionStart; we surface a note
	// and fall back to the shipped default, which never locks).
	pol, polNote := resolveSessionOfflinePolicy(home, *trustRootsPath)
	// SPEC-0317 R-7.2 (Option B): the `enterprise` opt-in that permits `locked` is
	// sourced from the ROOT-OWNED managed settings, never the trust-roots file —
	// so the displayed posture matches what the runtime gate actually enforces.
	pol.Enterprise = gateManagedEnterprise()

	// Snapshot inputs against the injected clock and compute the state.
	now := sessionBaselineNow().UTC()
	in := sessionBaselineGather(home, *online, now)
	dec := statemachine.Decide(in, pol)

	// Pin status → the AC-8 advisory banner.
	pinStatus := sessionBaselinePinStatus(*msPath)

	if *asJSON {
		out := struct {
			statemachine.StateDecision
			PinLevel        string   `json:"pin_level"`
			Pinned          bool     `json:"pinned"`
			AdvisoryBanner  string   `json:"advisory_banner,omitempty"`
			Notes           []string `json:"notes,omitempty"`
			RequireLocalAud bool     `json:"require_local_audit"`
		}{
			StateDecision:   dec,
			PinLevel:        pinStatus.Level.String(),
			Pinned:          pinStatus.Pinned(),
			RequireLocalAud: pol.RequireLocalAudit,
		}
		if !pinStatus.Pinned() {
			out.AdvisoryBanner = advisoryUntilPinnedMsg
		}
		if polNote != "" {
			out.Notes = append(out.Notes, polNote)
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(stderr, "skillctl session-baseline: %v\n", err)
			return 1
		}
		return 0
	}

	// Human output.
	fmt.Fprintf(stdout, "skillctl session baseline\n")
	fmt.Fprintf(stdout, "  offline state:        %s\n", dec.State)
	fmt.Fprintf(stdout, "  registry reachable:   %s\n", yesNo(dec.RegistryReachable))
	fmt.Fprintf(stdout, "  trust basis present:  %s (SPEC-0188 roots OR self/ER1 roots OR .m3c-provenance)\n", yesNo(dec.TrustBasisPresent))
	fmt.Fprintf(stdout, "  translog anchor:      %s\n", yesNo(dec.AnchorPresent))
	fmt.Fprintf(stdout, "  enterprise profile:   %s\n", yesNo(dec.Enterprise))
	fmt.Fprintf(stdout, "  online fallback:      %s  [INFORMATIONAL — posture only; state-gating the online fallback is R-1.4 P2, not yet wired: the runtime gate still falls back]\n", allowedBlocked(dec.AllowOnlineFallback))
	fmt.Fprintf(stdout, "  high-risk fail-closed:%s\n", yesNoPad(dec.HighRiskFailsClosed))
	fmt.Fprintf(stdout, "  deny all managed:     %s  [ENFORCED (R-7.2) by verify-hook/enforce when the gate is pinned: a locked host denies non-allowlisted managed skills, exit 28]\n", yesNo(dec.DenyAllManaged))
	if polNote != "" {
		fmt.Fprintf(stdout, "  note: %s\n", polNote)
	}

	// AC-8: the RED advisory-until-pinned banner when the gate is not pinned.
	fmt.Fprintf(stdout, "  gate pinning:         %s\n", pinStatus.Level)
	if !pinStatus.Pinned() {
		fmt.Fprintf(stdout, "%s  [!] %s — without managed-settings pinning (SPEC-0247 P1.3) this whole enforcement layer is ADVISORY: an operator can delete the hooks. Run `skillctl pin install`.%s\n",
			ansiRed, advisoryUntilPinnedMsg, ansiReset)
	}
	return 0
}

// resolveSessionOfflinePolicy loads the trust roots and selects the machine-wide
// offline policy. Selection: the FIRST root that opts into `enterprise` wins (the
// enterprise profile is machine-wide and the most consequential); otherwise the
// first declared offline_policy; otherwise the zero policy (the shipped default,
// which never locks). A missing/malformed trust-roots file returns the zero
// policy plus a human note — SessionStart must never wedge on config trouble.
func resolveSessionOfflinePolicy(home, pathOverride string) (statemachine.OfflinePolicy, string) {
	path := pathOverride
	if path == "" {
		path = filepath.Join(home, verify.DefaultTrustRootsPath)
	}
	tr, err := verify.Load(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return statemachine.OfflinePolicy{}, "no trust-roots file — using the shipped default (unmanaged=allow, never locks)"
		}
		return statemachine.OfflinePolicy{}, fmt.Sprintf("trust-roots unreadable (%v) — using the shipped default", err)
	}

	var firstDeclared *statemachine.OfflinePolicy
	for i := range tr.Roots {
		p, perr := tr.Roots[i].ResolveOfflinePolicy()
		if perr != nil {
			// Load already validated, so this should not happen; be defensive.
			continue
		}
		if tr.Roots[i].OfflinePolicy == nil {
			continue
		}
		if p.Enterprise {
			return p, ""
		}
		if firstDeclared == nil {
			pc := p
			firstDeclared = &pc
		}
	}
	if firstDeclared != nil {
		return *firstDeclared, ""
	}
	return statemachine.OfflinePolicy{}, ""
}

// defaultSessionBaselineGather assembles the inputs from the local filesystem.
// Cache ages are derived from the mtime of the loose cache files (the P2 tables
// are not yet populated; R-2.3 keeps the loose files as the fallback read). All
// of it is best-effort: a missing file yields a zero age (treated fresh — and
// under the shipped no-ceiling default, age is not consulted anyway).
func defaultSessionBaselineGather(home string, forceOnline bool, now time.Time) statemachine.Inputs {
	return statemachine.Inputs{
		RegistryReachable: forceOnline,
		PolicyAge:         fileAge(now, verdictCachePath(home)), // policy proxy (loose fallback)
		TrustAge:          fileAge(now, verdictCachePath(home)), // trust proxy
		RevocationAge:     fileAge(now, revocationCachePath(home)),
		AnchorPresent:     fileExists(transparencyLogPath(home)),
		TrustBasisPresent: trustBasisPresent(home),
		Now:               now,
	}
}

// trustBasisPresent folds the BROAD R-7.1 trust-basis definition: a trust basis
// exists if ANY of the SPEC-0188 skill-trust-roots.yaml, the SPEC-0225 self/ER1
// trust-roots, OR a .m3c-provenance sidecar under ~/.claude/skills is present.
// This breadth is the never-brick guard — a self/ER1 sidecar-only host counts.
func trustBasisPresent(home string) bool {
	if fileExists(filepath.Join(home, verify.DefaultTrustRootsPath)) {
		return true // SPEC-0188 skill-trust-roots.yaml
	}
	if fileExists(filepath.Join(home, ".claude", "trust-roots.yaml")) {
		return true // SPEC-0225 self/ER1 trust-roots (registry.DefaultSelfTrustRootsPath)
	}
	// SPEC-0225 install-trust-mode writes a .m3c-provenance.json sidecar next to
	// each installed skill body — a legitimate trust basis on self/ER1 hosts that
	// have no skill-trust-roots.yaml at all (SPEC-0247 §10c).
	matches, _ := filepath.Glob(filepath.Join(home, ".claude", "skills", "*", ".m3c-provenance.json"))
	return len(matches) > 0
}

// revocationCachePath is the loose signed revoked-digest cache (the revocation
// cache's loose fallback per R-2.3).
func revocationCachePath(home string) string {
	return filepath.Join(verdictDir(home), "revoked-digests.json")
}

// transparencyLogPath is the SPEC-0278 L1 translog anchor file.
func transparencyLogPath(home string) string {
	return filepath.Join(verdictDir(home), "transparency-log.jsonl")
}

// fileAge returns now - mtime for path, or 0 when the file is missing/unstattable
// (treated fresh — under the shipped no-ceiling default the age is not consulted).
func fileAge(now time.Time, path string) time.Duration {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return now.Sub(fi.ModTime())
}

// defaultSessionBaselinePinStatus reads the managed-settings file and reports the
// pin level (mirrors `pin status`). A missing file is LevelAbsent (advisory); an
// unreadable/other error is treated as absent for the informational banner — the
// safe reading for "is the gate pinned?" is NO.
func defaultSessionBaselinePinStatus(pathOverride string) pin.StatusResult {
	path := pathOverride
	if path == "" {
		p, err := pin.DefaultManagedSettingsPath()
		if err != nil {
			return pin.StatusResult{Level: pin.LevelAbsent, Findings: []string{"no managed-settings path for this platform"}}
		}
		path = p
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return pin.StatusResult{Level: pin.LevelAbsent, Findings: []string{"managed-settings not readable at " + path}}
	}
	return pin.Verify(data)
}

func allowedBlocked(b bool) string {
	if b {
		return "allowed (online state)"
	}
	return "blocked (strictly local)"
}

func yesNoPad(b bool) string {
	if b {
		return " yes"
	}
	return " no"
}
