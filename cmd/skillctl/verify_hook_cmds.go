package main

// verify_hook_cmds.go — `skillctl verify-hook` (SPEC-0247 P0.1).
//
// A non-interactive Claude Code PreToolUse(Skill) trust gate. It reads the hook
// event JSON on stdin, extracts the invoked skill name (the confirmed field
// `tool_input.skill` — SPEC-0247 §3.4, observed across 93 real events + the
// production skill-usage hook), re-runs the SPEC-0188 §7 trust chain against the
// installed skill, and emits a Claude Code permission decision.
//
// Fail-closed by construction:
//   - unreadable / malformed stdin                       → DENY
//   - a skillctl-managed skill whose §7 chain fails       → DENY (with the exit code)
//   - infra failure (no trust roots, registry unreachable)→ DENY (managed skills)
//   - a suspicious skill name (path traversal)            → DENY
//
// Skills skillctl does NOT manage (namespaced/plugin skills, project command
// skills, built-ins — no stashed .skb under ~/.claude/skills/<name>/) follow the
// configurable unmanaged-skills policy (SPEC-0247 §9), default `allow`, so the
// gate does not break the plugin ecosystem on day one.
//
// Wire shape note (SPEC-0247 OQ-1, residual): the structured-deny JSON shape
// (`hookSpecificOutput.permissionDecision`) is documented but not yet observed
// firing on this machine. To be safe against that uncertainty, a DENY is emitted
// THREE ways at once — structured JSON on stdout, a human reason on stderr, and
// process exit code 2 — so whichever mechanism the installed harness honors, the
// skill body does not load. Confirm with scripts/hook-probe.py, then narrow.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/install"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
	"gopkg.in/yaml.v3"
)

// exitHookBlock is the process exit code Claude Code interprets as "block this
// tool call" for a PreToolUse hook. It happens to equal exitUsage (2); that is
// fine — verify-hook never reports a usage error (it has no flags), so 2 here
// unambiguously means "deny".
const exitHookBlock = 2

// verifyHookTimeout bounds the per-invocation registry roundtrip. P0.1 runs the
// online §7 chain (VerifyInstalled fetches fresh metadata); the offline fast
// path + verdict cache that removes this network dependency is SPEC-0247 P1.
const verifyHookTimeout = 8 * time.Second

// --- the hook event envelope (confirmed shape, SPEC-0247 §3.4) ---

type hookEvent struct {
	HookEventName  string        `json:"hook_event_name"`
	ToolName       string        `json:"tool_name"`
	SessionID      string        `json:"session_id"`
	Cwd            string        `json:"cwd"`
	PermissionMode string        `json:"permission_mode"`
	ToolInput      hookToolInput `json:"tool_input"`
}

type hookToolInput struct {
	Skill     string `json:"skill"`      // confirmed primary field (§3.4)
	SkillName string `json:"skill_name"` // defensive fallback (docs-named)
	Name      string `json:"name"`       // defensive fallback
	Args      string `json:"args"`
}

// skillID returns the invoked skill name, trying the confirmed field first.
func (ti hookToolInput) skillID() string {
	for _, s := range []string{ti.Skill, ti.SkillName, ti.Name} {
		if t := strings.TrimSpace(s); t != "" {
			return t
		}
	}
	return ""
}

// --- decision output ---

type hookDecisionOut struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"` // "deny"
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// verifyManagedFn is the verification seam. Production points it at
// verifyManagedSkill (which talks to the registry); tests stub it so the
// decision logic can be exercised without a network or a real trust-roots file.
var verifyManagedFn = verifyManagedSkill

// hookPreflight is a no-op seam at the very top of the gate body. Production
// leaves it nil (zero cost). The panic-safety regression test sets it to a
// function that panics, proving the deferred recover converts ANY panic in the
// gate into a fail-closed DENY rather than crashing the process.
var hookPreflight func()

// runVerifyHook is the entrypoint for `skillctl verify-hook`. It returns the
// process exit code: 0 = allow, 2 = deny/block.
//
// Panic-safety by design (SPEC-0251 P1): this gate sits on the PreToolUse path,
// so a panic anywhere below (a malformed cache row, a nil seam in a future
// refactor, a registry client that dereferences nil) must NOT crash the process
// — a crash exits non-2 and the harness may interpret a non-block exit as
// "allow", silently opening the very hole the gate exists to close. The deferred
// recover therefore converts any panic into the canonical three-way DENY (exit
// 2 + decision JSON + stderr), failing closed. The named return `code` is what
// the recover overwrites.
func runVerifyHook(stdin io.Reader, stdout, stderr io.Writer) (code int) {
	defer func() {
		if r := recover(); r != nil {
			code = emitDeny(stdout, stderr,
				fmt.Sprintf("skillctl verify-hook: internal error (%v) — failing closed (DENY)", r))
		}
	}()

	if hookPreflight != nil {
		hookPreflight()
	}

	raw, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		return emitDeny(stdout, stderr, "skillctl verify-hook: unreadable hook event on stdin (fail-closed)")
	}

	var ev hookEvent
	if err := json.Unmarshal(raw, &ev); err != nil {
		return emitDeny(stdout, stderr, "skillctl verify-hook: malformed hook event JSON (fail-closed)")
	}

	// Gate only the Skill tool. A matcher mis-wired onto another tool must not
	// block it — verify-hook governs skills, nothing else.
	if ev.ToolName != "" && ev.ToolName != "Skill" {
		return emitAllow()
	}

	skill := ev.ToolInput.skillID()
	if skill == "" {
		return emitAllow() // nothing to gate
	}

	// A skill name that could escape ~/.claude/skills/ is itself a red flag.
	if strings.ContainsAny(skill, "/\\") || strings.Contains(skill, "..") {
		return emitDeny(stdout, stderr,
			fmt.Sprintf("skillctl: BLOCKED %q — suspicious skill name (path traversal); refusing (fail-closed)", skill))
	}

	pol := loadGatePolicyW(stderr)

	if pol.isAllowlisted(skill) {
		return emitAllow() // explicit operator escape hatch (§9.4)
	}

	managed, why := isManagedSkill(skill)
	if !managed {
		switch pol.Unmanaged {
		case "deny":
			return emitDeny(stdout, stderr,
				fmt.Sprintf("skillctl: BLOCKED '%s' — not skillctl-managed (%s) and policy unmanaged_skills=deny. Import it with `skillctl import` or allowlist it.", skill, why))
		case "warn":
			fmt.Fprintf(stderr, "skillctl verify-hook: WARN unverified skill '%s' (%s) — allowed by policy unmanaged_skills=warn\n", skill, why)
			return emitAllow()
		default: // "allow"
			return emitAllow()
		}
	}

	// Managed skill → offline fast path first: a fresh, digest-matching PASS
	// in the verdict cache (written by the SessionStart sweep or a prior hook)
	// lets us allow without touching the network (SPEC-0247 §8 / P1.1).
	home, _ := userHome()
	now := time.Now()
	if home != "" && cachedAllow(home, skill, ev.SessionID, now) {
		return emitAllow()
	}

	// Cache miss → prefer the network-free offline chain (no registry call, and
	// it binds the on-disk body to the signed .skb so an edited SKILL.md is
	// caught). Fall back to the online chain only for legacy installs that have
	// no stashed offline metadata.
	//
	// NB: `code` is the function's named return (declared in the signature so the
	// deferred recover can overwrite it on panic); we reuse it here rather than
	// shadowing it with a fresh `var code int`.
	var reason string
	if home != "" {
		if c, r, ok := verifyManagedOfflineFn(skill, pol, home); ok {
			code, reason = c, r
		} else {
			code, reason = verifyManagedFn(skill, pol)
		}
		recordVerdict(home, skill, ev.SessionID, code, "", now)
	} else {
		code, reason = verifyManagedFn(skill, pol)
	}
	if code == exitOK {
		return emitAllow()
	}
	return emitDeny(stdout, stderr,
		fmt.Sprintf("skillctl: BLOCKED '%s' — %s (exit %d). Run `skillctl verify %s` for the full chain, or `skillctl install %s` to repair.",
			skill, reason, code, skill, skill))
}

// emitAllow lets the tool proceed. SPEC-0247 §5.3: an allow emits nothing and
// exits 0, so it never overrides a deny from another hook in the chain.
func emitAllow() int { return exitOK }

// emitDeny blocks the tool call three ways (see file header): structured JSON on
// stdout, a human reason on stderr, and process exit 2.
func emitDeny(stdout, stderr io.Writer, reason string) int {
	out := hookDecisionOut{HookSpecificOutput: hookSpecificOutput{
		HookEventName:            "PreToolUse",
		PermissionDecision:       "deny",
		PermissionDecisionReason: reason,
	}}
	if b, err := json.Marshal(out); err == nil {
		fmt.Fprintln(stdout, string(b))
	}
	fmt.Fprintln(stderr, reason)
	return exitHookBlock
}

// verifyManagedSkill runs the online §7 chain against an installed skill, using
// the same trust-root resolution as `skillctl verify`. Returns (exitCode,
// human-reason); exitOK with empty reason means the chain passed.
func verifyManagedSkill(name string, pol gatePolicy) (int, string) {
	tr, root, err := loadAndPickRoot("")
	if err != nil {
		// No trust roots / ambiguous registry: a managed skill cannot be
		// verified, so fail closed rather than wave it through.
		return exitGeneric, "trust roots unavailable (" + err.Error() + ")"
	}
	tenant := resolveTenant("", tr)
	httpClient := install.HTTPClientOf(verifyHookTimeout)
	c := registry.New(root.RegistryURL, httpClient)

	_, err = install.VerifyInstalled(install.Opts{
		Name:          name,
		Client:        c,
		TrustRoot:     root,
		GovernanceMin: pol.ManagedMinGovernance,
		Tenant:        tenant,
		Ctx:           context.Background(),
	})
	if err == nil {
		return exitOK, ""
	}
	code := verify.ExitCode(err)
	return code, reasonForExit(code, err)
}

// verifyManagedOfflineFn is the network-free verification seam (SPEC-0247
// offline path). It returns (exitCode, reason, available); available=false
// means "no usable offline metadata / trust roots" → the caller should fall
// back to the online chain. Stubbed in tests.
var verifyManagedOfflineFn = verifyManagedOffline

// verifyManagedOffline runs the §7 chain with NO network (stashed BundleMeta +
// identity + local trust roots) and the extracted-content binding check. It is
// "available" only when it produced a real §7 verdict; a missing stash or
// missing trust roots returns available=false so the hook/sweep can fall back.
func verifyManagedOffline(name string, pol gatePolicy, home string) (int, string, bool) {
	tr, root, rootErr := loadRootsFn("")

	// Tier 1: full §7 offline (SPEC-0188 install path: .skb + offline-meta).
	// Needs trust roots; skip the tier (not the whole verify) when absent so the
	// sidecar tier below can still run.
	if rootErr == nil {
		_, vErr := install.VerifyInstalledOffline(install.Opts{
			Name:          name,
			TrustRoot:     root,
			HomeDir:       home,
			GovernanceMin: pol.ManagedMinGovernance,
			Tenant:        resolveTenant("", tr),
			Ctx:           context.Background(),
		})
		if !errors.Is(vErr, install.ErrNoOfflineMeta) {
			if vErr == nil {
				return exitOK, "", true
			}
			code := verify.ExitCode(vErr)
			return code, reasonForExit(code, vErr), true
		}
	}

	// Tier 2: sidecar path (self/ER1 pull, SPEC-0225): content-binding +
	// governance floor from .m3c-provenance.json.
	sErr := install.VerifyInstalledSidecar(install.Opts{
		Name:          name,
		TrustRoot:     root,
		HomeDir:       home,
		GovernanceMin: pol.ManagedMinGovernance,
	})
	if errors.Is(sErr, registry.ErrNoSidecar) {
		return 0, "", false // neither offline-meta nor sidecar → fall back to online
	}
	if sErr == nil {
		return exitOK, "", true
	}
	code := verify.ExitCode(sErr)
	return code, reasonForExit(code, sErr), true
}

// reasonForExit turns a SPEC-0188 §11 numeric code into a short human phrase.
func reasonForExit(code int, err error) string {
	switch code {
	case verify.ExitDigestMismatch:
		return "bundle modified after signing (digest mismatch)"
	case verify.ExitAuthorSigInvalid:
		return "author signature invalid"
	case verify.ExitRegistryNotTrusted:
		return "registry not in trust roots"
	case verify.ExitGovernanceBelowMin:
		return "governance below required minimum"
	case verify.ExitDepsUnsatisfied:
		return "depends_on unsatisfied"
	case verify.ExitBlobMissing:
		return "bundle blob missing / revoked from registry"
	case verify.ExitTenantBlocked:
		return "blocked by CISO tenant verdict"
	case 17:
		return "author identity revoked"
	default:
		if err != nil {
			return "verification failed: " + err.Error()
		}
		return "verification failed"
	}
}

// --- managed/unmanaged classification ---

// isManagedSkill reports whether <name> is a skillctl-installed skill: a
// directory ~/.claude/skills/<name>/ that contains a stashed .skb. The second
// return value is a human reason when it is NOT managed.
func isManagedSkill(name string) (bool, string) {
	if strings.Contains(name, ":") {
		return false, "namespaced/plugin skill"
	}
	home, err := userHome()
	if err != nil {
		return false, "cannot resolve home dir"
	}
	dir := filepath.Join(home, ".claude", "skills", name)
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return false, "not installed under ~/.claude/skills"
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, "unreadable skill dir"
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// A stashed .skb (skillctl install / post-SPEC-0247 pull) OR a
		// .m3c-provenance.json sidecar (self/ER1 pull, SPEC-0225) both mark a
		// skillctl-managed skill.
		if strings.HasSuffix(e.Name(), ".skb") || e.Name() == ".m3c-provenance.json" {
			return true, ""
		}
	}
	return false, "no .skb / provenance sidecar (not skillctl-installed)"
}

// --- gate policy (SPEC-0247 §9) ---

type gatePolicy struct {
	Unmanaged            string   `yaml:"unmanaged_skills"`       // allow | warn | deny
	Allowlist            []string `yaml:"allowlist"`              // names always allowed
	ManagedMinGovernance string   `yaml:"managed_min_governance"` // green | yellow
}

func defaultGatePolicy() gatePolicy { return gatePolicy{Unmanaged: "allow"} }

// loadGatePolicy reads ~/.claude/skillctl/gate-policy.yaml.
//
// A MISSING file yields safe defaults (unmanaged=allow, managed still verified)
// — the gate must not brick a fresh machine that never wrote a policy.
//
// A PRESENT-BUT-BROKEN file (malformed YAML, or an unknown/misspelled field)
// fails CLOSED (SPEC-0251 SEC-L2, mirroring the SPEC-0188 strict trust-roots
// loader): the operator clearly INTENDED a policy, so silently discarding it and
// falling back to unmanaged=allow would turn a typo — e.g. `unmanaged_skils:
// deny` — into an allow-all, defeating the gate. Instead we treat the unmanaged
// disposition as `deny` and log a clear warning to stderr. Parsing is strict
// (yaml.Decoder + KnownFields(true)) so an unknown field is an error, not a
// silently-ignored line.
//
// The env var SKILLCTL_GATE_UNMANAGED still overrides the final disposition, so
// an operator who knows what they are doing can recover without editing the file.
//
// loadGatePolicy is the zero-arg convenience form (callers that have no captured
// stderr — e.g. the sweep in verify_all_cmds.go, and direct unit tests). It logs
// the fail-closed WARN to the process os.Stderr. The verify-hook gate uses
// loadGatePolicyW so the WARN lands on the SAME stderr writer the harness
// captures (otherwise the operator never sees the "failing closed" signal on the
// hook's stderr stream, only the BLOCKED reason).
func loadGatePolicy() gatePolicy {
	return loadGatePolicyW(os.Stderr)
}

// loadGatePolicyW is loadGatePolicy with an explicit warn sink so the fail-closed
// WARN can be routed to the gate's captured stderr.
func loadGatePolicyW(warn io.Writer) gatePolicy {
	p := defaultGatePolicy()
	if home, err := userHome(); err == nil {
		path := filepath.Join(home, ".claude", "skillctl", "gate-policy.yaml")
		if data, err := os.ReadFile(path); err == nil {
			var loaded gatePolicy
			dec := yaml.NewDecoder(bytes.NewReader(data))
			dec.KnownFields(true) // strict: unknown/misspelled fields → error
			if derr := dec.Decode(&loaded); derr != nil {
				// Present but unparseable → fail closed for the unmanaged
				// disposition rather than silently reverting to allow-all.
				fmt.Fprintf(warn,
					"skillctl verify-hook: WARN gate-policy.yaml at %s is invalid (%v) — failing closed: treating unmanaged_skills as deny. Fix the policy or set SKILLCTL_GATE_UNMANAGED.\n",
					path, derr)
				p.Unmanaged = "deny"
			} else {
				if loaded.Unmanaged != "" {
					p.Unmanaged = loaded.Unmanaged
				}
				p.Allowlist = loaded.Allowlist
				p.ManagedMinGovernance = loaded.ManagedMinGovernance
			}
		}
		// A missing file (os.ReadFile error) keeps the safe default — see doc.
	}
	if e := strings.TrimSpace(os.Getenv("SKILLCTL_GATE_UNMANAGED")); e != "" {
		p.Unmanaged = e
	}
	return p
}

func (p gatePolicy) isAllowlisted(name string) bool {
	for _, a := range p.Allowlist {
		if strings.TrimSpace(a) == name {
			return true
		}
	}
	return false
}
