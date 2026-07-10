// Package pin implements SPEC-0247 §7.3 managed-settings pinning.
//
// It generates the Claude Code *managed settings* file that wires the skillctl
// trust gate (SPEC-0247 §7.1: a SessionStart sweep + a PreToolUse(Skill)
// verify-hook) into the one settings tier a non-privileged user cannot edit,
// and it verifies whether that pinning is currently active. Stdlib-only; the
// privileged install itself is a human/runbook step (the file lives under a
// root-owned system directory).
//
// Verified mechanism (Claude Code docs, fetched 2026-07-08):
//   - Managed settings occupy the HIGHEST precedence tier; nothing — not even a
//     CLI flag or `--dangerously-skip-permissions` — overrides them.
//   - A hook defined in managed settings cannot be suppressed or deleted by
//     user/project settings, so the gate becomes un-deletable by non-root users
//     (root, or anyone who can write the managed-settings dir, still can —
//     SPEC-0247 §3.2).
//   - A PreToolUse hook returning "deny" blocks even under
//     `--dangerously-skip-permissions`, and a user "allow" hook can never
//     override a "deny" — so a managed deny is absolute.
//   - `allowManagedHooksOnly: true` (STRICT) additionally blocks ALL user and
//     project hooks. That is the CISO lockdown, but it also disables any OTHER
//     user hooks the operator relies on (e.g. usage telemetry) — callers MUST
//     warn about this. Without it, the gate is still un-deletable by non-root
//     users and its deny is still absolute; the operator's own hooks keep working.
//
// This package makes no privileged writes and reaches no network.
package pin

import (
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"strings"
)

// ManagedSettingsPath returns the platform managed-settings.json path for goos
// ("darwin"/"linux"/"windows"); pass runtime.GOOS in production. The paths are
// the documented, admin/root-owned locations. An unknown goos is an error
// rather than a silent guess (fail-closed).
func ManagedSettingsPath(goos string) (string, error) {
	switch goos {
	case "darwin":
		return "/Library/Application Support/ClaudeCode/managed-settings.json", nil
	case "linux":
		return "/etc/claude-code/managed-settings.json", nil
	case "windows":
		return `C:\Program Files\ClaudeCode\managed-settings.json`, nil
	default:
		return "", fmt.Errorf("pin: no known managed-settings path for GOOS %q", goos)
	}
}

// DefaultManagedSettingsPath resolves the path for the running OS.
func DefaultManagedSettingsPath() (string, error) { return ManagedSettingsPath(runtime.GOOS) }

// GenerateOptions controls the emitted managed settings.
type GenerateOptions struct {
	// BinaryPath is the skillctl binary the hooks invoke. SPEC-0247 §7.2
	// recommends an absolute path so a missing binary fails the spawn (and is
	// noticed) rather than resolving to nothing. Empty → the bare name "skillctl".
	BinaryPath string
	// Strict adds `allowManagedHooksOnly: true` (blocks ALL non-managed hooks).
	Strict bool
	// Harden implies Strict and also sets `disableBypassPermissionsMode:"disable"`.
	Harden bool
	// Enterprise emits `skillctlEnterprise: true` — the SPEC-0317 R-7.2 opt-in
	// that the runtime gate reads to enable the `offline_locked` state. It lives
	// HERE (the root-owned managed-settings tier), deliberately separate from the
	// trust-roots verification material: declaring "enterprise" must not itself
	// create a trust basis (that conflation made `locked` unreachable). Claude
	// Code ignores the unknown key (its schema is additive); skillctl reads it.
	Enterprise bool
	// RequireLocalAudit emits `skillctlRequireLocalAudit: true` — the SPEC-0317
	// R-8.2 opt-in that inverts the SPEC-0255 fire-and-forget audit contract: when
	// set, `skillctl enforce` fails CLOSED (exit 26) if an ALLOW's evidence cannot
	// be durably recorded. It is ENTERPRISE-ONLY, so setting it also emits
	// skillctlEnterprise:true. Same root-owned managed tier as Enterprise, so the
	// two enterprise knobs share ONE source (closing the R-7.2 F3 split).
	//
	// SCOPE: this escalates EVERY audited Skill allow that can't be recorded —
	// managed, UNMANAGED (default-allow plugins/namespaced skills), AND allowlisted.
	// On a host with an unrecordable outbox it therefore denies the plugin ecosystem
	// and the operator's allowlisted escapes too; that is the intended "no un-audited
	// allow" posture, not a bug. Enable it deliberately.
	RequireLocalAudit bool
	// StateGateFallback emits `skillctlStateGateFallback: true` — the SPEC-0317
	// R-1.4 P2 opt-in that state-gates the verify-hook's ONLINE fallback (the §7
	// network chain used only for LEGACY installs that carry no offline metadata).
	// When set, that fallback runs only in the state machine's `online` state; the
	// gate is offline-first (it does NOT probe the registry on the hot path), so in
	// practice the hot path stays STRICTLY LOCAL and a legacy install with no offline
	// metadata fails CLOSED (offline_unverifiable_managed) instead of blocking on an
	// 8s network round-trip. ENTERPRISE-ONLY, so setting it also emits
	// skillctlEnterprise:true — same root-owned managed tier as the other knobs.
	//
	// NEVER-BRICK: this only ever affects LEGACY managed installs missing offline
	// metadata; modern installs verify offline and never reach the fallback. It is
	// opt-in precisely so a disconnected NON-enterprise host keeps its network
	// fallback (turning it on by default would fail-close legacy installs offline).
	StateGateFallback bool
}

// wire structs — field order here is the emitted JSON key order (encoding/json
// preserves struct field order). Security flags first, then hooks.
type hookCommand struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}
type hookMatcher struct {
	Matcher string        `json:"matcher"`
	Hooks   []hookCommand `json:"hooks"`
}
type hooksBlock struct {
	SessionStart []hookMatcher `json:"SessionStart,omitempty"`
	PreToolUse   []hookMatcher `json:"PreToolUse,omitempty"`
}
type managedSettings struct {
	AllowManagedHooksOnly        bool       `json:"allowManagedHooksOnly,omitempty"`
	DisableBypassPermissionsMode string     `json:"disableBypassPermissionsMode,omitempty"`
	SkillctlEnterprise           bool       `json:"skillctlEnterprise,omitempty"`
	SkillctlRequireLocalAudit    bool       `json:"skillctlRequireLocalAudit,omitempty"`
	SkillctlStateGateFallback    bool       `json:"skillctlStateGateFallback,omitempty"`
	Hooks                        hooksBlock `json:"hooks"`
}

// Canonical gate command shapes (SPEC-0247 §7.1). Verify() matches on the
// command's *argv shape* — the binary basename must be skillctl and the
// subcommand tokens must match — NOT a loose substring, so decoys like
// `echo verify-hook` or exit-suppressed `skillctl verify-hook || true` (which
// would turn every DENY into an ALLOW) are rejected.
const (
	verifyHookSub = "verify-hook"
	sweepSub      = "verify" // + must carry --all and --quarantine
)

func binaryOrDefault(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "skillctl"
	}
	return p
}

// quoteIfNeeded shell-quotes a binary path that contains whitespace so the
// generated command string stays a single argv[0].
func quoteIfNeeded(p string) string {
	if strings.ContainsAny(p, " \t") {
		return `"` + p + `"`
	}
	return p
}

// gateHooks builds the SessionStart sweep + PreToolUse(Skill) matchers for a
// given binary, exactly per SPEC-0247 §7.1.
func gateHooks(binary string) hooksBlock {
	b := quoteIfNeeded(binaryOrDefault(binary))
	return hooksBlock{
		SessionStart: []hookMatcher{{
			Matcher: "*",
			Hooks:   []hookCommand{{Type: "command", Command: b + " verify --all --quarantine", Timeout: 90}},
		}},
		PreToolUse: []hookMatcher{{
			Matcher: "Skill",
			Hooks:   []hookCommand{{Type: "command", Command: b + " verify-hook", Timeout: 20}},
		}},
	}
}

// Generate returns the pretty-printed managed-settings.json bytes for the given
// options (trailing newline included).
func Generate(opts GenerateOptions) ([]byte, error) {
	ms := managedSettings{Hooks: gateHooks(opts.BinaryPath)}
	if opts.Enterprise {
		ms.SkillctlEnterprise = true
	}
	if opts.RequireLocalAudit {
		ms.SkillctlEnterprise = true // require_local_audit is enterprise-only
		ms.SkillctlRequireLocalAudit = true
	}
	if opts.StateGateFallback {
		ms.SkillctlEnterprise = true // state-gating the fallback is enterprise-only
		ms.SkillctlStateGateFallback = true
	}
	if opts.Strict || opts.Harden {
		ms.AllowManagedHooksOnly = true
	}
	if opts.Harden {
		ms.DisableBypassPermissionsMode = "disable"
	}
	b, err := json.MarshalIndent(ms, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Level classifies the managed-settings file's gate-pinning state.
type Level int

const (
	// LevelAbsent — no managed-settings file exists (gate is advisory: a
	// user-level hook, if any, is deletable). Set by the caller when the file
	// is missing; Verify never returns it.
	LevelAbsent Level = iota
	// LevelTampered — the file exists but is not valid JSON.
	LevelTampered
	// LevelPartial — valid JSON, but one or both gate hooks are missing.
	LevelPartial
	// LevelPinned — both gate hooks are present in managed settings; the gate is
	// un-deletable and its deny is absolute. User hooks still run.
	LevelPinned
	// LevelPinnedStrict — LevelPinned + allowManagedHooksOnly:true; no
	// non-managed hooks run at all (full CISO lockdown).
	LevelPinnedStrict
)

// MarshalJSON emits the human string ("pinned-strict", …) instead of the int,
// so `pin status --json` and any downstream consumer read a stable label.
func (l Level) MarshalJSON() ([]byte, error) { return json.Marshal(l.String()) }

func (l Level) String() string {
	switch l {
	case LevelAbsent:
		return "absent"
	case LevelTampered:
		return "tampered"
	case LevelPartial:
		return "partial"
	case LevelPinned:
		return "pinned"
	case LevelPinnedStrict:
		return "pinned-strict"
	default:
		return "unknown"
	}
}

// StatusResult reports what Verify found. It is a pure read; nothing here gates
// a decision.
type StatusResult struct {
	Level                 Level    `json:"level"`
	HasSweepHook          bool     `json:"has_sweep_hook"`  // SessionStart → verify --all --quarantine
	HasVerifyHook         bool     `json:"has_verify_hook"` // PreToolUse(Skill) → verify-hook
	AllowManagedHooksOnly bool     `json:"allow_managed_hooks_only"`
	DisableBypass         bool     `json:"disable_bypass_permissions_mode"`
	Findings              []string `json:"findings,omitempty"`
}

// Pinned reports whether the gate is un-deletable (Pinned or PinnedStrict).
func (s StatusResult) Pinned() bool {
	return s.Level == LevelPinned || s.Level == LevelPinnedStrict
}

// EnterpriseFromBytes reports whether managed settings enable the SPEC-0317
// R-7.2 enterprise posture (`skillctlEnterprise: true`) — the opt-in the runtime
// gate reads to permit the destructive `offline_locked` state.
//
// It is deliberately conservative and the OPPOSITE of the gate-hook checks: a
// MISSING or MALFORMED managed file yields false, so an unreadable managed file
// can never ENGAGE `locked` (R-7.2 never-brick priority — locking on a corrupt
// file would brick a host). Only a cleanly-parsed true engages it. It lives in
// the root-owned managed tier precisely so declaring "enterprise" does NOT create
// a trust basis (the conflation that made `locked` unreachable).
func EnterpriseFromBytes(settings []byte) bool {
	var ms managedSettings
	if json.Unmarshal(settings, &ms) != nil {
		return false
	}
	return ms.SkillctlEnterprise
}

// RequireLocalAuditFromBytes reports whether managed settings enable the
// SPEC-0317 R-8.2 require_local_audit posture. Enterprise-GATED: true only when
// BOTH skillctlEnterprise AND skillctlRequireLocalAudit are set — the
// decision-invariance carve-out cannot be enabled on a non-enterprise host (the
// same floor verify.Load enforced for the trust-roots surface). Same conservative
// contract as EnterpriseFromBytes: missing/malformed → false.
func RequireLocalAuditFromBytes(settings []byte) bool {
	var ms managedSettings
	if json.Unmarshal(settings, &ms) != nil {
		return false
	}
	return ms.SkillctlEnterprise && ms.SkillctlRequireLocalAudit
}

// StateGateFallbackFromBytes reports whether managed settings enable the
// SPEC-0317 R-1.4 P2 posture that state-gates the verify-hook's online fallback.
// Enterprise-GATED like RequireLocalAuditFromBytes (true only when BOTH
// skillctlEnterprise AND skillctlStateGateFallback are set) and equally
// conservative: missing/malformed → false, so an unreadable managed file can
// never fail-close a legacy install's network fallback (never-brick).
func StateGateFallbackFromBytes(settings []byte) bool {
	var ms managedSettings
	if json.Unmarshal(settings, &ms) != nil {
		return false
	}
	return ms.SkillctlEnterprise && ms.SkillctlStateGateFallback
}

// Verify parses managed-settings bytes and reports the pinning level. It matches
// gate hooks by *argv shape under a covering matcher*, not by substring, so a
// hook wired under the wrong matcher (e.g. "Bash") or a decoy/exit-suppressed
// command does NOT falsely classify as pinned. json.Unmarshal rejects trailing
// bytes after the first JSON value, so `{good}{evil}` is LevelTampered. A parse
// failure is LevelTampered (fail-closed: an unreadable managed file is NOT
// treated as pinned).
func Verify(settings []byte) StatusResult {
	var res StatusResult
	var ms managedSettings
	if err := json.Unmarshal(settings, &ms); err != nil {
		res.Level = LevelTampered
		res.Findings = append(res.Findings, "managed-settings.json is not valid JSON: "+err.Error())
		return res
	}
	res.AllowManagedHooksOnly = ms.AllowManagedHooksOnly
	res.DisableBypass = ms.DisableBypassPermissionsMode == "disable"
	res.HasSweepHook = hasGateHook(ms.Hooks.SessionStart, sessionStartCovers, isSweepCommand)
	res.HasVerifyHook = hasGateHook(ms.Hooks.PreToolUse, preToolUseCovers, isVerifyHookCommand)

	switch {
	case res.HasSweepHook && res.HasVerifyHook && res.AllowManagedHooksOnly:
		res.Level = LevelPinnedStrict
	case res.HasSweepHook && res.HasVerifyHook:
		res.Level = LevelPinned
	default:
		res.Level = LevelPartial
	}
	if !res.HasVerifyHook {
		res.Findings = append(res.Findings, "no PreToolUse(Skill) → skillctl verify-hook (the run-time gate): missing, bound to a non-Skill matcher, or an exit-suppressed/decoy command")
	}
	if !res.HasSweepHook {
		res.Findings = append(res.Findings, "no SessionStart(*) → skillctl verify --all --quarantine (the discovery sweep)")
	}
	if res.Pinned() && !res.AllowManagedHooksOnly {
		res.Findings = append(res.Findings, "gate is un-deletable by non-root users, but not strict: a user may still run their own hooks (a managed deny still wins). Use --strict for the full CISO lockdown.")
	}
	if res.Pinned() && res.AllowManagedHooksOnly {
		res.Findings = append(res.Findings, "un-deletable by non-root users only — root, or anyone with write access to the managed-settings directory, can still remove or rewrite it (SPEC-0247 §7.3, §3.2).")
	}
	return res
}

// hasGateHook reports whether any matcher that COVERS the target tool carries a
// command with the required gate shape.
func hasGateHook(matchers []hookMatcher, covers func(string) bool, shapeOK func(cmd string) bool) bool {
	for _, m := range matchers {
		if !covers(m.Matcher) {
			continue
		}
		for _, h := range m.Hooks {
			if shapeOK(h.Command) {
				return true
			}
		}
	}
	return false
}

// preToolUseCovers reports whether a PreToolUse matcher fires on the Skill tool.
// Claude Code matchers are REGEX (e.g. "Edit|Write", "Skill.*"), so we test the
// matcher — anchored to a full match — against the literal "Skill", plus the
// "*"/"" match-all shorthands. A matcher that fails to compile falls back to an
// exact/"|"-token check, so a plain "Skill" is never missed.
func preToolUseCovers(matcher string) bool {
	m := strings.TrimSpace(matcher)
	if m == "" || m == "*" {
		return true
	}
	if re, err := regexp.Compile("^(?:" + m + ")$"); err == nil {
		return re.MatchString("Skill")
	}
	for _, tok := range strings.Split(m, "|") {
		if strings.TrimSpace(tok) == "Skill" {
			return true
		}
	}
	return false
}

// sessionStartCovers: the sweep must run on every session start ("*" or "").
func sessionStartCovers(matcher string) bool {
	m := strings.TrimSpace(matcher)
	return m == "" || m == "*"
}

// isVerifyHookCommand requires exactly `<...>/skillctl verify-hook` with no
// trailing arguments and no shell control (which could suppress the exit code).
func isVerifyHookCommand(cmd string) bool {
	bin, args, ok := splitCommand(cmd)
	if !ok || !isSkillctlBinary(bin) {
		return false
	}
	return len(args) == 1 && args[0] == verifyHookSub
}

// isSweepCommand requires `<...>/skillctl verify --all --quarantine` (extra
// flags such as --json are tolerated; shell control is not). NOTE: a
// self-sabotaging operator can still pass a neutering flag (e.g. --budget 1ns,
// --home /nonexistent) that leaves the sweep present-but-ineffective. That is a
// root-configures-own-foot-gun, out of scope like the same-uid attacker
// (SPEC-0247 §3.2); the per-invocation DENY gate (isVerifyHookCommand) is
// arg-locked and not subject to this.
func isSweepCommand(cmd string) bool {
	bin, args, ok := splitCommand(cmd)
	if !ok || !isSkillctlBinary(bin) {
		return false
	}
	if len(args) < 3 || args[0] != sweepSub {
		return false
	}
	return containsToken(args, "--all") && containsToken(args, "--quarantine")
}

func containsToken(ss []string, tok string) bool {
	for _, s := range ss {
		if s == tok {
			return true
		}
	}
	return false
}

// isSkillctlBinary checks the command's argv[0] basename is skillctl, so a decoy
// like `echo verify-hook` or `/bin/true verify-hook` is rejected.
func isSkillctlBinary(bin string) bool {
	base := bin
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	return base == "skillctl" || base == "skillctl.exe"
}

// splitCommand splits a hook command into argv[0] (binary, optionally single-
// or double-quoted with spaces) and the remaining whitespace-separated args. It
// returns ok=false if the command carries shell control that could alter the
// gate's exit code (|| && ; | > < ` $ newline #), or if a quoted binary is
// concatenated to more text with no separating whitespace (e.g.
// `"skillctl"verify-hook`, which the shell would run as the single word
// `skillctlverify-hook` → command-not-found → gate fails open) — such a command
// is never a trustworthy gate.
func splitCommand(cmd string) (bin string, args []string, ok bool) {
	c := strings.TrimSpace(cmd)
	if c == "" || containsShellControl(c) {
		return "", nil, false
	}
	if q := c[0]; q == '"' || q == '\'' {
		end := strings.IndexByte(c[1:], q)
		if end < 0 {
			return "", nil, false
		}
		bin = c[1 : 1+end]
		rem := c[1+end+1:]
		// The closing quote MUST end the token: end-of-string or whitespace.
		if rem != "" && rem[0] != ' ' && rem[0] != '\t' {
			return "", nil, false
		}
		return bin, strings.Fields(rem), true
	}
	fields := strings.Fields(c)
	if len(fields) == 0 {
		return "", nil, false
	}
	return fields[0], fields[1:], true
}

// containsShellControl reports whether a command carries shell metacharacters
// that could suppress or override the gate's exit code (the `verify-hook || true`
// class). The canonical gate commands contain none of these.
func containsShellControl(cmd string) bool {
	return strings.ContainsAny(cmd, "|&;<>`$\n\r#")
}

// Merge injects skillctl's gate hooks into an EXISTING managed-settings.json,
// preserving every other key (other managed hooks, permission rules, env). It is
// idempotent — a file already carrying the covering gate hook is not
// duplicated — and never drops other entries. Empty/whitespace input returns a
// fresh Generate(opts). Invalid existing JSON is an error (refuse to overwrite).
func Merge(existing []byte, opts GenerateOptions) ([]byte, error) {
	if len(strings.TrimSpace(string(existing))) == 0 {
		return Generate(opts)
	}
	var doc map[string]any
	if err := json.Unmarshal(existing, &doc); err != nil {
		return nil, fmt.Errorf("existing managed-settings is not valid JSON (refusing to overwrite): %w", err)
	}
	gh := gateHooks(opts.BinaryPath)

	hooks, _ := doc["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	hooks["SessionStart"] = mergeMatcher(hooks["SessionStart"], gh.SessionStart[0], sessionStartCovers, isSweepCommand)
	hooks["PreToolUse"] = mergeMatcher(hooks["PreToolUse"], gh.PreToolUse[0], preToolUseCovers, isVerifyHookCommand)
	doc["hooks"] = hooks

	if opts.Strict || opts.Harden {
		doc["allowManagedHooksOnly"] = true
	}
	if opts.Harden {
		doc["disableBypassPermissionsMode"] = "disable"
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// mergeMatcher appends our gate matcher to an existing event array unless a
// shape-valid gate command already exists UNDER A COVERING MATCHER (idempotent).
// A shape-valid command under a NON-covering matcher (e.g. verify-hook under
// "Bash") does NOT satisfy the gate, so we still append our covering matcher —
// otherwise the merged file would fail its own Verify. Foreign entries are
// preserved verbatim.
func mergeMatcher(existing any, want hookMatcher, covers func(string) bool, shapeOK func(string) bool) []any {
	arr, _ := existing.([]any)
	for _, e := range arr {
		em, _ := e.(map[string]any)
		if em == nil {
			continue
		}
		matcher, _ := em["matcher"].(string)
		if !covers(matcher) {
			continue
		}
		hs, _ := em["hooks"].([]any)
		for _, h := range hs {
			hm, _ := h.(map[string]any)
			if hm == nil {
				continue
			}
			if cmd, _ := hm["command"].(string); shapeOK(cmd) {
				return arr // already covered by a covering matcher
			}
		}
	}
	// Append our matcher as a fresh map so it round-trips like the others.
	add := map[string]any{"matcher": want.Matcher, "hooks": []any{}}
	hs := []any{}
	for _, h := range want.Hooks {
		hc := map[string]any{"type": h.Type, "command": h.Command}
		if h.Timeout != 0 {
			hc["timeout"] = h.Timeout
		}
		hs = append(hs, hc)
	}
	add["hooks"] = hs
	return append(arr, add)
}
