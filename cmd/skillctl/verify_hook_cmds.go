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
	"github.com/kamir/m3c-tools/pkg/skillctl/pin"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/statemachine"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
	"github.com/kamir/m3c-tools/pkg/skillgate"
	"gopkg.in/yaml.v3"
)

// exitOfflineLocked is the semantic exit code carried in the message + signed
// refusal_code when the SPEC-0317 R-7.2 `locked` state denies a managed skill.
// The PROCESS still exits exitHookBlock (2); this rides the message, mirroring
// exitBundleRevoked (17) / exitRevocationStale (22) / exitSidechannelDenied (27).
const exitOfflineLocked = 28 // = exitcode.OfflineLocked.Number

// exitOfflineUnverifiable is the semantic code carried in the SPEC-0317 R-1.4 P2
// deny: state-gate-fallback is set and a LEGACY managed install with no offline
// metadata would otherwise reach the online §7 chain. The PROCESS still exits
// exitHookBlock (2); the number rides the message + signed refusal_code, mirroring
// exitOfflineLocked. 25 is deliberately below the skillgate 30–39 live-exit band
// (SPEC-0202 §8.2). TestExitConsts_MatchRegistry pins it to the registry.
const exitOfflineUnverifiable = 25 // = exitcode.OfflineUnverifiable.Number

// gateManagedEnterprise reports whether the ROOT-OWNED managed settings enable
// the SPEC-0317 enterprise posture (`skillctlEnterprise: true`). This is the ONLY
// source of the `locked` opt-in (Option B): sourcing it from the trust-roots file
// would make declaring "enterprise" itself create a trust basis — the conflation
// that left `locked` unreachable. A missing/unreadable/malformed managed file →
// false (never-brick: `locked` is the most destructive posture and must not
// engage on a file we cannot cleanly read). Seam: tests set it directly.
var gateManagedEnterprise = func() bool {
	path, err := pin.DefaultManagedSettingsPath()
	if err != nil {
		return false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return pin.EnterpriseFromBytes(b)
}

// gateOfflineStateDeniesManaged reports whether the SPEC-0317 R-7.2 `locked`
// state denies this (already-classified-managed) skill. Seam for tests.
//
// It performs NO network probe: `locked` depends only on the managed enterprise
// opt-in AND trust-basis presence (Compute checks locked BEFORE RegistryReachable),
// so the hot path stays strictly local. It fast-paths to false for every
// non-enterprise host BEFORE any filesystem gather — so a default machine pays
// nothing and AC-1 byte-parity holds trivially.
var gateOfflineStateDeniesManaged = defaultGateOfflineStateDeniesManaged

func defaultGateOfflineStateDeniesManaged(home string, now time.Time) bool {
	if !gateManagedEnterprise() {
		return false // never-brick: only a managed-enterprise host can ever lock
	}
	pol, _ := resolveSessionOfflinePolicy(home, "") // the freshness knobs
	// SPEC-0317 R-7.2 (Option B): the enterprise opt-in for `locked` comes from the
	// managed settings, overriding whatever the trust-roots offline_policy declared.
	// NOTE: pol.RequireLocalAudit still originates from trust-roots and is inert
	// today (Compute/gate never read it). When R-8 wires require_local_audit, its
	// enterprise source must be reconciled with this one before it is consumed.
	pol.Enterprise = true
	in := sessionBaselineGather(home, false, now) // forceOnline=false; locked ignores reachability
	return statemachine.DenyAllManaged(statemachine.Compute(in, pol))
}

// gateStateGatesFallback reports whether the ROOT-OWNED managed settings enable
// the SPEC-0317 R-1.4 P2 posture that state-gates the online fallback
// (`skillctlStateGateFallback: true`, enterprise-gated). Same source + conservative
// contract as gateManagedEnterprise: a missing/unreadable/malformed managed file →
// false, so an unreadable file can never fail-close a legacy install's network
// fallback (never-brick). Seam: tests set it directly.
var gateStateGatesFallback = func() bool {
	path, err := pin.DefaultManagedSettingsPath()
	if err != nil {
		return false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return pin.StateGateFallbackFromBytes(b)
}

// gateSkipOnlineFallback reports whether the SPEC-0317 R-1.4 P2 state-gate should
// SUPPRESS the online §7 fallback for this invocation — i.e. the operator opted in
// AND the state machine is not in `online`. Seam for tests.
//
// Like the R-7.2 locked gate it performs NO network probe: the offline-first
// gather sets RegistryReachable=false, so Compute never yields StateOnline on the
// hot path and AllowOnlineFallback is false. In practice this means: opted in →
// the online fallback is always suppressed (the hot path stays strictly local),
// connected or not — there is no connectivity check on the hot path. Routing
// through the state machine (rather than a bare boolean) keeps it the single
// arbiter and is forward-compatible with a future connectivity probe. For every
// non-opted-in host it reads only the managed-settings file, then fast-paths to
// false BEFORE any policy/cache gather — so the decision is byte-identical to the
// pre-R-1.4-P2 path (AC-1) and the default machine pays only that one small read.
var gateSkipOnlineFallback = defaultGateSkipOnlineFallback

func defaultGateSkipOnlineFallback(home string, now time.Time) bool {
	if !gateStateGatesFallback() {
		return false // opt-in only: a non-enterprise / non-opted host keeps its fallback
	}
	pol, _ := resolveSessionOfflinePolicy(home, "")
	pol.Enterprise = true // the opt-in comes from managed settings, same as R-7.2
	in := sessionBaselineGather(home, false, now)
	return !statemachine.AllowOnlineFallback(statemachine.Compute(in, pol))
}

// refusalCodeForHook maps the hook's (exitCode, reason) into a stable
// refusal_code token for the signed invocation record. An allow (exit 0) has
// no refusal. A deny carries "deny" by default, refined to a more specific
// token when the reason text reveals one (revoked / suspicious-name / etc.) so
// the Art.12 trail is queryable without parsing free-form reason strings.
func refusalCodeForHook(exitCode int, reason string) string {
	if exitCode == exitOK {
		return ""
	}
	switch {
	// SPEC-0317 R-7.2 — the `locked`-state managed deny. A unique token; placed
	// first as it cannot be a substring of any other reason.
	case strings.Contains(reason, "offline_locked"):
		return "offline_locked"
	// SPEC-0317 R-1.4 P2 — the state-gated online-fallback deny (a legacy managed
	// install with no offline metadata, kept strictly local while disconnected). A
	// unique token; placed with offline_locked as it cannot be a substring of any
	// other reason.
	case strings.Contains(reason, "offline_unverifiable_managed"):
		return "offline_unverifiable_managed"
	// SPEC-0277 P1 — agent-authorization denies. Checked BEFORE the generic
	// "revoked"/"unmanaged" cases so an agent deny gets its specific token (e.g.
	// an "agent_revoked" reason must not be flattened to "bundle_revoked").
	case strings.Contains(reason, "agentid: skill_not_in_grant"):
		return "agent_skill_not_in_grant"
	case strings.Contains(reason, "agentid: agent_revoked"):
		return "agent_revoked"
	case strings.Contains(reason, "agentid: agent_expired"):
		return "agent_expired"
	case strings.Contains(reason, "agentid: agent_approver_floor"):
		return "agent_approver_floor"
	case strings.Contains(reason, "agentid: agent_owner_sig_invalid"):
		return "agent_owner_sig_invalid"
	// SPEC-0279 — the freshness-channel denies (emergency deny-list + stale
	// revocation snapshot). Specific tokens before the generic agentid case so
	// the Art.12 trail distinguishes a compromise event / a freshness fail-closed
	// from a plain mandate failure.
	case strings.Contains(reason, "agent_emergency_denied"):
		return "agent_emergency_denied"
	case strings.Contains(reason, "agentid: agent_revocation_stale"):
		return "agent_revocation_stale"
	// FR-0045 N1 — the signed revocation HEAD is present but failed verification
	// (tampered/corrupt). A distinct token from the plain-stale case so the Art.12
	// trail separates "we could not prove the HEAD authentic" from "the HEAD is
	// authentic but too old". Checked BEFORE the stale case (the two tokens are
	// disjoint, but keep the more specific one first).
	case strings.Contains(reason, "bundle_revocation_head_untrusted"):
		return "bundle_revocation_head_untrusted"
	// SPEC-0279 R3 / FR-0045 D4 — bundle-revocation snapshot too stale to trust
	// (fail-closed for a high-risk skill invocation). Distinct from the agentid
	// mandate stale case so the Art.12 trail separates the two channels.
	case strings.Contains(reason, "bundle_revocation_stale"):
		return "bundle_revocation_stale"
	// Both the mandate path ("agentid_emergency_list_untrusted") and the
	// unconditional runtime path ("agent_emergency_list_untrusted") match this
	// common substring → a present-but-forged emergency file's fail-closed deny.
	case strings.Contains(reason, "emergency_list_untrusted"):
		return "agent_emergency_list_untrusted"
	case strings.Contains(reason, "agentid:"):
		return "agent_mandate_invalid"
	case strings.Contains(reason, "revoked"):
		return "bundle_revoked"
	case strings.Contains(reason, "suspicious skill name"):
		return "unsafe_skill_name"
	case strings.Contains(reason, "policy deny"), strings.Contains(reason, "unmanaged"):
		return "unmanaged_policy_deny"
	case strings.Contains(reason, "internal error"):
		return "internal_error"
	default:
		return "deny"
	}
}

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
	// SPEC-0317 R-6.4 — the Bash/Read/Edit/Write side-channel guard (`skillctl
	// guard-path`) reads these. Command is the Bash tool's shell line; FilePath is
	// the Read/Edit/Write target. They are unused by the Skill gate (verify-hook),
	// so adding them is inert for the Skill decision — a plain widening of the
	// shared envelope, not a semantic change.
	Command  string `json:"command"`   // Bash tool
	FilePath string `json:"file_path"` // Read | Edit | Write tool
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
	// SPEC-0255 gate-audit context: populated as the decision is made; the
	// deferred logger emits exactly ONE advisory event per gated skill, AFTER the
	// decision is final (best-effort, never alters code). audActive gates logging
	// to real skills — pre-skill input-validation denies are not logged.
	var (
		audSkill, audReason, audSession, audHome string
		audOnline, audCache, audActive           bool
		// SPEC-0277 P1: the acting agent's identity for the always-on signed
		// invocation event. Populated when an AgentID mandate is configured
		// (enforcement OPT-IN), stamped onto the record for BOTH allow and deny so
		// every action traces to (agent, owner). Empty when no mandate → the record
		// is byte-identical to the pre-SPEC-0277 v1.
		audAgentID, audOwner string
	)
	defer func() {
		if r := recover(); r != nil {
			code = emitDeny(stdout, stderr,
				fmt.Sprintf("skillctl verify-hook: internal error (%v) — failing closed (DENY)", r))
			audReason = fmt.Sprintf("internal error: %v", r)
		}
		if audActive {
			appendGateEvent(audHome, gateEvent{
				Source: "hook", Skill: audSkill, Decision: decisionForExit(code),
				Reason: audReason, ExitCode: code,
				Online: audOnline, CacheHit: audCache, SessionID: audSession,
			})
			// SPEC-0202 §9 — emit ONE device-signed invocation record per gated
			// skill, for BOTH allow AND deny, into the SEPARATE signed trail.
			// ALWAYS-ON evidence (Art.12), distinct from the advisory gate-audit
			// above. Best-effort + panic-safe inside appendSignedInvocation;
			// never alters `code`. The decision is encoded in exit_code (0=allow)
			// and refusal_code (the deny reason as a stable token). SPEC-0277 P1
			// stamps agent_identity / owner_identity (a VALUE change at the fixed
			// canonical line) when a mandate is active.
			appendSignedInvocation(audHome, skillgate.InvocationRecord{
				EventType:     "skill.invocation",
				SkillDigest:   installedSkillDigest(audHome, audSkill),
				SkillName:     audSkill,
				Action:        "skill_invocation",
				Tool:          "Skill",
				SessionID:     audSession,
				AgentIdentity: audAgentID,
				OwnerIdentity: audOwner,
				ExitCode:      code,
				RefusalCode:   refusalCodeForHook(code, audReason),
			})
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
	// From here we are gating a real skill → record the outcome. Resolve home up
	// front so every skill decision (not just the verify path) can be logged.
	home, _ := userHome()
	now := time.Now()
	audActive, audSkill, audSession, audHome = true, skill, ev.SessionID, home

	// SEC F12: validate the name through the ONE canonical fixed point the
	// verifier + loader use, so the gate cannot classify/cache/key a DIFFERENT
	// directory than the one actually verified and loaded. (The old check only
	// rejected '/','\\','..'; the verifier then resolved a lossy
	// sanitizeFilename(name), so a clean sibling could be verified while the
	// malicious raw-name dir loaded.) A name that is not a single safe component
	// is itself a red flag → fail closed.
	canon, nameErr := install.CanonicalSkillName(skill)
	if nameErr != nil {
		audReason = "suspicious skill name (not a single safe component)"
		return emitDeny(stdout, stderr,
			fmt.Sprintf("skillctl: BLOCKED %q — unsafe skill name (%v); refusing (fail-closed)", skill, nameErr))
	}
	skill = canon

	// SPEC-0277 P1 — AgentID authorization layer (the genuinely-new behaviour).
	// Computed ONCE, here, for the canonical skill name: it attributes the acting
	// agent (stamped onto the always-on signed invocation event for allow AND
	// deny) AND yields the agent-level verdict. ENFORCEMENT is OPT-IN — engaged
	// only when an AgentID mandate is configured. When engaged, EVERY allow path
	// below (allowlist, cache-hit, the verified chain, …) is wrapped by `allow()`
	// so an outside-grant / forged / expired / revoked agent is DENIED regardless
	// of how the skill chain itself would rule (fail-closed, §4 step 3).
	authz := authorizeAgentForSkill(home, skill)
	if authz.Configured {
		audAgentID, audOwner = authz.AgentID, authz.Owner
	}

	// SPEC-0279 R5 — EMERGENCY DENY-LIST on the installed bundle DIGEST + AUTHOR,
	// consulted FIRST and UNCONDITIONALLY (review finding #1, the merge-blocker).
	// This is the headline emergency guarantee at the runtime SPEC-0247 gate: a
	// compromised digest/author is denied on sight
	//   - independent of whether an AgentID mandate is configured (the common case
	//     has none — the old code only consulted the list inside the mandate path);
	//   - BEFORE the `fresh`-guarded readRevokedCache, BEFORE cachedAllow, and
	//     BEFORE the offline/online chain — so a STALE sweep cache (which skips the
	//     revoked-digest check) and a low-risk/cached action can NOT keep a burned
	//     bundle alive. The cache cadence is short-circuited.
	// A present-but-forged emergency file is fail-closed (DENY). A missing file is
	// a no-op (the channel is opt-in per machine).
	if ev := emergencyDeniesInstalledSkill(home, skill); ev.Deny {
		audReason = "agentid: agent_" + ev.Reason // → emergency_denied / emergency_list_untrusted
		msg := fmt.Sprintf("skillctl: BLOCKED '%s' — emergency deny-list (compromise event, SPEC-0279 R5); refusing on sight (fail-closed).", skill)
		if ev.Token != "" {
			msg = fmt.Sprintf("skillctl: BLOCKED '%s' — emergency deny-list names %q (compromise event, SPEC-0279 R5); refusing on sight regardless of cache freshness or AgentID mandate.", skill, ev.Token)
		}
		return emitDeny(stdout, stderr, msg)
	}

	// allow() is the single allow gate: when a mandate is engaged it denies
	// outside-grant/invalid agents; otherwise it is the plain emitAllow.
	allow := func() int {
		if authz.Configured && !authz.Allowed {
			audReason = "agentid: " + authz.Reason
			return emitDeny(stdout, stderr,
				fmt.Sprintf("skillctl: BLOCKED '%s' — agent %s is not authorized (%s). The skill is outside the AgentID's grant, or the mandate failed verification (fail-closed, SPEC-0277).",
					skill, dashOrAgent(authz.AgentID), authz.Reason))
		}
		return emitAllow()
	}

	pol := loadGatePolicyW(stderr)

	if pol.isAllowlisted(skill) {
		audReason = "allowlisted"
		return allow() // operator escape hatch (§9.4) — still bounded by the AgentID grant
	}

	managed, why := isManagedSkill(skill)
	if !managed {
		switch pol.Unmanaged {
		case "deny":
			audReason = fmt.Sprintf("unmanaged (%s) + policy deny", why)
			return emitDeny(stdout, stderr,
				fmt.Sprintf("skillctl: BLOCKED '%s' — not skillctl-managed (%s) and policy unmanaged_skills=deny. Import it with `skillctl import` or allowlist it.", skill, why))
		case "warn":
			audReason = fmt.Sprintf("unmanaged (%s) + policy warn", why)
			fmt.Fprintf(stderr, "skillctl verify-hook: WARN unverified skill '%s' (%s) — allowed by policy unmanaged_skills=warn\n", skill, why)
			return allow()
		default: // "allow"
			audReason = fmt.Sprintf("unmanaged (%s) + policy allow", why)
			return allow()
		}
	}

	// SPEC-0317 R-7.2 — `locked` STATE: a managed-enterprise host with NO trust
	// basis at all (roots/self-roots/sidecar all gone) denies ALL MANAGED skills
	// here — BEFORE the revoked/verdict cache, so a cached allow cannot outlive a
	// fleet that has lost its policy basis. Unmanaged skills already returned above
	// and are untouched (R-7.2). The enterprise opt-in is read from the ROOT-OWNED
	// managed settings (Option B), so this is inert on every non-enterprise host —
	// it never bricks a default / self-ER1 / air-gapped machine and preserves AC-1
	// byte-parity. Emergency already ran first (unconditional); the AgentID grant
	// still wraps the eventual allow() elsewhere.
	// NOTE ON SCOPE: this rung sits BELOW the operator allowlist (§9.4) above,
	// which is read from the USER-owned gate-policy.yaml — so a same-uid user can
	// allowlist a specific managed skill past the lock without root. That matches
	// the allowlist's existing role as the escape hatch that bypasses all §7
	// verification; the message therefore says "non-allowlisted", not "all".
	if gateOfflineStateDeniesManaged(home, now) {
		audReason = "offline_locked (managed-enterprise, no trust basis; SPEC-0317 R-7.2)"
		return emitDeny(stdout, stderr,
			fmt.Sprintf("skillctl: BLOCKED '%s' — offline 'locked' state (exit %d): the host is managed-enterprise but has NO trust basis (no trust roots, self/ER1 roots, or provenance sidecar), so offline_policy denies all non-allowlisted managed skills. Restore a trust root or a signed offline checkpoint.", skill, exitOfflineLocked))
	}

	// SPEC-0266 F1: a bundle revoked AFTER install is denied by the offline gate
	// too, via the sweep-maintained revoked-digest cache (consulted only while
	// fresh — the sweep is the authority that refreshes it online).
	if home != "" {
		if revset, fresh := readRevokedCache(home, revokedCacheTTL); fresh {
			if dig := installedSkillDigest(home, skill); dig != "" {
				if _, bad := revset[dig]; bad {
					audReason = "revoked (BundleRevokedEvent; offline cache)"
					return emitDeny(stdout, stderr,
						fmt.Sprintf("skillctl: BLOCKED '%s' — bundle revoked (exit %d); a BundleRevokedEvent was published for this digest. Run `skillctl verify --all` to refresh + quarantine.", skill, exitBundleRevoked))
				}
			}
		}
	}

	// SPEC-0279 R3 / FR-0045 D4 — FRESHNESS FAIL-CLOSED. If the revocation snapshot
	// is too stale to trust (per the trust-root max_staleness), refuse a high-risk
	// skill invocation rather than run against a revocation list we can no longer
	// prove is current. This closes the fail-OPEN gap above where a >TTL sweep cache
	// silently skips the revocation check. Placed BEFORE the verdict-cache fast path
	// so a cached allow cannot bypass a stale kill-switch. OPT-IN: a no-op unless a
	// max_staleness policy is set AND a signed HEAD/checkpoint anchor exists.
	if stale, reason, msg := revocationSnapshotStale(home, skill); stale {
		audReason = reason
		return emitDeny(stdout, stderr, msg)
	}

	// Managed skill → offline fast path first: a fresh, digest-matching PASS
	// in the verdict cache (written by the SessionStart sweep or a prior hook)
	// lets us allow without touching the network (SPEC-0247 §8 / P1.1).
	if home != "" && cachedAllow(home, skill, ev.SessionID, now) {
		audCache, audReason = true, "verdict-cache hit"
		return allow()
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
		} else if gateSkipOnlineFallback(home, now) {
			// SPEC-0317 R-1.4 P2 — no offline metadata for this LEGACY managed
			// install, and the enterprise state-gate keeps the hot path strictly
			// local (offline-first; no connectivity probe): the online §7 fallback is
			// SUPPRESSED, so we fail CLOSED here rather than blocking on an 8s network
			// round-trip. A deny short-circuits before recordVerdict (we never cache a
			// policy deny).
			audReason = "offline_unverifiable_managed (state-gated online fallback; SPEC-0317 R-1.4 P2)"
			return emitDeny(stdout, stderr,
				fmt.Sprintf("skillctl: BLOCKED '%s' — no offline verification metadata and offline_policy state-gates the online fallback (exit %d offline_unverifiable_managed): the hot path stays strictly local (offline-first). Re-run `skillctl install %s` to stash offline verification metadata.",
					skill, exitOfflineUnverifiable, skill))
		} else {
			code, reason = verifyManagedFn(skill, pol)
			audOnline = true
		}
		recordVerdict(home, skill, ev.SessionID, code, "", now)
	} else if gateSkipOnlineFallback("", now) {
		// Same R-1.4 P2 gate with no home to verify offline against. DEFENSIVE /
		// effectively unreachable: reaching this ladder requires a MANAGED
		// classification, which requires userHome() to have resolved a non-empty home
		// above — so home=="" does not occur here in practice. Kept as a fail-closed
		// belt-and-suspenders (it mirrors the pre-existing home=="" `else` below).
		audReason = "offline_unverifiable_managed (state-gated online fallback, no home; SPEC-0317 R-1.4 P2)"
		return emitDeny(stdout, stderr,
			fmt.Sprintf("skillctl: BLOCKED '%s' — offline_policy state-gates the online fallback and no local home is available to verify offline (exit %d offline_unverifiable_managed).",
				skill, exitOfflineUnverifiable))
	} else {
		code, reason = verifyManagedFn(skill, pol)
		audOnline = true
	}
	audReason = reason
	if code == exitOK {
		return allow()
	}
	return emitDeny(stdout, stderr,
		fmt.Sprintf("skillctl: BLOCKED '%s' — %s (exit %d). Run `skillctl verify %s` for the full chain, or `skillctl install %s` to repair.",
			skill, reason, code, skill, skill))
}

// dashOrAgent renders an agent id for a deny message, or a placeholder when the
// mandate was unreadable (no parsed id).
func dashOrAgent(id string) string {
	if id == "" {
		return "(unknown agent)"
	}
	return id
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

// revocationSnapshotStale applies the SPEC-0279 R3 freshness contract to the
// sweep-maintained bundle-revocation snapshot at the runtime gate. It is the
// fail-CLOSED half of the G5 kill-switch (FR-0045 D4): if the revocation snapshot
// is too stale to trust — older than the trust-root max_staleness — it refuses a
// high-risk skill invocation rather than run one against a revocation list we can
// no longer prove is current. That closes the fail-OPEN gap where a >TTL sweep
// cache silently skipped the revocation check entirely.
//
// Deliberately gated to STAY OUT OF THE WAY until a signed freshness anchor
// exists, so it cannot brick existing installs:
//   - engaged ONLY when the cache carries an adopted HEAD's issued_at (FR-0045 D3)
//     OR a signed freshness checkpoint (R4) is on disk. Absent both there is no
//     signed anchor to judge → no-op (the pre-FR-0045 sweep set-only path stands
//     unchanged; relevant until the D2 HEAD endpoint ships).
//   - a no-op anyway when the trust root sets no max_staleness (EvaluateFreshness
//     ALLOWs an unset ceiling) — so the whole fail-closed behaviour is OPT-IN by
//     trust-root policy.
//
// A skill invocation is classified RiskHigh: its concrete side effects are unknown
// at the gate, and SPEC-0279 fails high-risk closed past the ceiling (fail-safe).
// Returns (deny, refusalToken, humanMessage). Every decision is audited (R6) via
// auditFreshnessDecision inside evaluateFreshness's caller path.
func revocationSnapshotStale(home, skill string) (bool, string, string) {
	if home == "" {
		return false, "", ""
	}
	epoch, issuedAt := readRevokedCacheHead(home)
	cpPath := ""
	if p := freshnessCheckpointPath(home); fileExists(p) {
		cpPath = p
	}

	// FR-0045 N1 — a signed HEAD that is PRESENT but fails verification is tampering,
	// NOT the pre-D2 "no anchor" case. readRevokedCacheHead returns issued_at="" for
	// BOTH the ABSENT and the PRESENT-BUT-BAD states, so without this the early no-op
	// below would flip DENY→ALLOW on a one-byte corruption wherever max_staleness is
	// configured. Detect the tampered state explicitly and drive it through the
	// freshness evaluation with an empty anchor (= infinitely stale, per freshness.go)
	// so a high-risk action fails CLOSED once a max_staleness ceiling is set. The
	// ABSENT case (no signed HEAD, no checkpoint) stays a no-op — must not brick a
	// pre-D2 install that never adopted a HEAD.
	headTampered := false
	if fileExists(revokedHeadSignedPath(home)) {
		if _, ok := verifiedAdoptedHead(home); !ok {
			headTampered = true
		}
	}

	if issuedAt == "" && cpPath == "" && !headTampered {
		return false, "", "" // no signed anchor yet → nothing to enforce (pre-D2).
	}
	_, root, rerr := loadRootsFn("")
	if rerr != nil {
		// No trust roots → we cannot read the freshness policy. The managed-skill
		// chain fails closed later on the same condition; do not double-deny here.
		return false, "", ""
	}
	out := evaluateFreshness(freshnessInputs{
		root:           root,
		checkpointPath: cpPath,
		syncedEpoch:    epoch,
		syncedIssuedAt: issuedAt, // "" for a tampered HEAD → infinitely stale
		risk:           verify.RiskHigh,
	})
	auditFreshnessDecision("hook", skill, out)
	if out.Err != nil {
		if headTampered {
			return true, "bundle_revocation_head_untrusted",
				fmt.Sprintf("skillctl: BLOCKED '%s' — the signed revocation HEAD is present but its ed25519 envelope failed verification (tampered/corrupt); refusing a high-risk skill invocation (exit %d, fail-closed, FR-0045 N1). Run `skillctl revoke feed --refresh` to re-fetch a valid signed HEAD.", skill, exitRevocationStale)
		}
		return true, "bundle_revocation_stale",
			fmt.Sprintf("skillctl: BLOCKED '%s' — revocation snapshot too stale to trust (exit %d, SPEC-0279 R3); refusing a high-risk skill invocation until the revocation feed is refreshed. Run `skillctl verify --all` (or `skillctl revoke feed --refresh`).", skill, exitRevocationStale)
	}
	return false, "", ""
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
	// SEC F-ENV: the unmanaged disposition (from gate-policy.yaml OR the
	// SKILLCTL_GATE_UNMANAGED env override) MUST be one of deny|warn|allow. The
	// gate's switch routes any OTHER value through `default: emitAllow`, so an
	// attacker who can set a bogus env value (or a typo'd policy) would silently
	// neuter the unmanaged-skill deny. Validate in one place — unknown → FAIL
	// CLOSED to deny with a loud WARN.
	switch p.Unmanaged {
	case "deny", "warn", "allow":
	default:
		fmt.Fprintf(warn,
			"skillctl verify-hook: WARN unmanaged_skills=%q is not deny|warn|allow (from gate-policy.yaml or SKILLCTL_GATE_UNMANAGED) — failing closed (treating as deny).\n",
			p.Unmanaged)
		p.Unmanaged = "deny"
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
