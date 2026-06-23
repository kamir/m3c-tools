package main

// agentid_gate.go — SPEC-0277 P1 runtime authorization for the SPEC-0247
// PreToolUse(Skill) gate.
//
// The skill-verification chain (verify_hook_cmds.go) answers "is this skill a
// genuine, admitted, non-revoked bundle?". THIS file answers the genuinely-new
// SPEC-0277 question layered on top: "is the ACTING AGENT authorized to invoke
// this skill?" — i.e. is there an active AgentID mandate, does it VERIFY (owner
// sig vs a pinned key, the approver floor if set, not expired, not revoked), and
// is the skill WITHIN its grant? Outside-grant → DENY. Fail-closed.
//
// Two deliberate properties (SPEC-0277 §6 P1):
//   - ENFORCEMENT IS OPT-IN: the gate authorizes against an AgentID only when one
//     is configured at ~/.claude/skillctl/agentid.json. A machine with no mandate
//     keeps the pre-SPEC-0277 behaviour (skill chain only). This is what lets the
//     feature ship without breaking every existing install.
//   - EMISSION IS ALWAYS-ON: when an AgentID is configured, its agent:<id> /
//     id:<owner> is stamped onto the SPEC-0202 signed invocation event for EVERY
//     gated skill (allow AND deny), so the Art.12 trail traces every action to
//     (agent, owner). This is a VALUE change at the existing canonical line, not
//     a format change (the placeholder shipped in v1).

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/kamir/m3c-tools/pkg/skillctl/agentid"
)

// activeAgentIDPath is the configured mandate the gate enforces. Its presence is
// the opt-in switch: absent → no agent authorization (skill chain only).
func activeAgentIDPath(home string) string {
	return filepath.Join(home, ".claude", "skillctl", "agentid.json")
}

// agentRevocationsPath is the local signed agent-revocation list the offline gate
// consults (produced by `skillctl agentid revoke`). Absent → nothing revoked.
func agentRevocationsPath(home string) string {
	return filepath.Join(home, ".claude", "skillctl", "agent-revocations.json")
}

// agentAuthzResult is the outcome of the AgentID authorization layer.
type agentAuthzResult struct {
	// Configured is true when an AgentID mandate exists (enforcement engaged).
	// When false the gate skips authorization entirely (opt-in).
	Configured bool

	// Allowed is the verdict. Meaningful only when Configured.
	Allowed bool

	// AgentID / Owner identify the acting agent for the always-on invocation
	// event (stamped even on a deny, so the refused action is still attributed).
	AgentID string
	Owner   string

	// Reason is a stable deny token for the refusal_code / human reason.
	Reason string
}

// agentIDVerifyForGateFn is the verification seam so tests can drive the gate's
// authorization branch without writing trust-roots + keys. Production points it
// at verifyActiveAgentID.
var agentIDVerifyForGateFn = verifyActiveAgentID

// authorizeAgentForSkill is the gate's AgentID authorization entry point. It
// loads the active mandate (if any), verifies it offline, attributes the actor,
// and decides whether `skill` is within the grant. Fail-closed by construction:
//   - no mandate            → Configured=false (gate falls through to skill-only)
//   - mandate present but
//     fails verification     → Allowed=false (DENY: forged/expired/revoked/…)
//   - mandate ok, skill not
//     in grant               → Allowed=false (DENY: skill_not_in_grant)
//   - mandate ok, skill in
//     grant                  → Allowed=true
//
// The actor (AgentID/Owner) is returned even on a deny so the always-on signed
// invocation event attributes the refused action.
func authorizeAgentForSkill(home, skill string) agentAuthzResult {
	if home == "" {
		return agentAuthzResult{Configured: false}
	}
	doc, err := loadAgentIDFile(activeAgentIDPath(home))
	if err != nil {
		// No mandate configured (the common case) → opt-in: not engaged.
		if errors.Is(err, os.ErrNotExist) {
			return agentAuthzResult{Configured: false}
		}
		// A PRESENT-but-unreadable mandate is suspicious: the operator clearly
		// intended one, so fail CLOSED (deny) rather than silently ignore it.
		return agentAuthzResult{Configured: true, Allowed: false, Reason: "agentid_unreadable"}
	}

	// Attribute the actor up front so a deny still stamps (agent, owner).
	res := agentAuthzResult{
		Configured: true,
		AgentID:    doc.Payload.ID,
		Owner:      doc.Payload.Owner,
	}

	verified, reason := agentIDVerifyForGateFn(home, doc)
	if !verified {
		res.Allowed = false
		res.Reason = reason
		return res
	}

	// Mandate verified → authorize the skill against the grant (fail-closed).
	if r, ok := doc.Payload.Grant.AuthorizeSkill(skill, nil); !ok {
		res.Allowed = false
		res.Reason = r // "skill_not_in_grant"
		return res
	}
	res.Allowed = true
	return res
}

// verifyActiveAgentID runs the offline AgentID verification against the SAME
// pinned trust-roots the skill chain uses: the owner key pinned in `authors:`,
// the approver in `reviewers:`, the require_agent_approver floor, the expiry, and
// the local signed agent-revocation list. Returns (verified, deny-reason).
func verifyActiveAgentID(home string, doc *agentid.AgentID) (bool, string) {
	// Resolve the trust root: prefer the AgentID's own trust_root, else the sole
	// pinned root. A missing/ambiguous trust-roots config is fail-closed (an
	// AgentID we cannot check must not be trusted).
	_, root, err := loadRootsFn(doc.Payload.TrustRoot)
	if err != nil {
		return false, "agentid_trust_roots_unavailable"
	}

	// Offline revocation: load + signature-verify the local agent-revocation list
	// (if present) against the pinned root. A forged/untrusted list is fail-closed
	// (we refuse the AgentID rather than ignore a list the operator placed).
	var revoked map[string]struct{}
	if rp := agentRevocationsPath(home); fileExists(rp) {
		set, lerr := loadAgentRevocations(rp, root)
		if lerr != nil {
			return false, "agentid_revocation_list_untrusted"
		}
		revoked = set
	}

	_, verr := agentid.Verify(doc, agentid.VerifyOpts{
		Pins:            pinnedKeysFromRoot(root),
		RequireApprover: root.RequireAgentApprover,
		RevokedAgentIDs: revoked,
	})
	if verr == nil {
		return true, ""
	}
	return false, agentDenyReason(verr)
}

// agentDenyReason maps an agentid verification error to a stable refusal token.
func agentDenyReason(err error) string {
	switch agentIDExitCode(err) {
	case exitBundleRevoked: // 17
		return "agent_revoked"
	case exitAgentIDExpired: // 21
		return "agent_expired"
	case 20: // approver floor
		return "agent_approver_floor"
	case 11: // owner sig / not pinned
		return "agent_owner_sig_invalid"
	default:
		return "agent_mandate_invalid"
	}
}

// fileExists is a tiny presence check (a directory is treated as "not a file").
func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
