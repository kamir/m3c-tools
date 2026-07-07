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
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
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

// emergencyDenyPath is the local signed emergency deny-list (SPEC-0279 R5) the
// gate consults FIRST. Absent → empty set (the channel is opt-in per machine).
func emergencyDenyPath(home string) string {
	return filepath.Join(home, ".claude", "skillctl", "emergency-deny.json")
}

// freshnessCheckpointPath is the local signed freshness checkpoint (SPEC-0279 R4)
// the gate uses to (maybe) reset the staleness clock for the agent-revocation
// snapshot without a full re-sync. Absent → no reset (list's own issued_at).
func freshnessCheckpointPath(home string) string {
	return filepath.Join(home, ".claude", "skillctl", "freshness-checkpoint.json")
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
// the approver in `reviewers:`, the require_agent_approver floor, the expiry, the
// local signed agent-revocation list, the SPEC-0279 emergency deny-list (R5,
// consulted FIRST) and the freshness contract (R3, with the optional checkpoint
// R4). Returns (verified, deny-reason).
func verifyActiveAgentID(home string, doc *agentid.AgentID) (bool, string) {
	// Resolve the trust root: prefer the AgentID's own trust_root, else the sole
	// pinned root. A missing/ambiguous trust-roots config is fail-closed (an
	// AgentID we cannot check must not be trusted).
	_, root, err := loadRootsFn(doc.Payload.TrustRoot)
	if err != nil {
		return false, "agentid_trust_roots_unavailable"
	}

	// SPEC-0279 R5 — emergency deny-list FIRST: a compromise event denies on sight,
	// before revocation/expiry/freshness are even considered. A present-but-forged
	// list is fail-closed (we refuse rather than ignore an operator-placed list).
	if ep := emergencyDenyPath(home); fileExists(ep) {
		set, lerr := verify.LoadVerifiedEmergencyDenyList(ep, root)
		if lerr != nil {
			return false, "agentid_emergency_list_untrusted"
		}
		if tok, bad := verify.EmergencyDenies(set, doc.Payload.ID, doc.Payload.Owner); bad {
			appendGateEvent(home, gateEvent{
				Source: "hook", Skill: doc.Payload.ID, Decision: "deny",
				Reason: "emergency_deny:" + tok, ExitCode: exitBundleRevoked,
			})
			return false, "agent_emergency_denied"
		}
	}

	// Offline revocation: load + signature-verify the local agent-revocation list
	// (if present) against the pinned root. A forged/untrusted list is fail-closed
	// (we refuse the AgentID rather than ignore a list the operator placed). We
	// also capture the snapshot's epoch + issued_at for the freshness check.
	var revoked map[string]struct{}
	var revEpoch int
	var revIssuedAt string
	revPresent := false
	if rp := agentRevocationsPath(home); fileExists(rp) {
		set, ep, ia, lerr := loadAgentRevocationsWithMeta(rp, root)
		if lerr != nil {
			return false, "agentid_revocation_list_untrusted"
		}
		revoked, revEpoch, revIssuedAt, revPresent = set, ep, ia, true
	}

	res, verr := agentid.Verify(doc, agentid.VerifyOpts{
		Pins:            pinnedKeysFromRoot(root),
		RequireApprover: root.RequireAgentApprover,
		RevokedAgentIDs: revoked,
	})
	if verr != nil {
		return false, agentDenyReason(verr)
	}

	// SPEC-0279 R3/R4/R6 — the freshness contract on the agent-revocation snapshot.
	// Engaged only when a snapshot was present OR a checkpoint is on disk. A stale
	// snapshot fails the gate closed for a high-risk grant; the checkpoint can
	// reset the clock. EVERY decision is audited (R6).
	cpPath := ""
	if p := freshnessCheckpointPath(home); fileExists(p) {
		cpPath = p
	}
	if revPresent || cpPath != "" {
		fresh := evaluateFreshness(freshnessInputs{
			root:           root,
			checkpointPath: cpPath,
			// emergency already consulted above; do not double-load it here.
			syncedEpoch:    revEpoch,
			syncedIssuedAt: revIssuedAt,
			risk:           grantActionRisk(res.Grant),
		})
		auditFreshnessDecision("hook", res.AgentID, fresh)
		if fresh.Err != nil {
			return false, "agent_revocation_stale"
		}
	}
	return true, ""
}

// emergencyVerdict is the outcome of the runtime emergency-deny check on an
// installed skill's bundle digest + author identity (SPEC-0279 R5 at the
// SPEC-0247 gate).
type emergencyVerdict struct {
	// Deny is true when the skill must be refused: either a digest/author token is
	// on the verified emergency deny-list, OR the present emergency file failed to
	// verify (fail-closed — never ignore an operator-placed list).
	Deny bool
	// Token is the matched deny token (when a real entry matched), for the message.
	Token string
	// Reason is the stable refusal token: "emergency_denied" (a digest/author was
	// listed) or "emergency_list_untrusted" (the file is present but unverifiable).
	Reason string
}

// emergencyDeniesInstalledSkill consults the SPEC-0279 R5 emergency deny-list for
// an installed skill's BUNDLE DIGEST and AUTHOR IDENTITY at the runtime gate.
//
// This is the headline emergency guarantee at the SPEC-0247 PreToolUse path:
// it runs UNCONDITIONALLY — independent of any AgentID mandate, BEFORE the
// freshness/cache cadence — so a compromised digest/author is denied on sight
// even when no mandate is configured (the common case) and even when the
// SPEC-0266 sweep cache is fresh (the cadence cannot keep a burned bundle alive).
//
// Fail-closed by construction:
//   - no emergency file on disk            → no deny (opt-in per machine);
//   - file PRESENT but trust roots missing → DENY (we cannot verify a list the
//     operator placed; refusing the skill is safer than ignoring the list);
//   - file PRESENT but signature/rollback
//     invalid (forged)                     → DENY (emergency_list_untrusted);
//   - a listed digest/author               → DENY (emergency_denied).
//
// A skill with NO provenance sidecar (no digest/author to test) is still subject
// to a fail-closed file: if the operator placed an emergency list we cannot
// verify, we refuse regardless.
func emergencyDeniesInstalledSkill(home, skill string) emergencyVerdict {
	if home == "" {
		return emergencyVerdict{}
	}

	// Test BOTH the installed digest and the installed author identity. ANY hit
	// denies. (A "sha256:<digest>" on the list burns the exact bundle; an
	// "id:<owner>" burns everything that author signed.)
	digest := installedSkillDigest(home, skill)
	author := installedSkillAuthor(home, skill)

	// (1) SPEC-0279 R5 — the local signed emergency-deny.json. Opt-in per machine:
	// absent → skip. Present → any inability to VERIFY it is fail-closed.
	if ep := emergencyDenyPath(home); fileExists(ep) {
		_, root, err := loadRootsFn("")
		if err != nil {
			return emergencyVerdict{Deny: true, Reason: "emergency_list_untrusted"}
		}
		set, lerr := verify.LoadVerifiedEmergencyDenyList(ep, root)
		if lerr != nil {
			return emergencyVerdict{Deny: true, Reason: "emergency_list_untrusted"}
		}
		if tok, bad := verify.EmergencyDenies(set, digest, author); bad {
			appendGateEvent(home, gateEvent{
				Source: "hook", Skill: skill, Decision: "deny",
				Reason: "emergency_deny:" + tok, ExitCode: exitBundleRevoked,
				ContentDigest: digest,
			})
			return emergencyVerdict{Deny: true, Token: tok, Reason: "emergency_denied"}
		}
	}

	// (2) FR-0045 Fix C / finding F4 — the ADOPTED signed HEAD's emergency list.
	// A digest the registry placed in the signed HEAD.emergency MUST deny at the
	// gate, authenticated by the same registry key (headEmergencyDeniesDigest
	// re-verifies the HEAD envelope), even with NO local emergency-deny.json.
	if tok, bad := headEmergencyDeniesDigest(home, digest); bad {
		appendGateEvent(home, gateEvent{
			Source: "hook", Skill: skill, Decision: "deny",
			Reason: "emergency_deny:" + tok, ExitCode: exitBundleRevoked,
			ContentDigest: digest,
		})
		return emergencyVerdict{Deny: true, Token: tok, Reason: "emergency_denied"}
	}

	return emergencyVerdict{}
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
