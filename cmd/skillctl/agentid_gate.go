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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/agentid"
	"github.com/kamir/m3c-tools/pkg/skillctl/pin"
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

	// GrantRestricting / GrantNamesSkill are set only on the VERIFIED-mandate path
	// (FR-0090 IS-RS-02). GrantRestricting mirrors grantIsRestricting(grant) — the
	// grant bounds capability intents / data-scopes / limits, so a scope check is
	// owed. GrantNamesSkill mirrors grant.AllowsSkill(skill). Together they let the
	// gate deny an UNMANAGED skill (all provenance stripped → no digest-verified
	// scope to check) that a restricting mandate names, instead of letting it take
	// the unmanaged=allow branch and skip the IS-T7 scope check entirely.
	GrantRestricting bool
	GrantNamesSkill  bool
}

// agentIDVerifyForGateFn is the verification seam so tests can drive the gate's
// authorization branch without writing trust-roots + keys. Production points it
// at verifyActiveAgentID.
var agentIDVerifyForGateFn = verifyActiveAgentID

// gateRequireAgentMandate reports whether the ROOT-OWNED managed settings engage
// the SPEC-0277 IS-06 require-mandate floor (`skillctlRequireAgentMandate: true`).
// When set, a MISSING ~/.claude/skillctl/agentid.json is a DENY at the gate rather
// than the silent opt-out default — a non-privileged user cannot delete the mandate
// to escape agent authorization. Same conservative, never-brick contract as
// gateManagedEnterprise: a missing/unreadable/malformed managed file → false (an
// unreadable managed file must never itself deny every skill). Seam: tests set it.
var gateRequireAgentMandate = func() bool {
	path, err := pin.DefaultManagedSettingsPath()
	if err != nil {
		return false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return pin.RequireAgentMandateFromBytes(b)
}

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
		// No mandate configured (the common case).
		if errors.Is(err, os.ErrNotExist) {
			// SPEC-0277 IS-06: a root-owned require-mandate floor turns the MISSING
			// mandate from a silent opt-OUT into a hard DENY, so a non-privileged user
			// cannot delete agentid.json to escape agent authorization. Absent the
			// floor, keep the opt-in default (no mandate → skill chain only).
			if gateRequireAgentMandate() {
				return agentAuthzResult{Configured: true, Allowed: false, Reason: "agent_mandate_required"}
			}
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

	// FR-0090 IS-RS-02: expose the grant shape now that the mandate has VERIFIED, so
	// the gate can refuse an UNMANAGED (provenance-stripped) skill that a restricting
	// grant names — which would otherwise slip through the unmanaged=allow branch,
	// skipping the IS-T7 scope check. Only meaningful on the verified path (a forged
	// mandate already denies via allow()).
	res.GrantRestricting = grantIsRestricting(doc.Payload.Grant)
	res.GrantNamesSkill = doc.Payload.Grant.AllowsSkill(skill)

	// Mandate verified → authorize the skill against the grant, enforcing not just
	// the skill NAME but the capability intents / data-scopes / limits the skill
	// declares in its DIGEST-VERIFIED bundle.json (SPEC-0277 IS-04 / IS-T7). A skill
	// whose signed manifest exceeds the mandate's granted scope is DENIED even though
	// it is named in the grant. Fail-closed by construction.
	req, resolved := skillRequirementsFn(home, skill)
	if !resolved && grantIsRestricting(doc.Payload.Grant) && doc.Payload.Grant.AllowsSkill(skill) {
		// A managed bundle demonstrably exists for this IN-GRANT skill, but its signed
		// scope could not be resolved + digest-verified (no provenance basis at all, a
		// missing/unreadable stashed .skb, or a digest mismatch). For a RESTRICTING
		// grant that is a fail-closed DENY: a same-uid actor could otherwise delete the
		// provenance files (`.m3c-provenance.json` / `.skillctl-offline.json`) or the
		// stashed `*.skb` to strip scope enforcement down to name-only and slip an
		// over-scoped skill through. We refuse to authorize a scope we cannot confirm —
		// mirroring the IS-T6 deleted-mandate → deny posture. A NON-restricting grant
		// keeps the name-only never-brick path; a skill NOT named in the grant falls
		// through to the AuthorizeSkillScoped name check below (skill_not_in_grant).
		res.Allowed = false
		res.Reason = "skill_requirements_unresolved"
		return res
	}
	if r, ok := doc.Payload.Grant.AuthorizeSkillScoped(skill, req); !ok {
		res.Allowed = false
		res.Reason = r // skill_not_in_grant | intent_not_in_grant | data_scope_not_in_grant | limit_exceeded
		return res
	}
	res.Allowed = true
	return res
}

// grantIsRestricting reports whether the grant bounds anything BEYOND the skill
// name — i.e. it names capability intents, data-scopes, or resource limits. When it
// does, an UNRESOLVABLE signed manifest (a digest is on record but its .skb can't be
// read) must fail closed rather than silently degrade to name-only enforcement.
func grantIsRestricting(g agentid.Grant) bool {
	return len(g.Intents) > 0 || len(g.DataScopes) > 0 || len(g.Limits) > 0
}

// skillRequirementsFn resolves an installed skill's author-signed declared
// requirements (intents / data-scopes / limits) from its digest-verified
// bundle.json. The second result is `resolved`: true when the requirements are
// authoritative (either a genuine legacy/unmanaged skill with NO digest on record →
// empty req → name-only, OR a successful digest-verified read), false ONLY when a
// bundle digest IS on record but its signed manifest could not be read+verified.
// Seam so tests can drive the scope-enforcement branch without minting a real .skb;
// production points it at resolveInstalledSkillRequirements.
var skillRequirementsFn = resolveInstalledSkillRequirements

// resolveInstalledSkillRequirements resolves an installed skill's author-signed
// declared requirements from its DIGEST-VERIFIED bundle.json:
//   - the capability intents its data_dependencies + signed `intent` block imply,
//   - the data-scope ids it declares (data_dependencies[].id),
//   - any declared resource ceilings (a `limits` block; forward-compatible).
//
// The bytes are trustworthy ONLY because verify.ReadDigestVerifiedManifest
// recomputes the on-disk .skb digest and constant-time-compares it against the
// provenance sidecar's recorded bundle_digest before returning the manifest map — a
// tampered manifest breaks the digest and yields nothing.
//
// The (req, resolved) contract distinguishes the "empty" cases the gate must treat
// differently. The anchor is whether a MANAGED BASIS exists — a stashed .skb — and
// whether its digest is resolvable from any recorded basis (provenance sidecar OR
// the `skillctl install` offline stash, see installedSkillDigest):
//   - NO managed basis at all (no stashed .skb, no digest on record) → a genuine
//     legacy/unmanaged skill → (empty, TRUE): name-only is correct; never-brick.
//   - a stashed .skb IS present but NO digest resolves from any basis (both the
//     provenance sidecar and the offline stash are absent/unreadable — e.g. a
//     same-uid actor deleted them to strip enforcement) → (empty, FALSE): a bundle
//     demonstrably exists but its scope cannot be confirmed.
//   - a digest IS on record but the .skb is absent/unreadable, or the manifest
//     fails the digest check → (empty, FALSE): same "cannot confirm scope".
// The gate fails every (empty, FALSE) case CLOSED for a restricting grant, so a
// same-uid actor cannot delete provenance to downgrade enforcement to name-only.
func resolveInstalledSkillRequirements(home, skill string) (agentid.SkillRequirements, bool) {
	digest := installedSkillDigest(home, skill)
	skbPath := stashedSkbPath(home, skill)
	if digest == "" {
		if skbPath == "" {
			return agentid.SkillRequirements{}, true // no managed basis → name-only, never-brick
		}
		return agentid.SkillRequirements{}, false // managed .skb present but no resolvable digest → unconfirmable
	}
	if skbPath == "" {
		return agentid.SkillRequirements{}, false // digest on record but no .skb → scope unconfirmable
	}
	manifest, err := verify.ReadDigestVerifiedManifest(skbPath, digest)
	if err != nil {
		return agentid.SkillRequirements{}, false // digest on record but manifest unverifiable
	}
	return requirementsFromManifest(manifest), true
}

// stashedSkbPath returns the path to the first stashed .skb inside an installed
// skill's directory (~/.claude/skills/<skill>/), or "" if none. This is the same
// on-disk .skb whose bytes carry the author-signature-covered bundle.json.
func stashedSkbPath(home, skill string) string {
	dir := filepath.Join(home, ".claude", "skills", skill)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".skb") {
			return filepath.Join(dir, e.Name())
		}
	}
	return ""
}

// requirementsFromManifest projects a digest-verified bundle.json map into the
// agentid.SkillRequirements the grant is checked against.
func requirementsFromManifest(m map[string]any) agentid.SkillRequirements {
	var req agentid.SkillRequirements
	seenIntent := map[string]struct{}{}
	addIntent := func(tok string) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			return
		}
		if _, dup := seenIntent[tok]; dup {
			return
		}
		seenIntent[tok] = struct{}{}
		req.Intents = append(req.Intents, tok)
	}

	// (1) Intents the signed data_dependencies imply (kind+access), plus their ids.
	if deps, ok := m["data_dependencies"].([]any); ok {
		for _, d := range deps {
			dm, ok := d.(map[string]any)
			if !ok {
				continue
			}
			if id, _ := dm["id"].(string); strings.TrimSpace(id) != "" {
				req.DataScopes = append(req.DataScopes, strings.TrimSpace(id))
			}
			kind, _ := dm["kind"].(string)
			access, _ := dm["access"].(string)
			addIntent(intentForKindAccess(kind, access))
		}
	}

	// (2) The SIGNED `intent` block is ITSELF a capability declaration — the exact
	// class operators most want to restrict (network egress, subprocess/shell,
	// destructive ops, arbitrary side-effects). A skill can declare these with NO
	// data_dependencies entry (e.g. an http-egress or shell-spawning skill whose only
	// declared "data" is read-shaped), so reading data_dependencies ALONE let such a
	// skill pass a grant that never granted those capabilities — a false-security
	// overclaim. Union the intent block's declared tokens into the required intents so
	// the grant must cover them. side_effects are the authoritative SPEC-0196 §5
	// vocabulary ("fs:write", "network:outbound", "subprocess", "llm:call", …); the
	// network/subprocess/destructive flags are folded to stable capability tokens.
	if intent, ok := m["intent"].(map[string]any); ok {
		if ses, ok := intent["side_effects"].([]any); ok {
			for _, s := range ses {
				if t, _ := s.(string); strings.TrimSpace(t) != "" {
					addIntent(strings.TrimSpace(t))
				}
			}
		}
		if net, _ := intent["network"].(bool); net {
			addIntent("network:write") // a skill asserting outbound network needs the network:write capability
		}
		if subprocessDeclared(intent["subprocess"]) {
			addIntent("subprocess:exec")
		}
		if d, _ := intent["destructive"].(bool); d {
			addIntent("destructive")
		}
	}

	// (3) Declared resource ceilings (forward-compatible: today's bundle.json carries
	// none; a future `limits` block is enforced against the grant's caps). Values are
	// stringified so a JSON number (float64) and a JSON string compare identically.
	if lim, ok := m["limits"].(map[string]any); ok && len(lim) > 0 {
		req.Limits = make(map[string]string, len(lim))
		for k, v := range lim {
			req.Limits[k] = fmt.Sprint(v)
		}
	}
	return req
}

// subprocessDeclared reports whether a signed intent.subprocess value declares a
// subprocess/shell capability in ANY of its encodings: a non-empty argv list (the
// documented form), a bool true, a non-empty command string, or a non-empty
// object. Only an absent / false / empty value means "no subprocess"; every other
// non-empty shape is treated as declared (fail-closed), so a skill cannot dodge
// the subprocess:exec requirement by encoding its declaration as a scalar or map.
func subprocessDeclared(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return strings.TrimSpace(t) != ""
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	default:
		return true // an unexpected non-empty encoding → fail-closed, treat as declared
	}
}

// intentForKindAccess maps a signed data_dependency (SPEC-0196 kind + access) to
// the "<category>:<action>" capability-intent token a mandate grant uses, so the
// skill's signed data access is checked in the grant's own vocabulary
// (http read → "network:read"; local_fs write → "fs:write"). An unknown kind is
// carried VERBATIM as its own category (fail-closed): it fails set-membership
// unless the operator granted exactly it, rather than silently contributing no
// intent (pack-time already rejects unknown kinds, so this is defense-in-depth).
// An empty kind contributes nothing. An unknown access likewise surfaces verbatim.
func intentForKindAccess(kind, access string) string {
	kind = strings.TrimSpace(kind)
	if kind == "" {
		return "" // no declared kind → no derived intent
	}
	var cat string
	switch kind {
	case "local_fs":
		cat = "fs"
	case "http_endpoint":
		cat = "network"
	case "er1_collection":
		cat = "er1"
	case "firestore_collection":
		cat = "firestore"
	case "gcs_bucket":
		cat = "gcs"
	case "secrets_store":
		cat = "secrets"
	default:
		cat = kind // unknown kind → verbatim category, fails membership unless granted
	}
	act := "read"
	switch strings.TrimSpace(access) {
	case "write", "transform", "egress":
		act = "write" // any mutating / outbound-egress access is the "write" capability
	case "", "read", "passthrough":
		// keep the "read" default (read/passthrough/unspecified access is read-only)
	default:
		act = strings.TrimSpace(access) // unknown → verbatim, fails membership unless granted
	}
	return cat + ":" + act
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
