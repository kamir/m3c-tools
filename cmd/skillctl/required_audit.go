package main

// required_audit.go: the FR-0110b reconciliation surface (SPEC-0403 §6b).
//
// WHY THIS FILE EXISTS. §6b's `required` fail-close for policy.allow ALREADY runs
// LIVE in the gate hot path as SPEC-0317 R-8.2 `require_local_audit`
// (enforce_cmds.go): a skill ALLOW whose evidence cannot be DURABLY recorded
// (outbox row AND spool line both failed) is escalated to a fail-closed deny
// (exit 26). That path is the concrete instantiation of the §6b positive-list
// entry `policy.allow`:
//
//	§6b / this package                    SPEC-0317 R-8.2 enforce path
//	----------------------------------    -----------------------------------------
//	policy.allow on the positive list  ↔  a gated skill ALLOW is escalated
//	spool acceptance = fulfillment     ↔  durable = outbox row OR spool line (no net)
//	denial types exempt (REQ-6.7)      ↔  a DENY is never re-escalated (kept as-is)
//	separate confirmation (REQ-6.10a)  ↔  skillctlRequireLocalAudit, a flag DISTINCT
//	                                       from skillctlEnterprise
//	default byte-identical (REQ-6.4)   ↔  flag unset → decision returned unchanged
//
// FR-0110b therefore does NOT wire a SECOND policy.allow fail-close into the gate
// (that would double-enforce). It adds the GENERAL, reusable §6b mechanism in
// pkg/skillctl/auditevent (for the other REQ-6.9 types: skill.execute,
// capability.grant, trustroot.change, config.change, whose producers arrive with
// FR-0111), and it makes the ONE managed toggle wired today readable as the §6b
// vocabulary via effectiveRequiredAuditConfig, so the two layers share ONE
// interpretation instead of drifting.
//
// O3 / SPEC-0247 P1.3 HONESTY. `required` is only a *policy* (not merely a
// *request*) when its source is a tier a same-uid user cannot rewrite. The source
// here is the ROOT-OWNED managed-settings file (pin.RequireLocalAuditFromBytes,
// enterprise-gated), which is the correct tier (REQ-11.2). But P1.3 (the pinning
// runbook) is NOT yet in force, and skillctl at same-uid cannot PROVE the file is
// root-owned, so we do not claim unbypassability: `session baseline` prints the
// RED "advisory-only until SPEC-0247 P1.3 pinned" banner whenever the gate is not
// pinned (AUD-07), and this file's summary defers to that banner.

import (
	"fmt"

	"github.com/kamir/m3c-tools/pkg/skillctl/auditevent"
)

// effectiveRequiredAuditConfig maps the ONE §6b toggle wired today, the SPEC-0317
// R-8.2 require_local_audit managed flag, onto the auditevent.RequiredConfig
// vocabulary. require_local_audit == the positive-list entry policy.allow WITH its
// REQ-6.10a separate confirmation (the flag is itself a distinct managed key from
// skillctlEnterprise), fulfilled at the local spool (REQ-6.10b).
//
// When the flag is off it returns the zero config (mode ""), which BuildPolicy
// maps to "no required policy" (best-effort/durable default, REQ-6.4). The other
// four REQ-6.9 types have no managed toggle yet (their producers are FR-0111), so
// they are deliberately NOT asserted here: claiming them active would overclaim.
func effectiveRequiredAuditConfig(requireLocalAudit bool) auditevent.RequiredConfig {
	if !requireLocalAudit {
		return auditevent.RequiredConfig{} // mode "" → no policy.
	}
	return auditevent.RequiredConfig{
		Mode:               string(auditevent.ModeRequired),
		AllowList:          []string{string(auditevent.EventPolicyAllow)},
		ConfirmPolicyAllow: true, // the managed flag IS the REQ-6.10a separate confirmation.
	}
}

// describeRequiredAudit returns a one-line operator summary of the effective §6b
// required-audit policy, VALIDATED through the same BuildPolicy the library uses
// (so a future mis-map surfaces here rather than silently). It never fails the
// caller: a validation error is surfaced as text, because this is an
// informational surface (session baseline), never a gate.
func describeRequiredAudit(requireLocalAudit bool) string {
	rc := effectiveRequiredAuditConfig(requireLocalAudit)
	pol, err := rc.BuildPolicy()
	if err != nil {
		return fmt.Sprintf("misconfigured (%v)", err)
	}
	if pol == nil {
		return "off (best-effort/durable default: a lost audit event never changes a decision)"
	}
	// policy.allow is the only type wired live; name it and its fulfillment rule.
	return "required for policy.allow (SPEC-0403 §6b, fulfilled at the local spool, REQ-6.10b; enforced in the gate by R-8.2 require_local_audit)"
}
