package auditevent

// required.go: the FR-0110b `required` positive-list policy and its config
// validation (SPEC-0403 §6b). This is the ONLY fail-closed path in the audit
// layer, and it runs in a skill load path, so the rules are deliberately narrow:
//
//   - REQ-6.6: `required` fail-closes ONLY for an explicitly configured positive
//     list of event types. A `required` with NO list is a config error and is
//     rejected (BuildPolicy).
//   - REQ-6.7: DENIAL events (policy.deny, signature.reject, revocation.detect)
//     are exempt EVEN IF listed. You never fail an already-failed operation a
//     second time; that reopens the DoS the list just bounded. The exemption is
//     enforced in failCloseable, in CODE, not only in docs.
//   - REQ-6.9: the eligible types are exactly policy.allow, skill.execute,
//     capability.grant, trustroot.change, config.change. Anything else on a
//     configured list is a config error (bounding the DoS surface, REQ-6.8).
//   - REQ-6.10a: policy.allow is in EVERY skill's load path, so listing it needs a
//     SEPARATE confirmation (ConfirmPolicyAllow), distinct from enabling required.
//   - REQ-6.10b: "durably accepted" for policy.allow is spool acceptance, never a
//     network/broker ack; the enforcement in deliver reaches only local sinks.
//
// O3 / SPEC-0247 P1.3 HONESTY (AUD-07). This policy makes `required` a fail-close
// for the LISTED types. Whether that is a *policy* or merely *a request* depends
// on WHERE its config was read from. A `required` config MUST be sourced from the
// highest-precedence, root-owned tier (managed settings, REQ-11.2). SPEC-0247
// P1.3 (managed-settings pinning) is NOT yet marked in force: without it a
// same-uid user can rewrite the source and flip `required` off, so on such a host
// this is advisory (AUD-07). This package does NOT claim it read a pinned tier: it
// validates a config it is handed. The caller that sources the bytes owns the
// pinning check and the operator warning (cmd/skillctl surfaces it in
// `session baseline`: the RED "advisory-only until SPEC-0247 P1.3 pinned" banner).

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// RequiredPolicy is the validated §6b positive list. It is the DoS boundary of
// ModeRequired (REQ-6.8): only a type on the list, that is not a denial type, and
// (for policy.allow) confirmed, can ever fail a caller's operation closed. Build
// one with RequiredConfig.BuildPolicy; a zero/nil RequiredPolicy fail-closes
// nothing.
type RequiredPolicy struct {
	allow         map[EventType]struct{} // configured, validated subset of the REQ-6.9 five.
	policyAllowOK bool                   // the getrennte Bestaetigung for policy.allow (REQ-6.10a).
}

// denialEventTypes are the DENIAL events (REQ-6.7): a denial logs an operation
// that ALREADY failed, so failing it a second time protects no one and reopens
// the DoS the positive list just bounded. They are exempt from required
// fail-close EVEN IF an operator lists them; the exemption is NOT configurable.
var denialEventTypes = map[EventType]struct{}{
	EventPolicyDeny:       {},
	EventSignatureReject:  {},
	EventRevocationDetect: {},
}

// canonicalRequiredTypes is the REQ-6.9 decided positive list: the ONLY event
// types an operator may make fail-closeable under required. Anything outside it
// on a configured list is a config error (bounding the DoS surface, REQ-6.8).
var canonicalRequiredTypes = map[EventType]struct{}{
	EventPolicyAllow:     {},
	EventSkillExecute:    {},
	EventCapabilityGrant: {},
	EventTrustrootChange: {},
	EventConfigChange:    {},
}

// IsDenialEventType reports whether t is a non-configurable denial-exempt type
// (REQ-6.7): a required policy can never fail-close on it, whatever the config says.
func IsDenialEventType(t EventType) bool {
	_, ok := denialEventTypes[t]
	return ok
}

// CanonicalRequiredTypes returns the REQ-6.9 eligible positive list, sorted. The
// returned slice is a copy the caller may mutate.
func CanonicalRequiredTypes() []EventType {
	out := make([]EventType, 0, len(canonicalRequiredTypes))
	for t := range canonicalRequiredTypes {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// failCloseable reports whether an event of type t must fail the caller's
// operation closed when it was not durably accepted. ALL of the following gate it,
// and each is a distinct code check, not a comment:
//
//	(1) t is on the operator's configured positive list;
//	(2) t is NOT a denial type (REQ-6.7, the non-configurable exemption);
//	(3) if t is policy.allow, the separate confirmation was given (REQ-6.10a).
//
// A nil receiver (no policy) returns false, so a required Dispatcher built without
// a policy, and every non-required Dispatcher, fail-closes nothing.
func (p *RequiredPolicy) failCloseable(t EventType) bool {
	if p == nil {
		return false
	}
	if IsDenialEventType(t) { // (2) checked first, so a listed denial is still exempt.
		return false
	}
	if _, ok := p.allow[t]; !ok { // (1)
		return false
	}
	if t == EventPolicyAllow && !p.policyAllowOK { // (3)
		return false
	}
	return true
}

// RequiredConfig is the raw, operator-facing shape of the required-mode policy as
// read from a config surface. It is validated by BuildPolicy. A required policy
// MUST be sourced from the highest-precedence, root-owned tier (managed settings,
// REQ-11.2 / the O3 note in the file header); this type does not itself enforce
// that, it only validates the parsed values.
type RequiredConfig struct {
	// Mode is the §6 delivery mode name. Only "required" builds a policy; any
	// other value (including "", "best-effort", "durable") builds no policy and is
	// not an error (BuildPolicy returns nil, nil).
	Mode string
	// AllowList is the operator's positive list of event-type names that fail-close
	// under required (REQ-6.6). Empty under required is a config error.
	AllowList []string
	// ConfirmPolicyAllow is the SEPARATE REQ-6.10a switch. It MUST be a different
	// toggle from whatever enables required, so an operator turning on required does
	// not accidentally couple skill execution to a file write. policy.allow on the
	// list without this is a config error.
	ConfirmPolicyAllow bool
}

// ErrRequiredConfig is the sentinel wrapped by every BuildPolicy rejection, so a
// caller can errors.Is it without matching on message text.
var ErrRequiredConfig = errors.New("auditevent: invalid required-mode config")

// BuildPolicy validates c into a RequiredPolicy (SPEC-0403 §6b).
//
//	Mode != "required"                         : (nil, nil) no policy, not an error.
//	required + EMPTY allow-list                : ErrRequiredConfig (REQ-6.6).
//	required + a type outside the REQ-6.9 five : ErrRequiredConfig (REQ-6.9/6.8);
//	                                             a denial type is TOLERATED but inert (REQ-6.7).
//	required + only inert (denial) entries     : ErrRequiredConfig (nothing to enforce).
//	policy.allow listed without confirmation   : ErrRequiredConfig (REQ-6.10a).
//
// A rejected config MUST be treated by the caller as fatal to activating required
// (fail-closed on config), never silently downgraded to advisory: a malformed
// high-security policy that silently becomes best-effort is exactly the false
// assurance §6b forbids.
func (c RequiredConfig) BuildPolicy() (*RequiredPolicy, error) {
	if Mode(strings.TrimSpace(c.Mode)) != ModeRequired {
		return nil, nil
	}

	// REQ-6.6: required WITHOUT a positive list is a config error.
	hasEntry := false
	for _, s := range c.AllowList {
		if strings.TrimSpace(s) != "" {
			hasEntry = true
			break
		}
	}
	if !hasEntry {
		return nil, fmt.Errorf("%w: mode=required needs a non-empty allow-list (REQ-6.6): a required with no positive list is the unbounded DoS surface the list exists to bound",
			ErrRequiredConfig)
	}

	allow := make(map[EventType]struct{}, len(c.AllowList))
	for _, raw := range c.AllowList {
		name := EventType(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		if IsDenialEventType(name) {
			// REQ-6.7: tolerated on the list, but never enforceable. Keep it OUT of
			// the fail-close set rather than error, so a copy-paste of the full
			// taxonomy is not rejected; the exemption is what matters.
			continue
		}
		if _, ok := canonicalRequiredTypes[name]; !ok {
			return nil, fmt.Errorf("%w: %q is not a required-eligible event type (REQ-6.9: only policy.allow, skill.execute, capability.grant, trustroot.change, config.change)",
				ErrRequiredConfig, name)
		}
		allow[name] = struct{}{}
	}
	if len(allow) == 0 {
		// The list held only denial-exempt entries: `required` is on, but nothing
		// can ever fail-close. That is a mis-config (the list is BOTH the DoS bound
		// AND the reason to fail-close). Reject rather than silently degrade.
		return nil, fmt.Errorf("%w: the allow-list has no enforceable type (only denial-exempt entries, REQ-6.6/6.7)",
			ErrRequiredConfig)
	}
	if _, wantsPolicyAllow := allow[EventPolicyAllow]; wantsPolicyAllow && !c.ConfirmPolicyAllow {
		return nil, fmt.Errorf("%w: policy.allow needs the separate confirmation (REQ-6.10a): it sits in EVERY skill's load path, so listing it couples skill execution to a spool write and must be an explicit, distinct opt-in",
			ErrRequiredConfig)
	}

	return &RequiredPolicy{allow: allow, policyAllowOK: c.ConfirmPolicyAllow}, nil
}

// NewDispatcherRequired builds a ModeRequired Dispatcher that ENFORCES fail-close
// for the event types on policy (SPEC-0403 §6b). Obtain policy from
// RequiredConfig.BuildPolicy (which rejects an empty allow-list, REQ-6.6). A nil
// policy is accepted but fail-closes NOTHING (it degrades to durable-equivalent):
// pass a validated, non-nil policy for real enforcement.
//
// sinks SHOULD be a SINGLE durable sink (OutboxSink). Under required, "durably
// accepted" is every configured sink accepting the write, which for the OutboxSink
// is spool acceptance (REQ-6.10b), never a network ack.
func NewDispatcherRequired(policy *RequiredPolicy, r Redactor, sinks ...Sink) *Dispatcher {
	d := NewDispatcherMode(ModeRequired, r, sinks...)
	d.required = policy
	return d
}
