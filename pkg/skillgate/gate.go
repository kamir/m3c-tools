package skillgate

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// SPEC-0202 §8.2 refusal exit codes. Mirrors the Python SkillEnvelopeViolation.
const (
	ExitCapabilityMissing = 30
	ExitDataSourceMissing = 31
	ExitEgressNotAllowed  = 32
	ExitSubprocessDenied  = 33
	ExitFileOutsideEnv    = 34
	ExitTokenExpired      = 35
	ExitTokenRevoked      = 36
	ExitInvalidSignature  = 37
	ExitRuntimeQuota      = 38
	ExitEgressByteQuota   = 39
)

// Stable refusal codes paired with the InvocationEvent emitted on refuse.
// Kept as untyped string constants so JSON marshaling matches the Python
// reference 1:1 ("subprocess_not_allowed", etc.).
const (
	RefusalSubprocessNotAllowed = "subprocess_not_allowed"
	RefusalSubprocessDenied     = "subprocess_denied"
	RefusalEgressNotAllowed     = "egress_not_allowed"
	RefusalCapabilityMissing    = "capability_missing"
	RefusalDestructiveRequired  = "destructive_required"
	RefusalExpired              = "expired"
)

// GateAction is implemented by every action shape the gate enforces.
// Adding a new surface = adding a new GateAction implementation; the gate
// keeps a tiny static dispatch in Allow().
type GateAction interface{ isGateAction() }

// Subprocess models an exec request. The gate checks subprocess_denylist
// FIRST (deny beats allow) then subprocess_allowlist.
type Subprocess struct {
	Name string
	Args []string
}

func (Subprocess) isGateAction() {}

// Egress models an outbound network request. The gate checks
// envelope.egress_allowlist; matching is case-insensitive on host with
// optional ":port". An entry "host" matches any port; "host:port" requires
// the exact port. A leading "*." entry matches the suffix.
type Egress struct {
	Host string
	Port int
}

func (Egress) isGateAction() {}

// Capability models a generic capability check. The gate looks for an exact
// match in envelope.capabilities OR a "<cap>:<arg>" prefix match (e.g.
// "subprocess_run:bash" satisfies a "subprocess_run" requirement).
type Capability struct {
	Name string
}

func (Capability) isGateAction() {}

// Destructive is a sentinel action used when the caller is about to perform
// a destructive operation; the gate refuses unless envelope.destructive=true.
type Destructive struct{}

func (Destructive) isGateAction() {}

// InvocationPoster is the audit-event sink. Implementations may be HTTP-backed
// (HTTPInvocationPoster) or in-memory (the test fakes).
type InvocationPoster interface {
	PostInvocation(ev InvocationEvent) error
}

// InvocationEvent is the JSON shape posted to aims-core. The fields mirror
// the kafscale_stub envelope's `payload` for `gate.allowed` / `gate.refused`
// event types (SPEC-0202 §9 + kafscale_stub.publish_event).
type InvocationEvent struct {
	Type         string `json:"type"`
	TokenID      string `json:"token_id"`
	SkillName    string `json:"skill_name"`
	Tenant       string `json:"tenant"`
	Timestamp    string `json:"timestamp"`
	RefusalCode  string `json:"refusal_code,omitempty"`
	RequestedCmd string `json:"requested_cmd,omitempty"`
}

// SignedSink records ONE device-signed, action-level InvocationRecord into the
// durable signed trail (SPEC-0202 §9). It is OPTIONAL on a Gate: when nil, the
// gate only posts the legacy unsigned InvocationEvent to AuditPoster. When set,
// every allow/refuse ALSO produces a signed record — so action-level events
// (subprocess / egress / capability checks inside a running skill) join the same
// Art.12 trail the hook writes. The sink owns signing + appending and MUST be
// fire-and-forget (the cooperative model never lets a logging failure block
// enforcement); the gate calls it as a bare statement.
type SignedSink func(InvocationRecord)

// Gate enforces a verified token's envelope. It is COOPERATIVE — see the
// package doc.
type Gate struct {
	Token       *Token
	AuditPoster InvocationPoster
	// SignedSink, when non-nil, receives one signed action-level record per
	// allow/refuse. Optional — see SignedSink.
	SignedSink SignedSink
	// SessionID is stamped into signed records so action events join the same
	// session join-key the hook uses (SPEC-0277 P3 forward-compat). Optional.
	SessionID string
	Now       func() time.Time // injectable clock; defaults to time.Now().UTC()
}

// GateError is returned by Allow() on refuse. ExitCode maps to SPEC-0202 §8.2.
type GateError struct {
	Code     string // refusal_code, e.g. "egress_not_allowed"
	ExitCode int    // 30..39
	Message  string
}

func (e *GateError) Error() string {
	return fmt.Sprintf("skillgate refused: %s (exit %d): %s", e.Code, e.ExitCode, e.Message)
}

// nowFn returns the gate's configured clock or time.Now().UTC().
func (g *Gate) nowFn() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now().UTC()
}

// Allow checks whether the requested action is permitted by the token's
// envelope. Returns nil on allow, a *GateError on refuse. In both cases
// the gate posts an InvocationEvent to AuditPoster (best-effort; audit
// failures are logged but never block the gate decision).
func (g *Gate) Allow(action GateAction) error {
	if g.Token == nil {
		return g.refuse(RefusalCapabilityMissing, ExitCapabilityMissing,
			"no token attached to gate", "")
	}
	// Expiry pre-check — Verify() should already have caught this, but a
	// caller invoking Allow() far after Verify() may cross the boundary.
	if exp, err := time.Parse("2006-01-02T15:04:05Z", g.Token.ExpiresAt); err == nil {
		if !g.nowFn().Before(exp) {
			return g.refuse(RefusalExpired, ExitTokenExpired, "token expired", "")
		}
	}

	switch a := action.(type) {
	case Subprocess:
		return g.checkSubprocess(a)
	case Egress:
		return g.checkEgress(a)
	case Capability:
		return g.checkCapability(a)
	case Destructive:
		return g.checkDestructive()
	default:
		return g.refuse(RefusalCapabilityMissing, ExitCapabilityMissing,
			fmt.Sprintf("unknown action type %T", action), "")
	}
}

// checkSubprocess: denylist beats allowlist. Allowlist entries may be a
// basename ("bash") or a full absolute path; matching is on the binary's
// basename to be portable across PATH layouts.
func (g *Gate) checkSubprocess(s Subprocess) error {
	base := filepath.Base(s.Name)
	requested := base
	if len(s.Args) > 0 {
		requested = base + " " + strings.Join(s.Args, " ")
	}

	// Denylist beats allowlist.
	for _, d := range g.Token.Envelope.SubprocessDenylist {
		if d == base || d == s.Name {
			return g.refuse(RefusalSubprocessDenied, ExitSubprocessDenied,
				fmt.Sprintf("subprocess %q is in denylist", base), requested)
		}
	}
	// Capability check: subprocess_run must be in capabilities (exactly or
	// scoped as "subprocess_run:<bin>").
	hasCap := false
	for _, c := range g.Token.Envelope.Capabilities {
		if c == "subprocess_run" || c == "subprocess_run:"+base ||
			c == "subprocess_run:"+s.Name {
			hasCap = true
			break
		}
	}
	if !hasCap {
		return g.refuse(RefusalCapabilityMissing, ExitCapabilityMissing,
			"capability subprocess_run not in envelope", requested)
	}
	// Allowlist check.
	for _, a := range g.Token.Envelope.SubprocessAllowlist {
		if a == base || a == s.Name {
			g.audit("gate.allowed", "", requested)
			return nil
		}
	}
	return g.refuse(RefusalSubprocessNotAllowed, ExitSubprocessDenied,
		fmt.Sprintf("subprocess %q not in allowlist", base), requested)
}

// checkEgress: match host[:port] entries. "*.example" is a suffix match.
func (g *Gate) checkEgress(e Egress) error {
	hasCap := false
	for _, c := range g.Token.Envelope.Capabilities {
		if c == "egress" || strings.HasPrefix(c, "egress:") {
			hasCap = true
			break
		}
	}
	if !hasCap {
		return g.refuse(RefusalCapabilityMissing, ExitCapabilityMissing,
			"capability egress not in envelope",
			fmt.Sprintf("%s:%d", e.Host, e.Port))
	}

	host := strings.ToLower(e.Host)
	for _, allowed := range g.Token.Envelope.EgressAllowlist {
		al := strings.ToLower(allowed)
		alHost, alPort, hasPort := splitHostPort(al)
		if hasPort {
			if e.Port != 0 && alPort != e.Port {
				continue
			}
		}
		if matchHost(host, alHost) {
			g.audit("gate.allowed", "", fmt.Sprintf("%s:%d", e.Host, e.Port))
			return nil
		}
	}
	return g.refuse(RefusalEgressNotAllowed, ExitEgressNotAllowed,
		fmt.Sprintf("egress to %s:%d not in allowlist", e.Host, e.Port),
		fmt.Sprintf("%s:%d", e.Host, e.Port))
}

// checkCapability: exact match or "<cap>:<arg>" prefix match.
func (g *Gate) checkCapability(c Capability) error {
	for _, granted := range g.Token.Envelope.Capabilities {
		if granted == c.Name {
			g.audit("gate.allowed", "", c.Name)
			return nil
		}
		if strings.HasPrefix(granted, c.Name+":") {
			g.audit("gate.allowed", "", c.Name)
			return nil
		}
	}
	return g.refuse(RefusalCapabilityMissing, ExitCapabilityMissing,
		fmt.Sprintf("capability %q not in envelope", c.Name), c.Name)
}

// checkDestructive — refuses unless envelope.destructive=true.
func (g *Gate) checkDestructive() error {
	if g.Token.Envelope.Destructive {
		g.audit("gate.allowed", "", "destructive")
		return nil
	}
	return g.refuse(RefusalDestructiveRequired, ExitCapabilityMissing,
		"destructive operation requires envelope.destructive=true", "destructive")
}

// refuse posts the gate.refused event AND returns a *GateError so the
// caller can inspect Code/ExitCode and translate to OS exit.
func (g *Gate) refuse(code string, exitCode int, msg, requestedCmd string) error {
	g.audit("gate.refused", code, requestedCmd)
	return &GateError{Code: code, ExitCode: exitCode, Message: msg}
}

// audit fires-and-forgets to the AuditPoster AND (when set) the SignedSink. A
// nil poster/sink is allowed (e.g. in tests where audit is irrelevant); failures
// are silently swallowed because the cooperative model never lets audit failure
// block enforcement.
func (g *Gate) audit(eventType, refusalCode, requestedCmd string) {
	now := g.nowFn().Format("2006-01-02T15:04:05Z")
	if g.AuditPoster != nil {
		ev := InvocationEvent{
			Type:         eventType,
			TokenID:      g.Token.TokenID,
			SkillName:    g.Token.SkillName,
			Tenant:       g.Token.TenantScope,
			Timestamp:    now,
			RefusalCode:  refusalCode,
			RequestedCmd: requestedCmd,
		}
		_ = g.AuditPoster.PostInvocation(ev) // best-effort
	}
	if g.SignedSink != nil {
		// Action-level signed record — the durable Art.12 evidence for what the
		// running skill actually did. exit_code carries the gate verdict: 0 on
		// allow, the refusal exit (30..39 — not known here) is left to the sink's
		// caller; we encode allow/refuse via refusal_code (empty = allowed).
		exit := 0
		if refusalCode != "" {
			exit = 1
		}
		g.SignedSink(InvocationRecord{
			EventType:    eventType, // "gate.allowed" | "gate.refused"
			SkillName:    g.Token.SkillName,
			SkillVersion: g.Token.SkillVersion,
			SkillDigest:  g.Token.BundleDigest,
			Action:       requestedCmd,
			Tool:         g.Token.SkillName,
			TokenID:      g.Token.TokenID,
			SessionID:    g.SessionID,
			OccurredAt:   now,
			ExitCode:     exit,
			RefusalCode:  refusalCode,
		})
	}
}

// splitHostPort parses "host" or "host:port" allowlist entries. Returns
// (host, port, hasPort). port is 0 when absent.
func splitHostPort(entry string) (string, int, bool) {
	idx := strings.LastIndex(entry, ":")
	if idx < 0 {
		return entry, 0, false
	}
	hostPart := entry[:idx]
	portPart := entry[idx+1:]
	port := 0
	for _, c := range portPart {
		if c < '0' || c > '9' {
			return entry, 0, false
		}
		port = port*10 + int(c-'0')
	}
	return hostPart, port, true
}

// matchHost: exact match OR wildcard suffix match ("*.example.com" matches
// "api.example.com" but not "example.com").
func matchHost(host, pattern string) bool {
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}
	return false
}
