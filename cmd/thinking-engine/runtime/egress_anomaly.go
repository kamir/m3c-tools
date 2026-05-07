package runtime

import (
	"context"
	"net/url"
	"strings"
	"time"
)

// EgressAnomaly is the SPEC-0167 A.4 reflector that flags egress
// crossings to hosts never-before-seen in this user's stream over the
// preceding KnownWindow. Emits a Reflection when one or more
// new hosts cross the gateway in the trailing AlertWindow.
//
// Output content shape (A.4):
//   {
//     "new_hosts":           ["api.attacker.example", ...],
//     "first_seen_at":       "2026-05-06T14:13:00Z",
//     "related_skill_names": ["didactic-session", ...]
//   }
//
// State model:
//   - knownHosts: every host this user has ever crossed (within
//     KnownWindow), with last-seen timestamp. Hosts older than
//     KnownWindow age out.
//   - candidateNew: hosts seen for the first time in the trailing
//     AlertWindow but not yet emitted. Flushed on Tick or when more
//     than EmitThreshold candidates accumulate.
type EgressAnomaly struct {
	KnownWindow    time.Duration // default 30 days — how long a host stays "known"
	AlertWindow    time.Duration // default 24 hours — anomaly horizon
	EmitThreshold  int           // default 1 — emit on first new host (sensitive)

	emitter ReflectionEmitter
	idFn    func() string
	clock   func() time.Time

	knownHosts   map[string]time.Time
	candidateNew map[string]egressCandidate
}

type egressCandidate struct {
	firstSeen     time.Time
	skillNames    map[string]struct{}
	thoughtIDs    []string
	allowed       bool // if both gate.allowed AND gate.refused observed for this host, prefer refused
	refusedTarget string
}

// NewEgressAnomaly constructs the reflector with defaults applied.
func NewEgressAnomaly(emitter ReflectionEmitter, idFn func() string, clock func() time.Time) *EgressAnomaly {
	if clock == nil {
		clock = time.Now
	}
	return &EgressAnomaly{
		KnownWindow:   30 * 24 * time.Hour,
		AlertWindow:   24 * time.Hour,
		EmitThreshold: 1,
		emitter:       emitter,
		idFn:          idFn,
		clock:         clock,
		knownHosts:    map[string]time.Time{},
		candidateNew:  map[string]egressCandidate{},
	}
}

func (r *EgressAnomaly) Name() string { return "egress-anomaly" }

func (r *EgressAnomaly) Observe(ctx context.Context, t Thought) error {
	content, ok := t.Content.(map[string]interface{})
	if !ok {
		return nil
	}
	surface, _ := content["surface"].(string)
	if !strings.HasPrefix(surface, "http_") {
		return nil
	}
	target, _ := content["target"].(string)
	host := extractHost(target)
	if host == "" {
		return nil
	}
	now := r.clock()

	// Known hosts: refresh last-seen, no anomaly fire.
	if last, ok := r.knownHosts[host]; ok && now.Sub(last) <= r.KnownWindow {
		r.knownHosts[host] = now
		return nil
	}

	// New host (or aged-out re-introduction).
	skillName, _ := content["skill_name"].(string)
	cand, ok := r.candidateNew[host]
	if !ok {
		cand = egressCandidate{
			firstSeen:  now,
			skillNames: map[string]struct{}{},
		}
	}
	if skillName != "" {
		cand.skillNames[skillName] = struct{}{}
	}
	cand.thoughtIDs = append(cand.thoughtIDs, t.ThoughtID)

	// Refused calls dominate allowed in the candidate (we want the
	// CISO to see "this was already blocked" alongside "this was new").
	if et, _ := content["event_type"].(string); et == string(EventGateRefused) {
		cand.allowed = false
		if tgt, _ := content["target"].(string); tgt != "" {
			cand.refusedTarget = tgt
		}
	} else if !ok {
		cand.allowed = true
	}
	r.candidateNew[host] = cand

	if len(r.candidateNew) >= r.EmitThreshold {
		return r.flush(ctx, now)
	}
	return nil
}

func (r *EgressAnomaly) Tick(ctx context.Context, now time.Time) error {
	r.ageOutKnownHosts(now)
	if len(r.candidateNew) == 0 {
		return nil
	}
	return r.flush(ctx, now)
}

func (r *EgressAnomaly) Drain(ctx context.Context) ([]Reflection, error) {
	if len(r.candidateNew) == 0 {
		return nil, nil
	}
	now := r.clock()
	refl := r.makeReflection(now)
	// Promote candidates to known on drain so a graceful restart
	// doesn't immediately re-fire.
	r.promote(now)
	return []Reflection{refl}, nil
}

func (r *EgressAnomaly) flush(ctx context.Context, now time.Time) error {
	refl := r.makeReflection(now)
	r.promote(now)
	return r.emitter.Emit(ctx, refl)
}

func (r *EgressAnomaly) makeReflection(now time.Time) Reflection {
	hosts := make([]string, 0, len(r.candidateNew))
	skillSet := map[string]struct{}{}
	thoughtIDs := []string{}
	earliest := now
	for h, c := range r.candidateNew {
		hosts = append(hosts, h)
		thoughtIDs = append(thoughtIDs, c.thoughtIDs...)
		if c.firstSeen.Before(earliest) {
			earliest = c.firstSeen
		}
		for s := range c.skillNames {
			skillSet[s] = struct{}{}
		}
	}
	skills := make([]string, 0, len(skillSet))
	for s := range skillSet {
		skills = append(skills, s)
	}

	return Reflection{
		SchemaVer:    1,
		ReflectionID: r.idFn(),
		ThoughtIDs:   thoughtIDs,
		Strategy:     "classify",
		Objective:    "runtime_pattern_detection",
		Content: map[string]interface{}{
			"reflector":           r.Name(),
			"new_hosts":           hosts,
			"first_seen_at":       earliest,
			"related_skill_names": skills,
			"alert_window":        r.AlertWindow.String(),
		},
		Trace: ReflectionTrace{
			PromptID: "rule:" + r.Name() + "/v1",
			Model:    "rule:" + r.Name() + "/v1",
		},
		Timestamp: now,
	}
}

// promote moves candidate hosts into the known set and clears the
// candidate map. Called after a flush so we don't re-alert on the same
// host inside the AlertWindow.
func (r *EgressAnomaly) promote(now time.Time) {
	for h := range r.candidateNew {
		r.knownHosts[h] = now
	}
	r.candidateNew = map[string]egressCandidate{}
}

func (r *EgressAnomaly) ageOutKnownHosts(now time.Time) {
	cutoff := now.Add(-r.KnownWindow)
	for h, last := range r.knownHosts {
		if last.Before(cutoff) {
			delete(r.knownHosts, h)
		}
	}
}

// extractHost returns the host from a URL-shaped target. Handles raw
// `https://example.com/...` and bare `example.com:443` shapes.
// Returns "" when target is non-URL (subprocess argv, file path).
func extractHost(target string) string {
	if target == "" {
		return ""
	}
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil {
			return ""
		}
		return strings.ToLower(u.Hostname())
	}
	// `host:port` shape (rare; gateway records URLs but defensive)
	if i := strings.Index(target, ":"); i > 0 {
		return strings.ToLower(target[:i])
	}
	// Argv-shaped or path-shaped — not an egress target
	if strings.ContainsAny(target, "/ ") {
		return ""
	}
	return strings.ToLower(target)
}
