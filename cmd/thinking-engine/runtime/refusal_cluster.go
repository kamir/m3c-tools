package runtime

import (
	"context"
	"sort"
	"time"
)

// RefusalCluster is the SPEC-0167 A.4 reflector that groups
// gate.refused events by rule_hit over a sliding 1-hour window and
// emits a Reflection when count ≥ Threshold for the same rule.
//
// Output content shape (A.4):
//   {
//     "rule":           "egress_host_not_allowed",
//     "count":          7,
//     "window_start":   "2026-05-06T14:00:00Z",
//     "window_end":     "2026-05-06T15:00:00Z",
//     "sample_targets": ["https://attacker.example/...", ...]
//   }
type RefusalCluster struct {
	Window    time.Duration // default 1h
	Threshold int           // default 5

	emitter ReflectionEmitter
	idFn    func() string
	clock   func() time.Time

	// Per-rule sliding window of (Thought, occurredAt). Bounded by
	// Window — entries older than now-Window are evicted on Observe/Tick.
	byRule map[string][]refusalSample

	// Suppression: once a rule fires, don't re-fire until the window
	// has rolled past the firing event. lastFired[rule] is the
	// firing-event timestamp; subsequent samples count toward a fresh
	// window once now > lastFired[rule] + Window.
	lastFired map[string]time.Time
}

type refusalSample struct {
	thoughtID  string
	occurredAt time.Time
	target     string // truncated to 256 chars at observe time
}

// NewRefusalCluster constructs the reflector with defaults applied.
func NewRefusalCluster(emitter ReflectionEmitter, idFn func() string, clock func() time.Time) *RefusalCluster {
	if clock == nil {
		clock = time.Now
	}
	return &RefusalCluster{
		Window:    1 * time.Hour,
		Threshold: 5,
		emitter:   emitter,
		idFn:      idFn,
		clock:     clock,
		byRule:    map[string][]refusalSample{},
		lastFired: map[string]time.Time{},
	}
}

func (r *RefusalCluster) Name() string { return "refusal-cluster" }

func (r *RefusalCluster) Observe(ctx context.Context, t Thought) error {
	// Only refused events carry a rule_hit; skip all others fast.
	if t.Type != ThoughtSignal {
		return nil
	}
	content, ok := t.Content.(map[string]interface{})
	if !ok {
		return nil
	}
	if et, _ := content["event_type"].(string); et != string(EventGateRefused) {
		return nil
	}
	rule, _ := content["rule_hit"].(string)
	if rule == "" {
		return nil
	}

	now := r.clock()
	target, _ := content["target"].(string)
	if len(target) > 256 {
		target = target[:256]
	}

	r.evict(rule, now)
	r.byRule[rule] = append(r.byRule[rule], refusalSample{
		thoughtID:  t.ThoughtID,
		occurredAt: t.Timestamp,
		target:     target,
	})

	if len(r.byRule[rule]) >= r.Threshold {
		// Suppression: don't re-fire if we already fired for this rule
		// inside the current window.
		if last, ok := r.lastFired[rule]; ok && now.Sub(last) < r.Window {
			return nil
		}
		refl := r.makeReflection(rule, now)
		r.lastFired[rule] = now
		// Reset the sliding window for this rule on fire so the next
		// reflection requires Threshold fresh samples.
		delete(r.byRule, rule)
		return r.emitter.Emit(ctx, refl)
	}
	return nil
}

func (r *RefusalCluster) Tick(ctx context.Context, now time.Time) error {
	// On tick, evict aged samples for every rule. No emissions on tick;
	// this reflector is observation-driven.
	for rule := range r.byRule {
		r.evict(rule, now)
		if len(r.byRule[rule]) == 0 {
			delete(r.byRule, rule)
		}
	}
	return nil
}

func (r *RefusalCluster) Drain(ctx context.Context) ([]Reflection, error) {
	// At shutdown, do NOT emit half-formed reflections (count below
	// Threshold). Drop the in-flight state.
	return nil, nil
}

func (r *RefusalCluster) evict(rule string, now time.Time) {
	cutoff := now.Add(-r.Window)
	in := r.byRule[rule]
	// Find first index whose occurredAt >= cutoff. Samples were
	// appended in arrival order, which is roughly chronological — but
	// we don't trust that for correctness; sort if needed.
	if !sort.SliceIsSorted(in, func(a, b int) bool { return in[a].occurredAt.Before(in[b].occurredAt) }) {
		sort.Slice(in, func(a, b int) bool { return in[a].occurredAt.Before(in[b].occurredAt) })
	}
	keep := 0
	for i, s := range in {
		if !s.occurredAt.Before(cutoff) {
			keep = i
			break
		}
		keep = i + 1
	}
	r.byRule[rule] = in[keep:]
}

func (r *RefusalCluster) makeReflection(rule string, firedAt time.Time) Reflection {
	samples := r.byRule[rule]
	thoughtIDs := make([]string, 0, len(samples))
	targets := make([]string, 0, min(len(samples), 5))
	for i, s := range samples {
		thoughtIDs = append(thoughtIDs, s.thoughtID)
		if i < cap(targets) {
			targets = append(targets, s.target)
		}
	}
	windowStart := firedAt.Add(-r.Window)

	return Reflection{
		SchemaVer:    1,
		ReflectionID: r.idFn(),
		ThoughtIDs:   thoughtIDs,
		Strategy:     "classify",
		Objective:    "runtime_pattern_detection",
		Content: map[string]interface{}{
			"reflector":      r.Name(),
			"rule":           rule,
			"count":          len(samples),
			"window_start":   windowStart,
			"window_end":     firedAt,
			"sample_targets": targets,
		},
		Trace: ReflectionTrace{
			PromptID: "rule:" + r.Name() + "/v1",
			Model:    "rule:" + r.Name() + "/v1",
		},
		Timestamp: firedAt,
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
