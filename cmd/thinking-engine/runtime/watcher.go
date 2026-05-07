package runtime

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// WatcherConfig binds one runtime-invocation-watcher instance to a
// (tenant, user_context_id) pair. The watcher subscribes to the
// tenant-scope invocation topic and projects the user's own events
// onto the per-context Thought stream.
//
// MUST invariants from SPEC-0167 A.2:
//   - CallerIdentity is the filter key. Events whose
//     event.CallerIdentity != cfg.CallerIdentity are dropped silently;
//     no projection, no reflection, no log spam.
//   - Tenant lands in Thought.Context.Domain so a user belonging to
//     multiple tenants can see which one each runtime Thought came from.
//   - Reflectors are PER (tenant, ctx); a watcher instance owns its
//     own reflector slice.
type WatcherConfig struct {
	Tenant         string // e.g. "kup-berlin"
	UserContextID  string // engine's --user-context-id flag value
	CallerIdentity string // e.g. "id:kamir@m3c" — the filter key
	CtxHash        string // first 16 hex of SHA-256(UserContextID), per SPEC-0167

	// Backpressure (SPEC-0167 A.6).
	MaxThoughtsPerMinute int   // default 60
	GateAllowedSampleN   int   // default 50; 1-in-N sampling. 0 disables gate.allowed projection.
	TickInterval         time.Duration // default 1 * time.Minute

	// Wired by the engine bootstrap; never nil at runtime.
	Consumer  EventConsumer
	Publisher ThoughtPublisher
	Emitter   ReflectionEmitter
	Reflectors []Reflector

	// IDFn produces UUIDv7s for Thought.ThoughtID. Tests may inject a
	// deterministic fn; production uses a uuidv7 generator.
	IDFn func() string

	// Clock is the time source. Tests inject a fake; production uses
	// time.Now.
	Clock func() time.Time
}

// Watcher is the runtime-invocation-watcher main loop. One per (tenant,
// ctx) subscription. Implements SPEC-0167 A.2 / A.3 / A.6.
type Watcher struct {
	cfg WatcherConfig

	// backpressure budget (per minute, refilled by Tick)
	budgetRemaining int
	budgetWindow    time.Time

	// allowed-sampling counter
	allowedSeen int

	// drop-audit accumulator for SPEC-0167 A.6's "one drop-audit event
	// per minute" requirement
	droppedAllowed int
	droppedAtten   int
}

// NewWatcher builds a Watcher with cfg defaults applied. Returns an
// error if any required field is unset.
func NewWatcher(cfg WatcherConfig) (*Watcher, error) {
	if cfg.Tenant == "" || cfg.UserContextID == "" || cfg.CallerIdentity == "" {
		return nil, errors.New("runtime: tenant, user_context_id, and caller_identity are required")
	}
	if cfg.CtxHash == "" {
		return nil, errors.New("runtime: ctx_hash must be precomputed by the bootstrap")
	}
	if cfg.Consumer == nil || cfg.Publisher == nil || cfg.Emitter == nil {
		return nil, errors.New("runtime: consumer, publisher, and emitter must all be wired")
	}
	if cfg.IDFn == nil {
		return nil, errors.New("runtime: IDFn (uuidv7 generator) is required")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.MaxThoughtsPerMinute == 0 {
		cfg.MaxThoughtsPerMinute = 60
	}
	if cfg.GateAllowedSampleN == 0 {
		cfg.GateAllowedSampleN = 50
	}
	if cfg.TickInterval == 0 {
		cfg.TickInterval = 1 * time.Minute
	}
	return &Watcher{
		cfg:             cfg,
		budgetRemaining: cfg.MaxThoughtsPerMinute,
		budgetWindow:    cfg.Clock(),
	}, nil
}

// Run drives the watcher until ctx is cancelled. Two goroutines:
// the consumer loop (Next → project → publish + observe) and the tick
// loop (refill budget + flush drop-audits + reflector.Tick + emit).
//
// TODO(SPEC-0202 Phase 5): wire actual segmentio/kafka-go consumer +
// producer; this stub just blocks on consumer.Next.
func (w *Watcher) Run(ctx context.Context) error {
	tickCh := time.NewTicker(w.cfg.TickInterval)
	defer tickCh.Stop()

	errCh := make(chan error, 1)
	go func() { errCh <- w.consumerLoop(ctx) }()

	for {
		select {
		case <-ctx.Done():
			return w.drain(ctx)
		case now := <-tickCh.C:
			w.refillBudget(now)
			w.flushDropAudit(ctx, now)
			for _, r := range w.cfg.Reflectors {
				if err := r.Tick(ctx, now); err != nil {
					// TODO: structured log; do not abort the loop on a
					// single reflector failure — the others must keep
					// running. SPEC-0167 A.9 #6.
					_ = err
				}
			}
		case err := <-errCh:
			return err
		}
	}
}

func (w *Watcher) consumerLoop(ctx context.Context) error {
	for {
		ev, err := w.cfg.Consumer.Next(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			// TODO: log + retry policy. SPEC-0167 A.9 #6 — degrade to
			// "no runtime Insights" rather than crash.
			return fmt.Errorf("consumer.Next: %w", err)
		}

		// --- A.2 isolation invariant: filter by caller_identity ---
		if ev.CallerIdentity != w.cfg.CallerIdentity {
			continue // never project, never log; cross-user leak guard
		}

		t, projected := w.project(ev)
		if !projected {
			continue
		}

		if !w.takeBudget(ev) {
			continue
		}

		if err := w.cfg.Publisher.Publish(ctx, t); err != nil {
			// TODO: surface a `watcher.publish_failed` audit; do not
			// crash the engine.
			_ = err
			continue
		}

		// Feed the projected thought to every reflector. Each
		// reflector decides internally whether to act.
		for _, r := range w.cfg.Reflectors {
			if err := r.Observe(ctx, t); err != nil {
				// TODO: log; reflectors must not poison the watcher.
				_ = err
			}
		}
	}
}

// project applies SPEC-0167 A.3's mapping rules and returns whether
// this event should produce a Thought at all.
func (w *Watcher) project(ev InvocationEvent) (Thought, bool) {
	var thoughtType ThoughtType
	switch ev.EventType {
	case EventGateRefused:
		thoughtType = ThoughtSignal
	case EventCapabilityRevoked:
		thoughtType = ThoughtSignal
	case EventInvocationCompleted:
		// Only failed/killed completions project; ok completions are
		// noise at the T layer. SPEC-0167 A.3.
		if ev.ExitStatus != "fail" && ev.ExitStatus != "killed" {
			return Thought{}, false
		}
		thoughtType = ThoughtSignal
	case EventGateAllowed:
		// 1-in-N sampled.
		w.allowedSeen++
		if w.cfg.GateAllowedSampleN <= 0 || w.allowedSeen%w.cfg.GateAllowedSampleN != 0 {
			return Thought{}, false
		}
		thoughtType = ThoughtObservation
	case EventCapabilityAttenuated:
		thoughtType = ThoughtObservation
	case EventCapabilityIssued:
		// Pure routing; no reflective value (A.3).
		return Thought{}, false
	default:
		// Unknown event_type — forward-compat: log + drop.
		// TODO: emit `watcher.unknown_event_type` once.
		return Thought{}, false
	}

	content := map[string]interface{}{
		"event_type":    string(ev.EventType),
		"surface":       ev.Surface,
		"target":        ev.Target,
		"exit_code":     ev.ExitCode,
		"rule_hit":      ev.RuleHit,
		"bundle_digest": ev.BundleDigest,
		"skill_name":    ev.SkillName,
	}
	if ev.EventType == EventInvocationCompleted {
		content["exit_status"] = ev.ExitStatus
		content["wall_clock_ms"] = ev.WallClockMS
		content["egress_bytes"] = ev.EgressBytes
	}
	if ev.EventType == EventCapabilityAttenuated {
		content["attenuation_rule"] = ev.AttenuationRule
		content["attenuation_value"] = ev.AttenuationValue
		content["applied_by"] = ev.AppliedBy
	}
	if ev.EventType == EventCapabilityRevoked {
		content["revoked_by"] = ev.RevokedBy
		content["revoked_reason"] = ev.RevokedReason
	}

	tags := []string{
		"skill:" + ev.SkillName,
		"tenant:" + ev.Tenant,
	}
	if len(ev.BundleDigest) >= len("sha256:")+8 {
		tags = append(tags, "digest:"+ev.BundleDigest[len("sha256:"):len("sha256:")+8])
	}

	return Thought{
		SchemaVer: 1,
		ThoughtID: w.cfg.IDFn(),
		Type:      thoughtType,
		Content:   content,
		Source: ThoughtSource{
			Kind: "agent",
			Ref:  fmt.Sprintf("skill-invocation://%s/%s", ev.Tenant, ev.TokenID),
		},
		Tags:      tags,
		Timestamp: ev.OccurredAt,
		Context: &ThoughtContext{
			Domain: ev.Tenant,
		},
		Provenance: ThoughtProvenance{
			CapturedBy:       "runtime-invocation-watcher/v1",
			ParentArtifactID: ev.BundleDigest, // A.3: graph edge to bundle
		},
	}, true
}

// takeBudget honors the per-minute thought budget. Refusals and
// signal-class events are NEVER dropped (A.6 invariant); only
// gate.allowed observations and attenuation observations may be dropped.
func (w *Watcher) takeBudget(ev InvocationEvent) bool {
	// Always-allow classes (signal): refused, revoked, completed-fail.
	switch ev.EventType {
	case EventGateRefused, EventCapabilityRevoked, EventInvocationCompleted:
		// Decrement budget but never refuse — overflow is recorded as
		// budget debt; tick refills.
		w.budgetRemaining--
		return true
	}
	// Droppable classes.
	if w.budgetRemaining <= 0 {
		switch ev.EventType {
		case EventGateAllowed:
			w.droppedAllowed++
		case EventCapabilityAttenuated:
			w.droppedAtten++
		}
		return false
	}
	w.budgetRemaining--
	return true
}

// refillBudget resets the per-minute window to MaxThoughtsPerMinute.
func (w *Watcher) refillBudget(now time.Time) {
	if now.Sub(w.budgetWindow) >= time.Minute {
		w.budgetRemaining = w.cfg.MaxThoughtsPerMinute
		w.budgetWindow = now
	}
}

// flushDropAudit emits one `watcher.dropped_under_backpressure` audit
// event per minute when drops occurred (A.6).
//
// TODO(SPEC-0202 Phase 5): produce this onto a dedicated audit topic
// or fold into the existing process.events stream.
func (w *Watcher) flushDropAudit(ctx context.Context, now time.Time) {
	if w.droppedAllowed == 0 && w.droppedAtten == 0 {
		return
	}
	// Stub: just zero the counters. Real impl emits an audit event.
	_ = ctx
	_ = now
	w.droppedAllowed = 0
	w.droppedAtten = 0
}

// drain calls Drain on every reflector at shutdown so pending
// reflections aren't lost.
func (w *Watcher) drain(ctx context.Context) error {
	for _, r := range w.cfg.Reflectors {
		out, err := r.Drain(ctx)
		if err != nil {
			// TODO: log; continue draining the rest.
			_ = err
			continue
		}
		for _, refl := range out {
			if err := w.cfg.Emitter.Emit(ctx, refl); err != nil {
				_ = err
			}
		}
	}
	if err := w.cfg.Consumer.Close(); err != nil {
		// TODO: log
		_ = err
	}
	return w.cfg.Publisher.Close()
}
