package runtime

import (
	"context"
	"math"
	"time"
)

// TokenLifetimeShape is the SPEC-0167 A.4 reflector that tracks the
// distribution of token lifetimes — how long each capability token
// stayed active before invocation.completed — and emits a weekly
// Reflection when the trailing 7-day distribution shifts more than
// SigmaThreshold standard deviations from the trailing 30-day baseline.
//
// Output content shape (A.4):
//   {
//     "reflector":           "token-lifetime-shape",
//     "period":              "2026-04-29..2026-05-06",
//     "current_mean_seconds": 18.2,
//     "baseline_mean_seconds": 11.4,
//     "current_std_seconds":   9.1,
//     "baseline_std_seconds":  4.8,
//     "z_score":              3.7,
//     "sample_count":          124,
//     "interpretation":       "tokens running longer than baseline — possible runaway skill"
//   }
//
// Privacy: the histogram is over ttl SECONDS, not over token contents.
// No bundle digests, callers, or targets land in the Reflection
// content — just aggregate statistics about timing.
type TokenLifetimeShape struct {
	BaselineWindow time.Duration // default 30 days
	CurrentWindow  time.Duration // default 7 days
	EmitInterval   time.Duration // default 7 days — at most one emission per period
	SigmaThreshold float64       // default 2.0
	MinSamples     int           // default 30 — refuse to emit on thin distributions

	emitter ReflectionEmitter
	idFn    func() string
	clock   func() time.Time

	samples    []lifetimeSample
	lastEmit   time.Time
	thoughtIDs map[string]string // tokenID -> thoughtID for trace
}

type lifetimeSample struct {
	tokenID    string
	completedAt time.Time
	wallSeconds float64
}

// NewTokenLifetimeShape constructs the reflector with defaults applied.
func NewTokenLifetimeShape(emitter ReflectionEmitter, idFn func() string, clock func() time.Time) *TokenLifetimeShape {
	if clock == nil {
		clock = time.Now
	}
	return &TokenLifetimeShape{
		BaselineWindow: 30 * 24 * time.Hour,
		CurrentWindow:  7 * 24 * time.Hour,
		EmitInterval:   7 * 24 * time.Hour,
		SigmaThreshold: 2.0,
		MinSamples:     30,
		emitter:        emitter,
		idFn:           idFn,
		clock:          clock,
		thoughtIDs:     map[string]string{},
	}
}

func (r *TokenLifetimeShape) Name() string { return "token-lifetime-shape" }

func (r *TokenLifetimeShape) Observe(ctx context.Context, t Thought) error {
	content, ok := t.Content.(map[string]interface{})
	if !ok {
		return nil
	}
	if et, _ := content["event_type"].(string); et != string(EventInvocationCompleted) {
		return nil
	}
	wallMS, _ := content["wall_clock_ms"].(int)
	if wallMS <= 0 {
		// Fall back to JSON-parsed numeric (some decoders surface as float64)
		if f, ok := content["wall_clock_ms"].(float64); ok {
			wallMS = int(f)
		}
	}
	if wallMS <= 0 {
		return nil
	}
	// Extract token id from source.ref `skill-invocation://<tenant>/<token_id>`
	tokenID := extractTokenID(t.Source.Ref)
	if tokenID == "" {
		return nil
	}
	r.samples = append(r.samples, lifetimeSample{
		tokenID:     tokenID,
		completedAt: t.Timestamp,
		wallSeconds: float64(wallMS) / 1000.0,
	})
	r.thoughtIDs[tokenID] = t.ThoughtID
	return nil
}

func (r *TokenLifetimeShape) Tick(ctx context.Context, now time.Time) error {
	// Age out samples older than BaselineWindow.
	cutoff := now.Add(-r.BaselineWindow)
	keep := r.samples[:0]
	for _, s := range r.samples {
		if !s.completedAt.Before(cutoff) {
			keep = append(keep, s)
		} else {
			delete(r.thoughtIDs, s.tokenID)
		}
	}
	r.samples = keep

	// Throttle emission.
	if !r.lastEmit.IsZero() && now.Sub(r.lastEmit) < r.EmitInterval {
		return nil
	}

	current, baseline := r.partition(now)
	if len(current) < r.MinSamples || len(baseline) < r.MinSamples {
		return nil
	}

	curMean, curStd := meanStd(current)
	baseMean, baseStd := meanStd(baseline)
	if baseStd == 0 {
		return nil
	}
	z := (curMean - baseMean) / baseStd
	if math.Abs(z) < r.SigmaThreshold {
		return nil
	}

	refl := r.makeReflection(now, current, baseline, curMean, baseMean, curStd, baseStd, z)
	r.lastEmit = now
	return r.emitter.Emit(ctx, refl)
}

func (r *TokenLifetimeShape) Drain(ctx context.Context) ([]Reflection, error) {
	// On shutdown, do not flush partial windows — they'd mislead the
	// next-run baseline. The state is recoverable from Kafka replay.
	return nil, nil
}

// partition splits samples into (current, baseline) where current is
// the trailing CurrentWindow and baseline is the older portion of
// BaselineWindow. The two slices are disjoint by construction.
func (r *TokenLifetimeShape) partition(now time.Time) (current, baseline []lifetimeSample) {
	currentCutoff := now.Add(-r.CurrentWindow)
	for _, s := range r.samples {
		if s.completedAt.Before(currentCutoff) {
			baseline = append(baseline, s)
		} else {
			current = append(current, s)
		}
	}
	return
}

func (r *TokenLifetimeShape) makeReflection(now time.Time, current, baseline []lifetimeSample, curMean, baseMean, curStd, baseStd, z float64) Reflection {
	thoughtIDs := make([]string, 0, len(current))
	for _, s := range current {
		if id, ok := r.thoughtIDs[s.tokenID]; ok {
			thoughtIDs = append(thoughtIDs, id)
		}
	}
	periodStart := now.Add(-r.CurrentWindow)
	interpretation := "tokens running shorter than baseline"
	if z > 0 {
		interpretation = "tokens running longer than baseline — possible runaway skill"
	}
	return Reflection{
		SchemaVer:    1,
		ReflectionID: r.idFn(),
		ThoughtIDs:   thoughtIDs,
		Strategy:     "classify",
		Objective:    "runtime_pattern_detection",
		Content: map[string]interface{}{
			"reflector":             r.Name(),
			"period":                periodStart.Format(time.RFC3339) + ".." + now.Format(time.RFC3339),
			"current_mean_seconds":  curMean,
			"baseline_mean_seconds": baseMean,
			"current_std_seconds":   curStd,
			"baseline_std_seconds":  baseStd,
			"z_score":               z,
			"sample_count":          len(current),
			"interpretation":        interpretation,
		},
		Trace: ReflectionTrace{
			PromptID: "rule:" + r.Name() + "/v1",
			Model:    "rule:" + r.Name() + "/v1",
		},
		Timestamp: now,
	}
}

func meanStd(samples []lifetimeSample) (mean, std float64) {
	if len(samples) == 0 {
		return 0, 0
	}
	sum := 0.0
	for _, s := range samples {
		sum += s.wallSeconds
	}
	mean = sum / float64(len(samples))
	variance := 0.0
	for _, s := range samples {
		d := s.wallSeconds - mean
		variance += d * d
	}
	variance /= float64(len(samples))
	std = math.Sqrt(variance)
	return
}

// extractTokenID parses `skill-invocation://<tenant>/<token_id>` and
// returns the token_id segment. Returns "" on shape mismatch.
func extractTokenID(ref string) string {
	const prefix = "skill-invocation://"
	if len(ref) <= len(prefix) {
		return ""
	}
	if ref[:len(prefix)] != prefix {
		return ""
	}
	rest := ref[len(prefix):]
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			return rest[i+1:]
		}
	}
	return ""
}
