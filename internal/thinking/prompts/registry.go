// Package prompts resolves prompt IDs to prompt bodies.
//
// D1: prompts live in the Flask-hosted registry. The engine reads
// over HTTP with ETag-based revalidation and a 5-minute TTL local
// cache. No local SQLite replica.
//
// Week 1: we ship an in-memory stub registry with one prompt per
// strategy so processor handlers can reference a real prompt_id in
// traces. The HTTP client slot is prepared (interface shape +
// NewHTTPRegistry stub) so swapping to real network fetch is a
// one-file change in Week 2+.
//
// Invariant (SPEC-0167 AP-06): no processor hardcodes a prompt
// string. Every R/I/A step goes through this package even in stub
// form.
package prompts

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Prompt is the minimum Week 1 record.
type Prompt struct {
	ID      string
	Version int
	Body    string
	Model   string
}

// Registry is the prompt lookup surface. Both the in-memory stub
// and the forthcoming HTTP client implement it.
type Registry interface {
	Get(ctx context.Context, id string) (Prompt, error)
}

// ----- In-memory stub -----

type memRegistry struct {
	mu      sync.RWMutex
	prompts map[string]Prompt
}

// NewMemoryRegistry returns a registry seeded with one prompt per
// processor strategy. These are *stubs* — they describe the intent
// of the prompt, they are not production prompts.
func NewMemoryRegistry() Registry {
	r := &memRegistry{prompts: map[string]Prompt{}}
	seed := []Prompt{
		// R-proc strategies (Week 1: compare, classify)
		{ID: "thinking.r.compare.stub", Version: 1, Model: "stub", Body: "Compare the given thoughts pairwise and list points of agreement and disagreement."},
		{ID: "thinking.r.classify.stub", Version: 1, Model: "stub", Body: "Classify each thought into {fact, observation, question, idea, signal}."},
		// I-proc strategies (Week 1: pattern, contradiction)
		{ID: "thinking.i.pattern.stub", Version: 1, Model: "stub", Body: "From the input reflections, identify recurring patterns and name them."},
		{ID: "thinking.i.contradiction.stub", Version: 1, Model: "stub", Body: "From the input reflections, surface contradictions and frame each as an open question."},
		// A-proc strategies (Week 1: report, summary)
		{ID: "thinking.a.report.stub", Version: 1, Model: "stub", Body: "Render the insights as a short markdown report for a human audience."},
		{ID: "thinking.a.summary.stub", Version: 1, Model: "stub", Body: "Produce a one-paragraph summary of the insights."},
		// C-proc strategies (Week 1: summarize)
		{ID: "thinking.c.summarize.stub", Version: 1, Model: "stub", Body: "Compile a periodic rollup across the supplied artifacts."},
	}
	for _, p := range seed {
		r.prompts[p.ID] = p
	}
	return r
}

func (r *memRegistry) Get(ctx context.Context, id string) (Prompt, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.prompts[id]
	if !ok {
		return Prompt{}, fmt.Errorf("prompts: unknown id %q (registry in-memory stub)", id)
	}
	return p, nil
}

// ----- HTTP registry (Phase 2 placeholder) -----

// HTTPConfig configures the Flask-backed registry client.
type HTTPConfig struct {
	BaseURL string
	Token   string
	TTL     time.Duration
}

// NewHTTPRegistry will return an ETag-cached HTTP Registry client.
// Week 1 stub; real implementation lands Week 2 per PLAN-0167.
// Kept as a function rather than a struct so swapping drivers in
// main.go is a one-line change.
func NewHTTPRegistry(cfg HTTPConfig) (Registry, error) {
	_ = cfg
	return nil, fmt.Errorf("prompts: HTTP registry not yet implemented (Week 2)")
}

// DefaultStrategyPromptID returns the stub prompt id the Week 1
// processors use for a given (layer, strategy) pair. Keeps all
// prompt ids in one place so the seed list above is the single
// source of truth.
func DefaultStrategyPromptID(layer, strategy string) string {
	return fmt.Sprintf("thinking.%s.%s.stub", layer, strategy)
}
