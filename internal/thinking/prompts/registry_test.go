package prompts

import (
	"context"
	"testing"
)

func TestSeededPrompts(t *testing.T) {
	reg := NewMemoryRegistry()
	ctx := context.Background()
	wants := []string{
		"thinking.r.compare.stub",
		"thinking.r.classify.stub",
		"thinking.i.pattern.stub",
		"thinking.i.contradiction.stub",
		"thinking.a.report.stub",
		"thinking.a.summary.stub",
		"thinking.c.summarize.stub",
	}
	for _, id := range wants {
		p, err := reg.Get(ctx, id)
		if err != nil {
			t.Errorf("Get(%s) error: %v", id, err)
			continue
		}
		if p.ID != id {
			t.Errorf("Get(%s).ID = %s", id, p.ID)
		}
		if p.Body == "" {
			t.Errorf("Get(%s).Body empty", id)
		}
	}
}

func TestUnknownPromptError(t *testing.T) {
	reg := NewMemoryRegistry()
	if _, err := reg.Get(context.Background(), "does.not.exist"); err == nil {
		t.Errorf("expected error")
	}
}

func TestDefaultStrategyPromptIDMatchesSeed(t *testing.T) {
	reg := NewMemoryRegistry()
	for _, tc := range []struct{ layer, strat string }{
		{"r", "compare"}, {"r", "classify"},
		{"i", "pattern"}, {"i", "contradiction"},
		{"a", "report"}, {"a", "summary"},
		{"c", "summarize"},
	} {
		id := DefaultStrategyPromptID(tc.layer, tc.strat)
		if _, err := reg.Get(context.Background(), id); err != nil {
			t.Errorf("default id %q not in registry: %v", id, err)
		}
	}
}
