package store

import (
	"testing"

	"github.com/kamir/m3c-tools/internal/thinking/schema"
)

func mkStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestInsertAndGetProcess(t *testing.T) {
	s := mkStore(t)
	spec := schema.ProcessSpec{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: "p-1",
		Intent:    "x",
		Mode:      schema.ModeLinear,
		Depth:     1,
		Steps:     []schema.Step{{Layer: schema.LayerR, Strategy: "compare"}},
	}
	if err := s.InsertProcess(spec); err != nil {
		t.Fatal(err)
	}
	r, err := s.GetProcess("p-1")
	if err != nil {
		t.Fatal(err)
	}
	if r.State != StatePending {
		t.Errorf("state = %s, want pending", r.State)
	}
}

func TestUpdateStateAndArtifacts(t *testing.T) {
	s := mkStore(t)
	spec := schema.ProcessSpec{
		SchemaVer: schema.CurrentSchemaVer, ProcessID: "p-2", Intent: "x",
		Mode: schema.ModeLinear, Depth: 1,
		Steps: []schema.Step{{Layer: schema.LayerA, Strategy: "report"}},
	}
	if err := s.InsertProcess(spec); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateState("p-2", StateRunning, "A:report"); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendArtifact("p-2", "a-1"); err != nil {
		t.Fatal(err)
	}
	r, err := s.GetProcess("p-2")
	if err != nil {
		t.Fatal(err)
	}
	if r.State != StateRunning || r.CurrentStep != "A:report" {
		t.Errorf("state/current_step not updated: %+v", r)
	}
	if len(r.ArtifactIDs) != 1 || r.ArtifactIDs[0] != "a-1" {
		t.Errorf("artifact ids: %+v", r.ArtifactIDs)
	}
}

func TestBudgetCountersAccumulate(t *testing.T) {
	s := mkStore(t)
	if err := s.AddBudgetSpend(100, 0.01); err != nil {
		t.Fatal(err)
	}
	if err := s.AddBudgetSpend(50, 0.02); err != nil {
		t.Fatal(err)
	}
	tokens, cost, err := s.GetBudgetSpend()
	if err != nil {
		t.Fatal(err)
	}
	if tokens != 150 {
		t.Errorf("tokens = %d, want 150", tokens)
	}
	if cost < 0.029 || cost > 0.031 {
		t.Errorf("cost = %f, want ~0.03", cost)
	}
}
