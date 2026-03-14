//go:build darwin

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/menubar"
)

func TestIngestionCoordinatorLocking(t *testing.T) {
	c := newIngestionCoordinator()
	start := menubar.BulkRunState{
		RunID: "run-1",
		Total: 3,
	}
	if ok := c.TryStart("bulk_transcribe_upload", start); !ok {
		t.Fatal("first TryStart should succeed")
	}
	if ok := c.TryStart("bulk_reprocess", start); ok {
		t.Fatal("second TryStart should fail while busy")
	}

	busy, state := c.IsBusy()
	if !busy {
		t.Fatal("coordinator should be busy after start")
	}
	if state.RunID != "run-1" {
		t.Fatalf("run id = %q, want run-1", state.RunID)
	}

	c.Finish(state)
	busy, _ = c.IsBusy()
	if busy {
		t.Fatal("coordinator should be unlocked after Finish")
	}
}

func TestRunBulkSessionEventOrderAndCounters(t *testing.T) {
	var events []menubar.BulkProgressEvent
	emit := func(evt menubar.BulkProgressEvent) { events = append(events, evt) }
	handler := func(index, total int, filename, status string, emit func(menubar.BulkProgressEvent)) (string, error) {
		emit(menubar.BulkProgressEvent{
			Event: "ITEM_PHASE",
			Item:  filename,
			Index: index,
			Total: total,
			Phase: menubar.BulkPhaseTranscribe,
		})
		if filename == "b.wav" {
			return "failed", nil
		}
		return "ok", nil
	}

	summary := runBulkSession("run-2", "transcribe_upload",
		[]string{"a.wav", "b.wav"}, []string{"new", "new"}, handler, emit)

	if summary.Total != 2 || summary.Done != 2 || summary.Success != 1 || summary.Failed != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}

	if len(events) != 8 {
		t.Fatalf("unexpected event count=%d, want 8", len(events))
	}
	if events[0].Event != "RUN_START" {
		t.Fatalf("event[0]=%s, want RUN_START", events[0].Event)
	}
	if events[1].Event != "ITEM_START" || events[2].Event != "ITEM_PHASE" || events[3].Event != "ITEM_DONE" {
		t.Fatalf("first item event order mismatch: %#v %#v %#v", events[1].Event, events[2].Event, events[3].Event)
	}
	if events[4].Event != "ITEM_START" || events[5].Event != "ITEM_PHASE" || events[6].Event != "ITEM_DONE" {
		t.Fatalf("second item event order mismatch: %#v %#v %#v", events[4].Event, events[5].Event, events[6].Event)
	}
	if events[7].Event != "RUN_DONE" {
		t.Fatalf("event[7]=%s, want RUN_DONE", events[7].Event)
	}
	if events[6].Outcome != "failed" {
		t.Fatalf("second item outcome=%q, want failed", events[6].Outcome)
	}
}

func TestFormatBulkLogIncludesMarkersAndRunID(t *testing.T) {
	tests := []menubar.BulkProgressEvent{
		{Event: "RUN_START", RunID: "run-3", Action: "transcribe_upload", Total: 3},
		{Event: "ITEM_START", RunID: "run-3", Action: "transcribe_upload", Index: 1, Total: 3, Item: "a.wav"},
		{Event: "ITEM_PHASE", RunID: "run-3", Action: "transcribe_upload", Index: 1, Total: 3, Item: "a.wav", Phase: menubar.BulkPhaseTranscribe},
		{Event: "ITEM_DONE", RunID: "run-3", Action: "transcribe_upload", Index: 1, Total: 3, Item: "a.wav", Outcome: "ok", Elapsed: 2 * time.Second},
		{Event: "RUN_DONE", RunID: "run-3", Action: "transcribe_upload", Done: 3, Success: 3, Failed: 0, Elapsed: 4 * time.Second},
	}
	for _, tc := range tests {
		line := formatBulkLog(tc)
		if !strings.Contains(line, "[bulk][") {
			t.Fatalf("line missing marker: %q", line)
		}
		if !strings.Contains(line, "run_id=run-3") {
			t.Fatalf("line missing run_id: %q", line)
		}
	}
}
