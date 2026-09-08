package main

import (
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/plaud"
)

// BUG-0222: an empty Plaud transcript means two different things. On a fresh
// recording it means "the cloud ASR is not finished"; only after a grace period
// does it mean "there will never be a transcript". The hourly timer reliably hit
// the first case (a recording ending at :19:38 was read at :20:00) and the
// recording was then marked synced forever, so the real text never arrived.
//
// The window is measured from the END of the recording, not its start.

// devRec builds a recording that ENDED `endedAgo` before now.
func devRec(endedAgo, dur time.Duration) plaud.DevRecording {
	start := time.Now().Add(-endedAgo - dur)
	return plaud.DevRecording{
		ID:       "rec",
		StartAt:  start.UTC().Format("2006-01-02T15:04:05"),
		Duration: dur.Milliseconds(),
	}
}

func TestTranscriptPendingWithinGrace(t *testing.T) {
	// The exact shape of the reported incident: 6m23s recording, read 22s after
	// it stopped. It must be deferred, not queued.
	r := devRec(22*time.Second, 6*time.Minute+23*time.Second)
	pending, wait := plaudTranscriptPending(r, 30*time.Minute)
	if !pending {
		t.Fatalf("a recording that stopped 22s ago must be deferred, got pending=false")
	}
	if wait <= 0 || wait > 30*time.Minute {
		t.Fatalf("wait %v is outside the grace window", wait)
	}
}

func TestTranscriptNotPendingAfterGrace(t *testing.T) {
	// Past the grace, "no transcript" is a real answer: the old behavior
	// (server-side queue / local whisper) must still take over.
	r := devRec(45*time.Minute, 2*time.Minute)
	if pending, _ := plaudTranscriptPending(r, 30*time.Minute); pending {
		t.Fatalf("a recording that stopped 45min ago must NOT be deferred")
	}
}

func TestTranscriptGraceMeasuresFromEndNotStart(t *testing.T) {
	// A 40-minute recording STARTED 45 minutes ago stopped only 5 minutes ago.
	// Measuring from start would wave it through with an unfinished transcript.
	r := devRec(5*time.Minute, 40*time.Minute)
	if pending, _ := plaudTranscriptPending(r, 30*time.Minute); !pending {
		t.Fatalf("grace must be measured from the recording's END, not its start")
	}
}

func TestTranscriptGraceZeroDisablesTheWait(t *testing.T) {
	r := devRec(1*time.Second, time.Minute)
	if pending, _ := plaudTranscriptPending(r, 0); pending {
		t.Fatalf("grace 0 must restore the old, immediate behavior")
	}
}

func TestTranscriptUnreadableTimestampNeverStalls(t *testing.T) {
	// A timestamp we cannot parse must not park a recording forever: fail open.
	r := plaud.DevRecording{ID: "rec", StartAt: "not-a-time", Duration: 1000}
	if pending, _ := plaudTranscriptPending(r, 30*time.Minute); pending {
		t.Fatalf("an unparseable start_at must not defer the recording")
	}
}

func TestTranscriptGraceEnvOverride(t *testing.T) {
	if got := plaudTranscriptGrace(); got != 30*time.Minute {
		t.Fatalf("default grace = %v, want 30m", got)
	}
	t.Setenv("PLAUD_TRANSCRIPT_GRACE_MIN", "5")
	if got := plaudTranscriptGrace(); got != 5*time.Minute {
		t.Fatalf("PLAUD_TRANSCRIPT_GRACE_MIN=5 → %v, want 5m", got)
	}
	t.Setenv("PLAUD_TRANSCRIPT_GRACE_MIN", "0")
	if got := plaudTranscriptGrace(); got != 0 {
		t.Fatalf("PLAUD_TRANSCRIPT_GRACE_MIN=0 → %v, want 0", got)
	}
	// A malformed value must not silently disable the guard.
	t.Setenv("PLAUD_TRANSCRIPT_GRACE_MIN", "später")
	if got := plaudTranscriptGrace(); got != 30*time.Minute {
		t.Fatalf("a malformed grace value must fall back to the default, got %v", got)
	}
}

// --- the shared decision both the preview and the real run consult -----------
//
// These cover the WIRING, not just the clock. The dry run and the real sync
// each decided for themselves at first, and they disagreed: the preview
// reported "WOULD sync" for precisely the recordings the real run defers.

func TestDeferDecisionFreshRecordingWithoutTranscript(t *testing.T) {
	r := devRec(22*time.Second, 6*time.Minute+23*time.Second)
	got, wait := plaudDeferForTranscript(r, "", false, 30*time.Minute)
	if !got {
		t.Fatalf("a fresh recording with no Plaud transcript must be deferred")
	}
	if wait <= 0 {
		t.Fatalf("a deferred recording must report how long to wait, got %v", wait)
	}
}

func TestDeferDecisionNotWhenPlaudHasText(t *testing.T) {
	r := devRec(1*time.Second, time.Minute)
	if got, _ := plaudDeferForTranscript(r, "Mirko Kämpf: das Problem …", false, 30*time.Minute); got {
		t.Fatalf("a recording WITH a Plaud transcript must never be deferred")
	}
}

func TestDeferDecisionWhitespaceOnlyTranscriptCountsAsEmpty(t *testing.T) {
	r := devRec(1*time.Second, time.Minute)
	if got, _ := plaudDeferForTranscript(r, "  \n\t ", false, 30*time.Minute); !got {
		t.Fatalf("a blank transcript is no transcript and must be deferred")
	}
}

func TestDeferDecisionForceMeansNow(t *testing.T) {
	r := devRec(1*time.Second, time.Minute)
	if got, _ := plaudDeferForTranscript(r, "", true, 30*time.Minute); got {
		t.Fatalf("--force must bypass the wait: an explicit selection means now")
	}
}

func TestDeferDecisionOldRecordingFallsThroughToTheQueue(t *testing.T) {
	// Past the grace, an empty transcript is a real answer and the old
	// behavior (server-side queue / local whisper) must still take over.
	r := devRec(2*time.Hour, time.Minute)
	if got, _ := plaudDeferForTranscript(r, "", false, 30*time.Minute); got {
		t.Fatalf("past the grace the recording must proceed, not stall forever")
	}
}
