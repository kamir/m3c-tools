// Package bulkprogress is the platform-neutral progress vocabulary for the audio
// bulk import/upload pipeline. The pipeline runs on every OS, so it reports
// progress through these types instead of importing the darwin-only pkg/menubar
// (SPEC-0251 §5 multi-platform parity). pkg/menubar aliases these types, so its
// public API (BulkProgressEvent, BulkPhase*) is unchanged while the underlying
// types become portable.
package bulkprogress

import "time"

// Phase is the current step for a bulk-operation item.
type Phase string

const (
	PhaseQueued      Phase = "queued"
	PhaseImport      Phase = "import"
	PhaseTranscribe  Phase = "transcribe"
	PhaseUpload      Phase = "upload"
	PhaseDone        Phase = "done"
	PhaseFailed      Phase = "failed"
	PhaseReprocess   Phase = "reprocess"
	PhaseUnavailable Phase = "unavailable"
)

// Event is emitted by the bulk runner to synchronize logs + UI. Field layout
// mirrors the former menubar.BulkProgressEvent exactly (now an alias of this).
type Event struct {
	RunID       string
	Action      string
	Event       string // RUN_START | ITEM_START | ITEM_PHASE | ITEM_DONE | RUN_DONE
	Item        string
	Index       int // 1-based item index when relevant
	Total       int
	Phase       Phase
	Outcome     string // ok | failed | skipped
	Done        int
	Success     int
	Failed      int
	Elapsed     time.Duration
	Error       string
	CurrentFile string
}
