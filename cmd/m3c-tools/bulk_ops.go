//go:build darwin

package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kamir/m3c-tools/pkg/menubar"
)

type ingestionCoordinator struct {
	mu    sync.Mutex
	busy  bool
	state menubar.BulkRunState
}

func newIngestionCoordinator() *ingestionCoordinator {
	return &ingestionCoordinator{}
}

func (c *ingestionCoordinator) TryStart(opType string, meta menubar.BulkRunState) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.busy {
		return false
	}
	meta.Active = true
	meta.Action = strings.TrimSpace(opType)
	if meta.StartedAt.IsZero() {
		meta.StartedAt = time.Now()
	}
	c.busy = true
	c.state = meta
	return true
}

func (c *ingestionCoordinator) Update(state menubar.BulkRunState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.busy {
		return
	}
	c.state = state
}

func (c *ingestionCoordinator) Finish(final menubar.BulkRunState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	final.Active = false
	c.state = final
	c.busy = false
}

func (c *ingestionCoordinator) IsBusy() (bool, menubar.BulkRunState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.busy, c.state
}

type bulkSessionSummary struct {
	Total   int
	Done    int
	Success int
	Failed  int
}

type bulkItemHandler func(index, total int, filename, status string, emit func(menubar.BulkProgressEvent)) (string, error)

func runBulkSession(runID, action string, filenames, statuses []string, handler bulkItemHandler, emit func(menubar.BulkProgressEvent)) bulkSessionSummary {
	total := len(filenames)
	summary := bulkSessionSummary{Total: total}
	start := time.Now()

	emit(menubar.BulkProgressEvent{
		RunID:   runID,
		Action:  action,
		Event:   "RUN_START",
		Total:   total,
		Phase:   menubar.BulkPhaseQueued,
		Elapsed: 0,
	})

	for i, name := range filenames {
		status := ""
		if i < len(statuses) {
			status = statuses[i]
		}

		emit(menubar.BulkProgressEvent{
			RunID:       runID,
			Action:      action,
			Event:       "ITEM_START",
			Item:        name,
			Index:       i + 1,
			Total:       total,
			CurrentFile: name,
			Phase:       menubar.BulkPhaseQueued,
			Elapsed:     time.Since(start),
		})

		outcome, err := handler(i+1, total, name, status, emit)
		if strings.TrimSpace(outcome) == "" {
			outcome = "ok"
		}
		summary.Done++
		if err != nil || outcome == "failed" {
			summary.Failed++
			if err == nil {
				err = fmt.Errorf("failed")
			}
		} else {
			summary.Success++
		}

		errText := ""
		if err != nil {
			errText = err.Error()
		}
		emit(menubar.BulkProgressEvent{
			RunID:       runID,
			Action:      action,
			Event:       "ITEM_DONE",
			Item:        name,
			Index:       i + 1,
			Total:       total,
			Outcome:     outcome,
			Error:       errText,
			Done:        summary.Done,
			Success:     summary.Success,
			Failed:      summary.Failed,
			CurrentFile: name,
			Phase:       itemDonePhase(outcome, err),
			Elapsed:     time.Since(start),
		})
	}

	emit(menubar.BulkProgressEvent{
		RunID:   runID,
		Action:  action,
		Event:   "RUN_DONE",
		Total:   total,
		Done:    summary.Done,
		Success: summary.Success,
		Failed:  summary.Failed,
		Elapsed: time.Since(start),
	})
	return summary
}

func itemDonePhase(outcome string, err error) menubar.BulkRunPhase {
	if err != nil || outcome == "failed" {
		return menubar.BulkPhaseFailed
	}
	return menubar.BulkPhaseDone
}

func shortErrCode(errText string) string {
	low := strings.ToLower(strings.TrimSpace(errText))
	switch {
	case low == "":
		return "none"
	case strings.Contains(low, "timeout"):
		return "timeout"
	case strings.Contains(low, "cancel"):
		return "canceled"
	case strings.Contains(low, "whisper"):
		return "whisper"
	case strings.Contains(low, "upload"):
		return "upload"
	case strings.Contains(low, "duplicate"):
		return "duplicate"
	case strings.Contains(low, "not found"):
		return "not_found"
	default:
		return "error"
	}
}

func baseName(pathOrName string) string {
	if strings.TrimSpace(pathOrName) == "" {
		return ""
	}
	return filepath.Base(pathOrName)
}

func actionBlockedDuringBulk(action menubar.ActionType) bool {
	switch action {
	case menubar.ActionFetchTranscript,
		menubar.ActionCaptureScreenshot,
		menubar.ActionQuickImpulse,
		menubar.ActionRecordImpression,
		menubar.ActionBatchImport:
		return true
	default:
		return false
	}
}

func formatBulkLog(evt menubar.BulkProgressEvent) string {
	switch evt.Event {
	case "RUN_START":
		return fmt.Sprintf("[bulk][RUN_START] run_id=%s action=%s total=%d", evt.RunID, evt.Action, evt.Total)
	case "ITEM_START":
		return fmt.Sprintf("[bulk][ITEM_START] run_id=%s action=%s idx=%d/%d file=%q",
			evt.RunID, evt.Action, evt.Index, evt.Total, evt.Item)
	case "ITEM_PHASE":
		return fmt.Sprintf("[bulk][PHASE] run_id=%s action=%s idx=%d/%d file=%q phase=%s",
			evt.RunID, evt.Action, evt.Index, evt.Total, evt.Item, phaseLogToken(evt.Phase))
	case "ITEM_DONE":
		return fmt.Sprintf("[bulk][ITEM_DONE] run_id=%s action=%s idx=%d/%d file=%q outcome=%s err_code=%s elapsed=%s",
			evt.RunID, evt.Action, evt.Index, evt.Total, evt.Item, evt.Outcome, shortErrCode(evt.Error), evt.Elapsed.Round(time.Millisecond))
	case "RUN_DONE":
		return fmt.Sprintf("[bulk][RUN_DONE] run_id=%s action=%s done=%d success=%d failed=%d elapsed=%s",
			evt.RunID, evt.Action, evt.Done, evt.Success, evt.Failed, evt.Elapsed.Round(time.Millisecond))
	default:
		return fmt.Sprintf("[bulk][%s] run_id=%s action=%s", evt.Event, evt.RunID, evt.Action)
	}
}
