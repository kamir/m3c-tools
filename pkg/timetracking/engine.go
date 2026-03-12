package timetracking

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
)

// DefaultContextTimeout is the default auto-expiry duration for active contexts.
const DefaultContextTimeout = 2 * time.Hour

// ContextTimeout returns the configured context timeout from M3C_CONTEXT_TIMEOUT env var
// (in minutes), falling back to DefaultContextTimeout.
func ContextTimeout() time.Duration {
	if v := os.Getenv("M3C_CONTEXT_TIMEOUT"); v != "" {
		if mins, err := strconv.Atoi(v); err == nil && mins > 0 {
			return time.Duration(mins) * time.Minute
		}
	}
	return DefaultContextTimeout
}

// NotifyFunc is called to show user notifications.
type NotifyFunc func(title, message string)

// Engine manages project context activations, timers, and event recording.
type Engine struct {
	mu      sync.Mutex
	store   *Store
	timeout time.Duration
	notify  NotifyFunc

	// Per-project expiry timers and warning timers.
	timers  map[string]*time.Timer
	warning map[string]*time.Timer
}

// NewEngine creates a new time tracking engine backed by the given store.
func NewEngine(store *Store, notify NotifyFunc) *Engine {
	return &Engine{
		store:   store,
		timeout: ContextTimeout(),
		notify:  notify,
		timers:  make(map[string]*time.Timer),
		warning: make(map[string]*time.Timer),
	}
}

// Activate starts time tracking for a project. If already active, this is a no-op.
func (e *Engine) Activate(projectID, projectName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Check if already active.
	if _, ok := e.timers[projectID]; ok {
		return nil // already active
	}

	now := time.Now().UTC()
	expiresAt := now.Add(e.timeout)

	// Record activation event.
	event := Event{
		EventID:     uuid.New().String(),
		ProjectID:   projectID,
		ProjectName: projectName,
		EventType:   "activate",
		Timestamp:   now,
		Trigger:     "user",
	}
	if err := e.store.InsertEvent(event); err != nil {
		return fmt.Errorf("record activation: %w", err)
	}

	// Track active context for crash recovery.
	if err := e.store.SetActiveContext(ActiveContext{
		ProjectID:   projectID,
		ProjectName: projectName,
		ActivatedAt: now,
		ExpiresAt:   expiresAt,
	}); err != nil {
		log.Printf("[timetracking] failed to set active context: %v", err)
	}

	// Start auto-expiry timer.
	e.timers[projectID] = time.AfterFunc(e.timeout, func() {
		e.autoExpire(projectID, projectName)
	})

	// Start pre-expiry warning (5 min before expiry).
	warningDur := e.timeout - 5*time.Minute
	if warningDur > 0 {
		e.warning[projectID] = time.AfterFunc(warningDur, func() {
			if e.notify != nil {
				e.notify("Time Tracker", fmt.Sprintf("%s will deactivate in 5 minutes", projectName))
			}
		})
	}

	log.Printf("[timetracking] ACTIVATE project=%s name=%q expires=%s", projectID, projectName, expiresAt.Format(time.RFC3339))
	return nil
}

// Deactivate stops time tracking for a project.
func (e *Engine) Deactivate(projectID, trigger string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.deactivateLocked(projectID, trigger)
}

func (e *Engine) deactivateLocked(projectID, trigger string) error {
	// Cancel timers.
	if t, ok := e.timers[projectID]; ok {
		t.Stop()
		delete(e.timers, projectID)
	}
	if t, ok := e.warning[projectID]; ok {
		t.Stop()
		delete(e.warning, projectID)
	}

	// Get activation info for duration calculation.
	contexts, err := e.store.ListActiveContexts()
	if err != nil {
		return fmt.Errorf("list active contexts: %w", err)
	}

	var ctx *ActiveContext
	for _, c := range contexts {
		if c.ProjectID == projectID {
			ctx = &c
			break
		}
	}
	if ctx == nil {
		return nil // not active, nothing to deactivate
	}

	now := time.Now().UTC()
	durSec := int(now.Sub(ctx.ActivatedAt).Seconds())

	// Record deactivation event.
	event := Event{
		EventID:     uuid.New().String(),
		ProjectID:   projectID,
		ProjectName: ctx.ProjectName,
		EventType:   "deactivate",
		Timestamp:   now,
		Trigger:     trigger,
		DurationSec: &durSec,
	}
	if err := e.store.InsertEvent(event); err != nil {
		return fmt.Errorf("record deactivation: %w", err)
	}

	// Remove from active contexts.
	if err := e.store.RemoveActiveContext(projectID); err != nil {
		log.Printf("[timetracking] failed to remove active context: %v", err)
	}

	log.Printf("[timetracking] DEACTIVATE project=%s trigger=%s duration=%ds", projectID, trigger, durSec)
	return nil
}

func (e *Engine) autoExpire(projectID, projectName string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.deactivateLocked(projectID, "auto_expiry"); err != nil {
		log.Printf("[timetracking] auto-expire failed project=%s: %v", projectID, err)
	}
	if e.notify != nil {
		e.notify("Time Tracker", fmt.Sprintf("%s deactivated (2h timeout)", projectName))
	}
}

// IsActive returns true if the given project is currently active.
func (e *Engine) IsActive(projectID string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.timers[projectID]
	return ok
}

// ActiveProjects returns the IDs of all currently active projects.
func (e *Engine) ActiveProjects() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var ids []string
	for id := range e.timers {
		ids = append(ids, id)
	}
	return ids
}

// Toggle activates an inactive project or deactivates an active one.
func (e *Engine) Toggle(projectID, projectName string) error {
	if e.IsActive(projectID) {
		return e.Deactivate(projectID, "user")
	}
	return e.Activate(projectID, projectName)
}

// ShutdownAll deactivates all active projects with trigger "app_quit".
func (e *Engine) ShutdownAll() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for projectID := range e.timers {
		if err := e.deactivateLocked(projectID, "app_quit"); err != nil {
			log.Printf("[timetracking] shutdown deactivate failed project=%s: %v", projectID, err)
		}
	}
}

// RecoverOrphanedContexts handles active contexts left from a previous session.
// If a context is still within its timeout window, it is restored (re-activated
// with the remaining time). If the timeout has elapsed, a deactivation event is
// recorded capped at the expiry time. See BUG-0008.
func (e *Engine) RecoverOrphanedContexts() error {
	contexts, err := e.store.ListActiveContexts()
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, ctx := range contexts {
		now := time.Now().UTC()

		if now.Before(ctx.ExpiresAt.UTC()) {
			// Still within timeout — restore the project as active.
			remaining := ctx.ExpiresAt.UTC().Sub(now)
			projectID := ctx.ProjectID
			projectName := ctx.ProjectName

			e.timers[projectID] = time.AfterFunc(remaining, func() {
				e.autoExpire(projectID, projectName)
			})

			// Restore pre-expiry warning if >5 min remain.
			if remaining > 5*time.Minute {
				e.warning[projectID] = time.AfterFunc(remaining-5*time.Minute, func() {
					if e.notify != nil {
						e.notify("Time Tracker", fmt.Sprintf("%s will deactivate in 5 minutes", projectName))
					}
				})
			}

			log.Printf("[timetracking] RESTORE project=%s name=%q remaining=%s", projectID, projectName, remaining.Round(time.Second))
			continue
		}

		// Expired — deactivate with duration capped at expiry time.
		deactivateAt := ctx.ExpiresAt.UTC()
		durSec := int(deactivateAt.Sub(ctx.ActivatedAt).Seconds())

		event := Event{
			EventID:     uuid.New().String(),
			ProjectID:   ctx.ProjectID,
			ProjectName: ctx.ProjectName,
			EventType:   "deactivate",
			Timestamp:   deactivateAt,
			Trigger:     "crash_recovery",
			DurationSec: &durSec,
		}
		if err := e.store.InsertEvent(event); err != nil {
			log.Printf("[timetracking] crash recovery failed project=%s: %v", ctx.ProjectID, err)
			continue
		}
		if err := e.store.RemoveActiveContext(ctx.ProjectID); err != nil {
			log.Printf("[timetracking] crash recovery cleanup failed project=%s: %v", ctx.ProjectID, err)
		}
		log.Printf("[timetracking] CRASH_RECOVERY project=%s duration=%ds", ctx.ProjectID, durSec)
	}
	return nil
}
