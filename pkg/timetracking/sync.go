package timetracking

import (
	"context"
	"log"
	"time"
)

// Syncer periodically syncs unsynced events to the PLM API.
type Syncer struct {
	store    *Store
	client   *PLMClient
	interval time.Duration
	cancel   context.CancelFunc
	done     chan struct{}
}

// NewSyncer creates a background syncer that pushes unsynced events to ER1.
func NewSyncer(store *Store, client *PLMClient, interval time.Duration) *Syncer {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Syncer{
		store:    store,
		client:   client,
		interval: interval,
		done:     make(chan struct{}),
	}
}

// Start begins the background sync loop.
func (s *Syncer) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	go func() {
		defer close(s.done)

		// Sync immediately on start.
		s.syncOnce()

		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				// Final sync before exit.
				s.syncOnce()
				return
			case <-ticker.C:
				s.syncOnce()
			}
		}
	}()
}

// Stop gracefully stops the sync loop and waits for completion.
func (s *Syncer) Stop(timeout time.Duration) {
	if s.cancel != nil {
		s.cancel()
	}
	select {
	case <-s.done:
	case <-time.After(timeout):
		log.Printf("[sync] stop timed out after %s", timeout)
	}
}

func (s *Syncer) syncOnce() {
	if s.client == nil {
		return
	}

	events, err := s.store.UnsyncedEvents()
	if err != nil {
		log.Printf("[sync] list unsynced: %v", err)
		return
	}
	if len(events) == 0 {
		return
	}

	log.Printf("[sync] %d unsynced events to push", len(events))

	synced := 0
	for _, e := range events {
		if err := s.client.PostTimeEvent(e); err != nil {
			log.Printf("[sync] failed event=%s: %v", e.EventID, err)
			continue // will retry next cycle
		}
		if err := s.store.MarkSynced(e.EventID); err != nil {
			log.Printf("[sync] mark synced failed event=%s: %v", e.EventID, err)
		}
		synced++
	}

	if synced > 0 {
		log.Printf("[sync] synced %d/%d events", synced, len(events))
	}
}

// SyncOnce triggers an immediate sync (for use in tests or manual triggers).
func (s *Syncer) SyncOnce() {
	s.syncOnce()
}
