// commands_shared.go — portable m3c-tools subcommands (SPEC-0251 §5 multi-platform parity).
//
// This file has NO build tags, so it compiles on darwin AND non-darwin. Every
// command body here uses only portable packages (no pkg/menubar, pkg/recorder,
// pkg/screenshot), so these subcommands are available on Linux and Windows too —
// not just macOS. Genuinely darwin-only commands (menubar/record/devices/
// screenshot) stay in main.go behind //go:build darwin.
//
// Migrated verbatim from main.go (was darwin-only); main_other.go's dispatch now
// routes to them.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/tracking"
)

// plural is a tiny helper that mirrors setup.plural; kept inline so we don't
// export it from pkg/setup.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func cmdRetry(args []string) {
	interval := 30
	maxRetries := 10
	queuePath := er1.DefaultQueuePath()

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--interval":
			if i+1 < len(args) {
				if v, err := strconv.Atoi(args[i+1]); err == nil {
					interval = v
				}
				i++
			}
		case "--max-retries":
			if i+1 < len(args) {
				if v, err := strconv.Atoi(args[i+1]); err == nil {
					maxRetries = v
				}
				i++
			}
		case "--queue":
			if i+1 < len(args) {
				queuePath = args[i+1]
				i++
			}
		}
	}

	fmt.Printf("Starting ER1 retry loop (interval=%ds, max-retries=%d, queue=%s)\n", interval, maxRetries, queuePath)

	cfg := er1.LoadConfig()
	q := er1.NewQueue(queuePath)

	fmt.Printf("  ER1: %s\n", cfg.Summary())
	fmt.Printf("  Queue entries: %d\n", q.Len())
	fmt.Println("  Press Ctrl+C to stop.")

	runner := er1.NewRetryRunner(q, func(entry er1.QueueEntry) error {
		payload := &er1.UploadPayload{
			TranscriptFilename: entry.TranscriptPath,
			AudioFilename:      entry.AudioPath,
			ImageFilename:      entry.ImagePath,
			Tags:               entry.Tags,
		}
		if entry.TranscriptPath != "" {
			if data, readErr := os.ReadFile(entry.TranscriptPath); readErr == nil {
				payload.TranscriptData = data
			} else {
				payload.TranscriptData = []byte(fmt.Sprintf("Retry upload for %s", entry.ID))
			}
		} else {
			payload.TranscriptData = []byte(fmt.Sprintf("Retry upload for %s", entry.ID))
		}
		if entry.AudioPath != "" {
			if data, readErr := os.ReadFile(entry.AudioPath); readErr == nil {
				payload.AudioData = data
			}
		}
		if entry.ImagePath != "" {
			if data, readErr := os.ReadFile(entry.ImagePath); readErr == nil {
				payload.ImageData = data
			}
		}
		_, uploadErr := er1.Upload(cfg, payload)
		return uploadErr
	}, maxRetries)

	runner.Backoff = er1.DefaultBackoff(
		time.Duration(interval)*time.Second,
		5*time.Minute,
	)

	runner.OnRetry = func(entry er1.QueueEntry, retryErr error, removed bool) {
		if retryErr == nil {
			fmt.Printf("[retry] SUCCESS: %s (removed from queue)\n", entry.ID)
		} else if removed {
			fmt.Printf("[retry] DROPPED: %s — max retries exceeded\n", entry.ID)
		} else {
			fmt.Printf("[retry] FAILED: %s — attempt %d: %v\n", entry.ID, entry.RetryCount+1, retryErr)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down retry loop...")
		cancel()
	}()

	if loopErr := runner.Run(ctx, time.Duration(interval)*time.Second); loopErr != nil && loopErr != context.Canceled {
		fmt.Fprintf(os.Stderr, "Retry loop error: %v\n", loopErr)
		os.Exit(1)
	}
	fmt.Println("Retry loop stopped.")
}

// -- schedule command --

func defaultExportsDBPath() string {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".m3c-tools")
	os.MkdirAll(dir, 0700)
	return filepath.Join(dir, "exports.db")
}

func cmdSchedule(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: m3c-tools schedule <entry_id> --transcript <path> [--audio <path>] [--image <path>] [--tags <tags>] [--max-attempts <n>] [--db <path>]")
		os.Exit(1)
	}
	entryID := args[0]
	transcriptPath := ""
	audioPath := ""
	imagePath := ""
	tags := ""
	maxAttempts := 10
	dbPath := defaultExportsDBPath()

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--transcript":
			if i+1 < len(args) {
				transcriptPath = args[i+1]
				i++
			}
		case "--audio":
			if i+1 < len(args) {
				audioPath = args[i+1]
				i++
			}
		case "--image":
			if i+1 < len(args) {
				imagePath = args[i+1]
				i++
			}
		case "--tags":
			if i+1 < len(args) {
				tags = args[i+1]
				i++
			}
		case "--max-attempts":
			if i+1 < len(args) {
				if v, err := strconv.Atoi(args[i+1]); err == nil {
					maxAttempts = v
				}
				i++
			}
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		}
	}

	if transcriptPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --transcript is required")
		os.Exit(1)
	}

	db, err := tracking.OpenRetryQueueDB(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening DB: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	entry, err := db.Insert(entryID, transcriptPath, audioPath, imagePath, tags, maxAttempts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scheduling entry: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Scheduled retry entry:\n")
	fmt.Printf("  entry_id:     %s\n", entry.EntryID)
	fmt.Printf("  transcript:   %s\n", entry.TranscriptPath)
	if entry.AudioPath != "" {
		fmt.Printf("  audio:        %s\n", entry.AudioPath)
	}
	if entry.ImagePath != "" {
		fmt.Printf("  image:        %s\n", entry.ImagePath)
	}
	if entry.Tags != "" {
		fmt.Printf("  tags:         %s\n", entry.Tags)
	}
	fmt.Printf("  max_attempts: %d\n", entry.MaxAttempts)
	fmt.Printf("  status:       %s\n", entry.Status)
}

// -- status command --

func cmdStatus(args []string) {
	entryID := ""
	dbPath := defaultExportsDBPath()

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--entry":
			if i+1 < len(args) {
				entryID = args[i+1]
				i++
			}
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		}
	}

	db, err := tracking.OpenRetryQueueDB(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening DB: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	if entryID != "" {
		entry, err := db.GetByEntryID(entryID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if entry == nil {
			fmt.Fprintf(os.Stderr, "Entry not found: %s\n", entryID)
			os.Exit(1)
		}
		printRetryEntry(entry)
		return
	}

	// Show summary counts and list all entries
	pending, _ := db.CountByStatus(tracking.RetryStatusPending)
	retrying, _ := db.CountByStatus(tracking.RetryStatusRetrying)
	completed, _ := db.CountByStatus(tracking.RetryStatusCompleted)
	failed, _ := db.CountByStatus(tracking.RetryStatusFailed)

	fmt.Printf("ER1 Retry Queue Status:\n")
	fmt.Printf("  pending:   %d\n", pending)
	fmt.Printf("  retrying:  %d\n", retrying)
	fmt.Printf("  completed: %d\n", completed)
	fmt.Printf("  failed:    %d\n", failed)
	fmt.Printf("  total:     %d\n", pending+retrying+completed+failed)

	entries, err := db.ListAll(100)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing entries: %v\n", err)
		os.Exit(1)
	}

	if len(entries) > 0 {
		fmt.Printf("\nEntries:\n")
		for _, e := range entries {
			fmt.Printf("  %-20s  status=%-10s  attempts=%d/%d", e.EntryID, e.Status, e.Attempts, e.MaxAttempts)
			if e.LastError != "" {
				fmt.Printf("  error=%q", e.LastError)
			}
			fmt.Println()
		}
	}
}

func printRetryEntry(e *tracking.RetryEntry) {
	fmt.Printf("Entry: %s\n", e.EntryID)
	fmt.Printf("  status:       %s\n", e.Status)
	fmt.Printf("  attempts:     %d/%d\n", e.Attempts, e.MaxAttempts)
	fmt.Printf("  transcript:   %s\n", e.TranscriptPath)
	if e.AudioPath != "" {
		fmt.Printf("  audio:        %s\n", e.AudioPath)
	}
	if e.ImagePath != "" {
		fmt.Printf("  image:        %s\n", e.ImagePath)
	}
	if e.Tags != "" {
		fmt.Printf("  tags:         %s\n", e.Tags)
	}
	if e.LastError != "" {
		fmt.Printf("  last_error:   %s\n", e.LastError)
	}
	fmt.Printf("  created_at:   %s\n", e.CreatedAt.Format(time.RFC3339))
	fmt.Printf("  updated_at:   %s\n", e.UpdatedAt.Format(time.RFC3339))
	fmt.Printf("  next_retry:   %s\n", e.NextRetryAt.Format(time.RFC3339))
}

// -- cancel command --

func cmdCancel(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: m3c-tools cancel <entry_id> [--db <path>]")
		os.Exit(1)
	}
	entryID := args[0]
	dbPath := defaultExportsDBPath()

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		}
	}

	db, err := tracking.OpenRetryQueueDB(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening DB: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Check entry exists
	entry, err := db.GetByEntryID(entryID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if entry == nil {
		fmt.Fprintf(os.Stderr, "Entry not found: %s\n", entryID)
		os.Exit(1)
	}
	if entry.Status == tracking.RetryStatusCompleted {
		fmt.Fprintf(os.Stderr, "Entry %s is already completed\n", entryID)
		os.Exit(1)
	}

	err = db.SetStatus(entryID, "cancelled")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error cancelling: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Cancelled entry: %s\n", entryID)
}

