package e2e

import (
	"os"
	"testing"

	"github.com/kamir/m3c-tools/pkg/plaud"
)

func TestPlaudListRecordings(t *testing.T) {
	if os.Getenv("M3C_TEST_PLAUD") != "1" {
		t.Skip("Skipping Plaud integration test (set M3C_TEST_PLAUD=1)")
	}

	cfg := plaud.LoadConfig()
	session, err := plaud.LoadToken(cfg.TokenPath)
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}

	client := plaud.NewClient(cfg, session.Token)
	recordings, err := client.ListRecordings()
	if err != nil {
		t.Fatalf("ListRecordings: %v", err)
	}

	t.Logf("Found %d recordings", len(recordings))
	for i, rec := range recordings {
		t.Logf("  %d: %s (%ds) [%s]", i+1, rec.Title, rec.Duration, rec.Status)
		if i >= 4 {
			break
		}
	}
}

func TestPlaudSyncRecording(t *testing.T) {
	if os.Getenv("M3C_TEST_PLAUD") != "1" {
		t.Skip("Skipping Plaud integration test (set M3C_TEST_PLAUD=1)")
	}

	recID := os.Getenv("M3C_TEST_PLAUD_RECORDING_ID")
	if recID == "" {
		t.Skip("Skipping: set M3C_TEST_PLAUD_RECORDING_ID")
	}

	cfg := plaud.LoadConfig()
	session, err := plaud.LoadToken(cfg.TokenPath)
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}

	client := plaud.NewClient(cfg, session.Token)

	// Download audio.
	audioData, format, err := client.DownloadAudio(recID)
	if err != nil {
		t.Fatalf("DownloadAudio: %v", err)
	}
	t.Logf("Downloaded %d bytes (%s)", len(audioData), format)

	// Get transcript.
	tx, err := client.GetTranscript(recID)
	if err != nil {
		t.Logf("No transcript available: %v", err)
	} else {
		t.Logf("Transcript: %d chars, %d segments", len(tx.Text), len(tx.Segments))
	}
}
