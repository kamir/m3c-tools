package e2e

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/menubar"
	"github.com/kamir/m3c-tools/pkg/transcript"
)

// TestMenubarCLIHelp verifies the "menubar" subcommand is wired into the
// main binary by checking that it appears in --help output.
func TestMenubarCLIHelp(t *testing.T) {
	// Build the binary
	build := exec.Command("go", "build", "-o", "../build/m3c-tools-test", "../cmd/m3c-tools")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	// Run --help and check that "menubar" is listed
	cmd := exec.Command("../build/m3c-tools-test", "--help")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("help command failed: %v\n%s", err, out)
	}

	output := string(out)
	if !strings.Contains(output, "menubar") {
		t.Error("Expected 'menubar' in help output")
	}
	if !strings.Contains(output, "--title") {
		t.Error("Expected '--title' flag documentation in help output")
	}
	if !strings.Contains(output, "--icon") {
		t.Error("Expected '--icon' flag documentation in help output")
	}
	if !strings.Contains(output, "--log") {
		t.Error("Expected '--log' flag documentation in help output")
	}
}

// TestMenubarConfig verifies that the menubar command creates a properly
// configured App with custom flags applied.
func TestMenubarConfig(t *testing.T) {
	cfg := menubar.DefaultConfig()

	// Simulate flag parsing: override title, icon, log
	cfg.Title = "TEST"
	cfg.IconPath = "/tmp/test-icon.png"
	cfg.LogPath = "/tmp/test.log"

	app := menubar.NewAppWithConfig(cfg, menubar.Handlers{})

	if app.Config.Title != "TEST" {
		t.Errorf("Title = %q, want TEST", app.Config.Title)
	}
	if app.Config.IconPath != "/tmp/test-icon.png" {
		t.Errorf("IconPath = %q, want /tmp/test-icon.png", app.Config.IconPath)
	}
	if app.Config.LogPath != "/tmp/test.log" {
		t.Errorf("LogPath = %q, want /tmp/test.log", app.Config.LogPath)
	}
	if app.GetStatus() != menubar.StatusIdle {
		t.Errorf("initial status = %q, want idle", app.GetStatus())
	}
}

// TestMenubarTranscriptFetcherCreation verifies TranscriptFetcher can be
// created and configured without errors.
func TestMenubarTranscriptFetcherCreation(t *testing.T) {
	tf := menubar.NewTranscriptFetcher()
	if tf == nil {
		t.Fatal("NewTranscriptFetcher() returned nil")
	}

	// Custom languages
	tf2 := menubar.NewTranscriptFetcherWithLanguages([]string{"de", "ja"})
	if tf2 == nil {
		t.Fatal("NewTranscriptFetcherWithLanguages() returned nil")
	}

	// SetFormatter should not panic
	tf.SetFormatter(transcript.SRTFormatter{})
	tf.SetLanguages([]string{"fr", "it"})
}

// TestMenubarFetchAndDisplayStatus verifies that FetchAndDisplay updates
// app status correctly on failure (offline-safe, no network needed).
func TestMenubarFetchAndDisplayStatus(t *testing.T) {
	app := menubar.NewAppWithConfig(menubar.DefaultConfig(), menubar.Handlers{
		Notify: func(title, message string) {
			// Capture notifications silently in test
			t.Logf("notification: %s — %s", title, message)
		},
	})
	tf := menubar.NewTranscriptFetcher()

	// Fetch with an invalid video ID — should fail and set status to error
	tf.FetchAndDisplay(app, "!!!invalid!!!")

	if app.GetStatus() != menubar.StatusError {
		t.Errorf("status after invalid fetch = %q, want error", app.GetStatus())
	}
	if app.HistoryLen() != 0 {
		t.Errorf("history should be empty after failed fetch, got %d", app.HistoryLen())
	}
}

// TestMenubarWireToAppDispatch verifies that WireToAppInstance correctly
// dispatches fetch_transcript to the fetcher and other actions to fallback.
func TestMenubarWireToAppDispatch(t *testing.T) {
	app := menubar.NewAppWithConfig(menubar.DefaultConfig(), menubar.Handlers{
		Notify: func(title, message string) {},
	})
	tf := menubar.NewTranscriptFetcher()

	var fallbackActions []menubar.ActionType
	handler := tf.WireToAppInstance(app, func(action menubar.ActionType, data string) {
		fallbackActions = append(fallbackActions, action)
	})

	// Screenshot should go to fallback
	handler(menubar.ActionCaptureScreenshot, "")
	handler(menubar.ActionQuit, "")

	if len(fallbackActions) != 2 {
		t.Fatalf("expected 2 fallback calls, got %d", len(fallbackActions))
	}
	if fallbackActions[0] != menubar.ActionCaptureScreenshot {
		t.Errorf("fallback[0] = %q, want capture_screenshot", fallbackActions[0])
	}
	if fallbackActions[1] != menubar.ActionQuit {
		t.Errorf("fallback[1] = %q, want quit", fallbackActions[1])
	}
}

// TestMenubarFetchResult verifies FetchResult struct fields.
func TestMenubarFetchResult(t *testing.T) {
	r := menubar.FetchResult{
		VideoID:      "test123video",
		Language:     "English",
		LanguageCode: "en",
		SnippetCount: 10,
		CharCount:    500,
		Text:         "Hello world",
		Flag:         "🇬🇧",
	}
	if r.VideoID != "test123video" {
		t.Errorf("VideoID = %q", r.VideoID)
	}
	if r.SnippetCount != 10 {
		t.Errorf("SnippetCount = %d", r.SnippetCount)
	}
	if r.CharCount != 500 {
		t.Errorf("CharCount = %d", r.CharCount)
	}
	if r.Flag != "🇬🇧" {
		t.Errorf("Flag = %q", r.Flag)
	}
}

// TestMenubarActionCallback verifies the action callback is invoked correctly.
func TestMenubarActionCallback(t *testing.T) {
	var capturedAction menubar.ActionType
	var capturedData string

	cfg := menubar.DefaultConfig()
	app := menubar.NewAppWithConfig(cfg, menubar.Handlers{
		OnAction: func(action menubar.ActionType, data string) {
			capturedAction = action
			capturedData = data
		},
	})

	// Simulate actions through the app
	app.Handlers.OnAction(menubar.ActionFetchTranscript, "dQw4w9WgXcQ")

	if capturedAction != menubar.ActionFetchTranscript {
		t.Errorf("capturedAction = %q, want fetch_transcript", capturedAction)
	}
	if capturedData != "dQw4w9WgXcQ" {
		t.Errorf("capturedData = %q, want dQw4w9WgXcQ", capturedData)
	}
}

// TestMenubarER1UploadHandlerWiring verifies that OnUploadER1 can be wired
// into the Handlers struct and invoked with a video ID, returning results.
func TestMenubarER1UploadHandlerWiring(t *testing.T) {
	var uploadedVideoID string

	app := menubar.NewAppWithConfig(menubar.DefaultConfig(), menubar.Handlers{
		OnAction: func(action menubar.ActionType, data string) {
			t.Logf("[action] %s data=%q", action, data)
		},
		Notify: func(title, message string) {
			t.Logf("[notify] %s: %s", title, message)
		},
		OnUploadER1: func(videoID string) (*menubar.ER1UploadResult, error) {
			uploadedVideoID = videoID
			return &menubar.ER1UploadResult{
				VideoID: videoID,
				DocID:   "test-doc-id-123",
				Message: "Uploaded " + videoID + " → doc_id: test-doc-id-123",
				Queued:  false,
			}, nil
		},
	})

	// Verify the handler is set
	if app.Handlers.OnUploadER1 == nil {
		t.Fatal("OnUploadER1 handler should not be nil")
	}

	// Invoke the handler directly (simulating menu item click)
	result, err := app.Handlers.OnUploadER1("dQw4w9WgXcQ")
	if err != nil {
		t.Fatalf("OnUploadER1 error: %v", err)
	}
	if uploadedVideoID != "dQw4w9WgXcQ" {
		t.Errorf("uploadedVideoID = %q, want dQw4w9WgXcQ", uploadedVideoID)
	}
	if result.DocID != "test-doc-id-123" {
		t.Errorf("DocID = %q, want test-doc-id-123", result.DocID)
	}
	if result.Queued {
		t.Error("result.Queued should be false for successful upload")
	}
}

// TestMenubarER1UploadQueuedResult verifies that a queued upload result
// correctly sets the Queued flag and has empty DocID.
func TestMenubarER1UploadQueuedResult(t *testing.T) {
	app := menubar.NewAppWithConfig(menubar.DefaultConfig(), menubar.Handlers{
		OnUploadER1: func(videoID string) (*menubar.ER1UploadResult, error) {
			return &menubar.ER1UploadResult{
				VideoID: videoID,
				Message: "Upload failed, queued for retry: " + videoID + "_12345",
				Queued:  true,
			}, nil
		},
	})

	result, err := app.Handlers.OnUploadER1("abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Queued {
		t.Error("expected Queued=true for offline queued upload")
	}
	if result.DocID != "" {
		t.Errorf("DocID should be empty for queued upload, got %q", result.DocID)
	}
	if !strings.Contains(result.Message, "queued") {
		t.Errorf("message should mention 'queued', got %q", result.Message)
	}
}

// TestMenubarER1UploadStatusTransitions verifies that the app status
// changes correctly during the ER1 upload workflow.
func TestMenubarER1UploadStatusTransitions(t *testing.T) {
	app := menubar.NewApp()

	// Start idle
	if app.GetStatus() != menubar.StatusIdle {
		t.Fatalf("initial status = %q, want idle", app.GetStatus())
	}

	// Set to uploading (as handleUploadER1 does)
	app.SetStatus(menubar.StatusUploading)
	if app.GetStatus() != menubar.StatusUploading {
		t.Errorf("status during upload = %q, want uploading", app.GetStatus())
	}

	// After success, reset to idle
	app.SetStatus(menubar.StatusIdle)
	if app.GetStatus() != menubar.StatusIdle {
		t.Errorf("status after success = %q, want idle", app.GetStatus())
	}

	// After failure, set error
	app.SetStatus(menubar.StatusError)
	if app.GetStatus() != menubar.StatusError {
		t.Errorf("status after failure = %q, want error", app.GetStatus())
	}
}

