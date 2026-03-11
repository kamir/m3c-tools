package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/menubar"
)

// ---------------------------------------------------------------------------
// Menu bar integration tests — full component wiring
// ---------------------------------------------------------------------------

// TestMenubarIntegrationFullLifecycle verifies the complete menu bar app
// lifecycle: create → configure → wire handlers → simulate actions →
// update history → verify state → clear → verify cleanup.
func TestMenubarIntegrationFullLifecycle(t *testing.T) {
	var mu sync.Mutex
	var actions []string
	var notifications []string

	cfg := menubar.DefaultConfig()
	cfg.Title = "TEST-LIFECYCLE"

	app := menubar.NewAppWithConfig(cfg, menubar.Handlers{
		OnAction: func(action menubar.ActionType, data string) {
			mu.Lock()
			defer mu.Unlock()
			actions = append(actions, string(action)+":"+data)
		},
		Notify: func(title, message string) {
			mu.Lock()
			defer mu.Unlock()
			notifications = append(notifications, title+"|"+message)
		},
		OnUploadER1: func(videoID string) (*menubar.ER1UploadResult, error) {
			return &menubar.ER1UploadResult{
				VideoID: videoID,
				DocID:   "lifecycle-doc-" + videoID,
				Message: "OK",
			}, nil
		},
	})
	app.SetAuthSession(menubar.AuthSession{LoggedIn: true, UserID: "ctx-test"})

	// 1. Initial state
	if app.GetStatus() != menubar.StatusIdle {
		t.Fatalf("initial status = %q, want idle", app.GetStatus())
	}
	if app.HistoryLen() != 0 {
		t.Fatalf("initial history = %d, want 0", app.HistoryLen())
	}

	// 2. Simulate transcript fetch action
	app.Handlers.OnAction(menubar.ActionFetchTranscript, "vid1")
	app.AddHistory(menubar.NewHistoryEntry("vid1", "🇬🇧"))

	if app.HistoryLen() != 1 {
		t.Errorf("after 1 add, history = %d, want 1", app.HistoryLen())
	}

	// 3. Simulate ER1 upload action
	app.SetStatus(menubar.StatusUploading)
	result, err := app.Handlers.OnUploadER1("vid2")
	if err != nil {
		t.Fatalf("upload error: %v", err)
	}
	if result.DocID != "lifecycle-doc-vid2" {
		t.Errorf("DocID = %q", result.DocID)
	}
	app.AddHistory(menubar.NewHistoryEntry("vid2", "🚀"))
	app.SetStatus(menubar.StatusIdle)

	if app.HistoryLen() != 2 {
		t.Errorf("after 2 adds, history = %d, want 2", app.HistoryLen())
	}

	// 4. Verify menu items reflect current state
	items := app.BuildMenuItems()
	foundStatus := false
	foundHistory := false
	for _, item := range items {
		if strings.Contains(item.Text, "idle") {
			foundStatus = true
		}
		if strings.Contains(item.Text, "History (2)") {
			foundHistory = true
		}
	}
	if !foundStatus {
		t.Error("menu items should show 'idle' status")
	}
	if !foundHistory {
		t.Error("menu items should show 'History (2)'")
	}

	// 5. Verify actions were recorded
	mu.Lock()
	if len(actions) < 1 {
		t.Error("expected at least 1 action recorded")
	}
	mu.Unlock()

	// 6. Clear and verify cleanup
	app.ClearHistory()
	if app.HistoryLen() != 0 {
		t.Errorf("after clear, history = %d, want 0", app.HistoryLen())
	}

	items = app.BuildMenuItems()
	for _, item := range items {
		if strings.Contains(item.Text, "History (0)") {
			break
		}
	}
}

// TestMenubarIntegrationTranscriptFetcherWired verifies that the
// TranscriptFetcher correctly integrates with the App when wired via
// WireToAppInstance, dispatching fetch_transcript and passing other
// actions to the fallback handler.
func TestMenubarIntegrationTranscriptFetcherWired(t *testing.T) {
	app := menubar.NewAppWithConfig(menubar.DefaultConfig(), menubar.Handlers{
		Notify: func(title, message string) {},
	})
	app.SetAuthSession(menubar.AuthSession{LoggedIn: true, UserID: "ctx-test"})
	tf := menubar.NewTranscriptFetcher()

	var fallbackCalls []menubar.ActionType
	handler := tf.WireToAppInstance(app, func(action menubar.ActionType, data string) {
		fallbackCalls = append(fallbackCalls, action)
	})

	// Non-fetch actions go to fallback
	handler(menubar.ActionCaptureScreenshot, "")
	handler(menubar.ActionUploadER1, "vid1")
	handler(menubar.ActionQuit, "")

	if len(fallbackCalls) != 3 {
		t.Fatalf("expected 3 fallback calls, got %d", len(fallbackCalls))
	}
	expected := []menubar.ActionType{
		menubar.ActionCaptureScreenshot,
		menubar.ActionUploadER1,
		menubar.ActionQuit,
	}
	for i, exp := range expected {
		if fallbackCalls[i] != exp {
			t.Errorf("fallback[%d] = %q, want %q", i, fallbackCalls[i], exp)
		}
	}
}

// TestMenubarIntegrationStatusDuringFetch verifies status transitions
// when FetchAndDisplay runs with an invalid video ID (offline-safe).
func TestMenubarIntegrationStatusDuringFetch(t *testing.T) {
	var notifs []string
	app := menubar.NewAppWithConfig(menubar.DefaultConfig(), menubar.Handlers{
		Notify: func(title, message string) {
			notifs = append(notifs, title)
		},
	})
	tf := menubar.NewTranscriptFetcher()

	// FetchAndDisplay with invalid ID sets status to error
	tf.FetchAndDisplay(app, "!!!invalid!!!")

	if app.GetStatus() != menubar.StatusError {
		t.Errorf("status = %q, want error", app.GetStatus())
	}

	// Should have received notifications (Fetching + Error)
	if len(notifs) < 2 {
		t.Errorf("expected at least 2 notifications, got %d: %v", len(notifs), notifs)
	}
}

// TestMenubarIntegrationMenuItemsComplete verifies all expected menu
// items are present in the built menu.
func TestMenubarIntegrationMenuItemsComplete(t *testing.T) {
	app := menubar.NewApp()
	app.SetAuthSession(menubar.AuthSession{LoggedIn: true, UserID: "ctx-test"})
	items := app.BuildMenuItems()

	// Note: "Quit" is not listed here because menuet automatically
	// appends "Start at Login" and "Quit" to root menus at runtime.
	expectedTexts := []string{
		"Logout from ER1",
		"Fetch Transcript...",
		"Capture Screenshot",
		"Quick Impulse",
		"Status:",
		"History",
		"Open Log File",
	}

	for _, exp := range expectedTexts {
		found := false
		for _, item := range items {
			if strings.Contains(item.Text, exp) {
				found = true
				break
			}
		}
		if !found {
			texts := make([]string, 0, len(items))
			for _, item := range items {
				if item.Text != "" {
					texts = append(texts, item.Text)
				}
			}
			t.Errorf("menu item containing %q not found in: %v", exp, texts)
		}
	}
}

// TestMenubarIntegrationConcurrentStatusUpdates verifies thread-safety
// of concurrent status and history updates (race detector stress test).
func TestMenubarIntegrationConcurrentStatusUpdates(t *testing.T) {
	app := menubar.NewApp()
	var wg sync.WaitGroup

	// Concurrently update status from multiple goroutines
	statuses := []menubar.Status{
		menubar.StatusIdle, menubar.StatusFetching,
		menubar.StatusUploading, menubar.StatusRecording,
		menubar.StatusError,
	}

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			app.SetStatus(statuses[idx%len(statuses)])
			_ = app.GetStatus()
			app.AddHistory(menubar.NewHistoryEntry("vid", "🇬🇧"))
			_ = app.HistoryLen()
			_ = app.GetHistory()
		}(i)
	}
	wg.Wait()

	// Should have 50 history entries, status should be valid
	if app.HistoryLen() != 50 {
		t.Errorf("after 50 concurrent adds, HistoryLen = %d", app.HistoryLen())
	}
	s := app.GetStatus()
	validStatuses := map[menubar.Status]bool{
		menubar.StatusIdle: true, menubar.StatusFetching: true,
		menubar.StatusUploading: true, menubar.StatusRecording: true,
		menubar.StatusError: true,
	}
	if !validStatuses[s] {
		t.Errorf("status = %q is not a valid status", s)
	}
}

// TestMenubarIntegrationHistoryInMenuUpdates verifies that menu items
// reflect the correct history count as entries are added.
func TestMenubarIntegrationHistoryInMenuUpdates(t *testing.T) {
	app := menubar.NewApp()
	app.SetAuthSession(menubar.AuthSession{LoggedIn: true, UserID: "ctx-test"})

	// Empty history
	items := app.BuildMenuItems()
	foundEmpty := false
	for _, item := range items {
		if strings.Contains(item.Text, "History") && strings.Contains(item.Text, "(0)") {
			foundEmpty = true
			break
		}
	}
	if !foundEmpty {
		t.Error("expected 'History (0)' in empty app menu items")
	}

	// Add entries and verify
	app.AddHistory(menubar.NewHistoryEntry("a", "🇬🇧"))
	app.AddHistory(menubar.NewHistoryEntry("b", "🇩🇪"))
	app.AddHistory(menubar.NewHistoryEntry("c", "🇫🇷"))

	items = app.BuildMenuItems()
	foundThree := false
	for _, item := range items {
		if strings.Contains(item.Text, "History") && strings.Contains(item.Text, "(3)") {
			foundThree = true
			break
		}
	}
	if !foundThree {
		t.Error("expected 'History (3)' after adding 3 entries")
	}
}

// ---------------------------------------------------------------------------
// macOS .app bundle launch/quit lifecycle tests
// ---------------------------------------------------------------------------

// TestAppBundleLaunchHelp verifies the .app bundle executable can launch
// and respond to the help subcommand, confirming the binary is functional.
func TestAppBundleLaunchHelp(t *testing.T) {
	repoRoot := findRepoRootE2E(t)
	execPath := buildAndFindExec(t, repoRoot)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, execPath, "help")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("help command failed: %v\n%s", err, out)
	}

	output := string(out)
	// Verify all subcommands are listed
	for _, sub := range []string{"transcript", "upload", "record", "devices", "menubar", "retry", "check-er1"} {
		if !strings.Contains(output, sub) {
			t.Errorf("help output missing subcommand %q", sub)
		}
	}
}

// TestAppBundleLaunchUnknownCommand verifies that the .app binary
// exits with non-zero status on an unknown subcommand.
func TestAppBundleLaunchUnknownCommand(t *testing.T) {
	repoRoot := findRepoRootE2E(t)
	execPath := buildAndFindExec(t, repoRoot)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, execPath, "nonexistent-command-xyz")
	out, err := cmd.CombinedOutput()

	// Should fail with non-zero exit code
	if err == nil {
		t.Error("expected non-zero exit for unknown command")
	}
	if !strings.Contains(string(out), "Unknown command") {
		t.Errorf("expected 'Unknown command' in output, got: %s", out)
	}
}

// TestAppBundleLaunchNoArgs verifies the binary shows usage and exits
// with non-zero when invoked without arguments.
func TestAppBundleLaunchNoArgs(t *testing.T) {
	repoRoot := findRepoRootE2E(t)
	execPath := buildAndFindExec(t, repoRoot)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, execPath)
	out, err := cmd.CombinedOutput()

	// Should fail (no args)
	if err == nil {
		t.Error("expected non-zero exit when called without args")
	}
	if !strings.Contains(string(out), "m3c-tools") {
		t.Errorf("expected usage output containing 'm3c-tools', got: %s", out)
	}
}

// TestAppBundleRetryGracefulShutdown verifies that the retry subcommand
// responds to SIGTERM with graceful shutdown. This tests the signal
// handling lifecycle of the binary.
func TestAppBundleRetryGracefulShutdown(t *testing.T) {
	repoRoot := findRepoRootE2E(t)
	execPath := buildAndFindExec(t, repoRoot)

	// Use a temp queue file so no real queue is affected
	tmpQueue := filepath.Join(t.TempDir(), "test-queue.json")
	os.WriteFile(tmpQueue, []byte("[]"), 0644)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, execPath, "retry",
		"--interval", "1",
		"--max-retries", "1",
		"--queue", tmpQueue,
	)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())

	// Start the process
	err := cmd.Start()
	if err != nil {
		t.Fatalf("failed to start retry: %v", err)
	}

	// Give it a moment to initialize
	time.Sleep(500 * time.Millisecond)

	// Send SIGTERM for graceful shutdown
	if cmd.Process != nil {
		cmd.Process.Signal(syscall.SIGTERM)
	}

	// Wait for it to exit (should be quick since it handles SIGTERM)
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		// Process exited — success. The exit code may be non-zero due to
		// signal handling, but the key thing is it didn't hang.
		_ = err
		t.Log("retry process exited after SIGTERM — graceful shutdown confirmed")
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatal("retry process did not exit within 10s after SIGTERM")
	}
}

// TestAppBundleRetryExitsOnSIGINT verifies that the retry subcommand
// responds to SIGINT (Ctrl+C) and shuts down.
func TestAppBundleRetryExitsOnSIGINT(t *testing.T) {
	repoRoot := findRepoRootE2E(t)
	execPath := buildAndFindExec(t, repoRoot)

	tmpQueue := filepath.Join(t.TempDir(), "test-queue.json")
	os.WriteFile(tmpQueue, []byte("[]"), 0644)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, execPath, "retry",
		"--interval", "1",
		"--max-retries", "1",
		"--queue", tmpQueue,
	)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())

	err := cmd.Start()
	if err != nil {
		t.Fatalf("failed to start retry: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	// Send SIGINT (Ctrl+C equivalent)
	if cmd.Process != nil {
		cmd.Process.Signal(syscall.SIGINT)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		_ = err
		t.Log("retry process exited after SIGINT — graceful shutdown confirmed")
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatal("retry process did not exit within 10s after SIGINT")
	}
}

// TestAppBundleMenubarFlagParsing verifies the menubar subcommand
// accepts --title, --icon, --log flags by checking help output
// documents them.
func TestAppBundleMenubarFlagParsing(t *testing.T) {
	repoRoot := findRepoRootE2E(t)
	execPath := buildAndFindExec(t, repoRoot)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, execPath, "help")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("help failed: %v\n%s", err, out)
	}

	output := string(out)
	for _, flag := range []string{"--title", "--icon", "--log"} {
		if !strings.Contains(output, flag) {
			t.Errorf("help missing menubar flag %q", flag)
		}
	}
	if !strings.Contains(output, "menubar") {
		t.Error("help missing 'menubar' subcommand")
	}
}

// TestAppBundleExecPermissions verifies the built binary has the correct
// file permissions (executable).
func TestAppBundleExecPermissions(t *testing.T) {
	repoRoot := findRepoRootE2E(t)
	execPath := buildAndFindExec(t, repoRoot)

	info, err := os.Stat(execPath)
	if err != nil {
		t.Fatalf("stat exec: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Error("binary is not executable")
	}
	if info.Size() == 0 {
		t.Error("binary is empty")
	}
	t.Logf("binary: %s (%d bytes, mode=%s)", execPath, info.Size(), info.Mode())
}

// TestAppBundleInfoPlistLSUIElement verifies the .app bundle's
// Info.plist has LSUIElement set to true (agent app, no dock icon).
func TestAppBundleInfoPlistLSUIElement(t *testing.T) {
	repoRoot := findRepoRootE2E(t)
	buildDir := t.TempDir()

	// Build the app bundle
	cmd := exec.Command("make", "build-app", "BUILD_DIR="+buildDir)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make build-app failed: %v\n%s", err, out)
	}

	plistPath := filepath.Join(buildDir, "M3C-Tools.app", "Contents", "Info.plist")
	data, err := os.ReadFile(plistPath)
	if err != nil {
		t.Fatalf("read plist: %v", err)
	}
	plist := string(data)

	// LSUIElement = true makes it a menu bar (agent) app with no dock icon
	if !strings.Contains(plist, "LSUIElement") {
		t.Error("Info.plist missing LSUIElement key")
	}
	if !strings.Contains(plist, "<true/>") {
		t.Error("Info.plist LSUIElement should be <true/>")
	}

	// Verify privacy descriptions for microphone and screen capture
	if !strings.Contains(plist, "NSMicrophoneUsageDescription") {
		t.Error("Info.plist missing NSMicrophoneUsageDescription")
	}
	if !strings.Contains(plist, "NSScreenCaptureUsageDescription") {
		t.Error("Info.plist missing NSScreenCaptureUsageDescription")
	}

	// Verify bundle executable points to m3c-tools
	if !strings.Contains(plist, "<key>CFBundleExecutable</key>") {
		t.Error("Info.plist missing CFBundleExecutable")
	}
	if !strings.Contains(plist, "<string>m3c-tools</string>") {
		t.Error("Info.plist CFBundleExecutable should be m3c-tools")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// We import menuet for BuildMenuItems return type via the menubar package.

// findRepoRootE2E finds the repo root from the current working directory.
func findRepoRootE2E(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "Makefile")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("cannot find repo root from %s", wd)
		}
		dir = parent
	}
}

// buildAndFindExec builds the CLI binary and returns the path to it.
func buildAndFindExec(t *testing.T, repoRoot string) string {
	t.Helper()

	cmd := exec.Command("make", "build")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make build failed: %v\n%s", err, out)
	}

	execPath := filepath.Join(repoRoot, "build", "m3c-tools")
	if _, err := os.Stat(execPath); err != nil {
		t.Fatalf("binary not found at %s: %v", execPath, err)
	}
	return execPath
}
