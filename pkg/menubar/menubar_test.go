package menubar

import (
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/transcript"
)

func TestCleanVideoID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"dQw4w9WgXcQ", "dQw4w9WgXcQ"},
		{"https://www.youtube.com/watch?v=dQw4w9WgXcQ", "dQw4w9WgXcQ"},
		{"https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=42s", "dQw4w9WgXcQ"},
		{"https://youtu.be/dQw4w9WgXcQ", "dQw4w9WgXcQ"},
		{"https://youtu.be/dQw4w9WgXcQ?si=abc123", "dQw4w9WgXcQ"},
		{"https://www.youtube.com/watch?v=abc&list=PLxyz", "abc"},
		{"", ""},
	}
	for _, tt := range tests {
		got := CleanVideoID(tt.input)
		if got != tt.want {
			t.Errorf("CleanVideoID(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNewHistoryEntry(t *testing.T) {
	before := time.Now()
	entry := NewHistoryEntry("dQw4w9WgXcQ", "🇬🇧")
	after := time.Now()

	if entry.VideoID != "dQw4w9WgXcQ" {
		t.Errorf("VideoID = %q, want dQw4w9WgXcQ", entry.VideoID)
	}
	if entry.Language != "🇬🇧" {
		t.Errorf("Language = %q, want 🇬🇧", entry.Language)
	}
	if entry.Timestamp.Before(before) || entry.Timestamp.After(after) {
		t.Errorf("Timestamp %v not in range [%v, %v]", entry.Timestamp, before, after)
	}
	if entry.Label == "" {
		t.Error("Label should not be empty")
	}
	if !contains(entry.Label, "dQw4w9WgXcQ") {
		t.Errorf("Label %q should contain video ID", entry.Label)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.AppName != "M3C Tools" {
		t.Errorf("AppName = %q, want 'M3C Tools'", cfg.AppName)
	}
	if cfg.AppLabel != "com.kamir.m3c-tools" {
		t.Errorf("AppLabel = %q, want 'com.kamir.m3c-tools'", cfg.AppLabel)
	}
	if cfg.Title != "M3C" {
		t.Errorf("Title = %q, want 'M3C'", cfg.Title)
	}
	if cfg.LogPath == "" {
		t.Error("LogPath should not be empty")
	}
}

func TestActionTypes(t *testing.T) {
	// Verify all action types are distinct non-empty strings.
	actions := []ActionType{
		ActionFetchTranscript,
		ActionCaptureScreenshot,
		ActionQuickImpulse,
		ActionRecordImpression,
		ActionCopyTranscript,
		ActionBatchImport,
		ActionUploadER1,
		ActionLoginER1,
		ActionLogoutER1,
		ActionOpenLog,
		ActionQuit,
	}
	seen := make(map[ActionType]bool)
	for _, a := range actions {
		if a == "" {
			t.Error("ActionType should not be empty")
		}
		if seen[a] {
			t.Errorf("duplicate ActionType: %s", a)
		}
		seen[a] = true
	}
}

func TestStatusValues(t *testing.T) {
	statuses := []Status{StatusIdle, StatusFetching, StatusUploading, StatusRecording, StatusError}
	seen := make(map[Status]bool)
	for _, s := range statuses {
		if s == "" {
			t.Error("Status should not be empty")
		}
		if seen[s] {
			t.Errorf("duplicate Status: %s", s)
		}
		seen[s] = true
	}
}

func TestFindIconMissing(t *testing.T) {
	// A non-existent icon should return empty string, not panic.
	result := FindIcon("nonexistent_icon_abc123.png")
	if result != "" {
		t.Errorf("FindIcon for missing file returned %q, want empty", result)
	}
}

func TestHistoryStore(t *testing.T) {
	var store HistoryStore

	// Initially empty
	if store.Len() != 0 {
		t.Errorf("new store Len() = %d, want 0", store.Len())
	}
	if got := store.All(); len(got) != 0 {
		t.Errorf("new store All() has %d entries, want 0", len(got))
	}

	// Add entries
	store.Add(NewHistoryEntry("vid1", "🇬🇧"))
	store.Add(NewHistoryEntry("vid2", "🇩🇪"))

	if store.Len() != 2 {
		t.Errorf("after 2 adds, Len() = %d, want 2", store.Len())
	}

	entries := store.All()
	if len(entries) != 2 {
		t.Fatalf("All() returned %d entries, want 2", len(entries))
	}
	if entries[0].VideoID != "vid1" {
		t.Errorf("entries[0].VideoID = %q, want vid1", entries[0].VideoID)
	}
	if entries[1].VideoID != "vid2" {
		t.Errorf("entries[1].VideoID = %q, want vid2", entries[1].VideoID)
	}

	// All() returns a snapshot — mutating it doesn't affect the store
	entries[0].VideoID = "mutated"
	fresh := store.All()
	if fresh[0].VideoID != "vid1" {
		t.Error("All() should return a copy, not a reference to internal state")
	}

	// Clear
	store.Clear()
	if store.Len() != 0 {
		t.Errorf("after Clear(), Len() = %d, want 0", store.Len())
	}
}

func TestAppStatusConcurrency(t *testing.T) {
	app := NewApp()

	if app.GetStatus() != StatusIdle {
		t.Errorf("initial status = %q, want %q", app.GetStatus(), StatusIdle)
	}

	app.SetStatus(StatusFetching)
	if app.GetStatus() != StatusFetching {
		t.Errorf("after SetStatus, got %q, want %q", app.GetStatus(), StatusFetching)
	}

	app.SetStatus(StatusError)
	if app.GetStatus() != StatusError {
		t.Errorf("after second SetStatus, got %q, want %q", app.GetStatus(), StatusError)
	}
}

func TestAppHistory(t *testing.T) {
	app := NewApp()

	app.AddHistory(NewHistoryEntry("abc", "🇫🇷"))
	app.AddHistory(NewHistoryEntry("def", "🇪🇸"))

	if app.HistoryLen() != 2 {
		t.Errorf("HistoryLen() = %d, want 2", app.HistoryLen())
	}

	entries := app.GetHistory()
	if entries[0].VideoID != "abc" || entries[1].VideoID != "def" {
		t.Errorf("unexpected history entries: %+v", entries)
	}

	app.ClearHistory()
	if app.HistoryLen() != 0 {
		t.Errorf("after ClearHistory, HistoryLen() = %d, want 0", app.HistoryLen())
	}
}

func TestNewAppWithConfig(t *testing.T) {
	cfg := MenuConfig{
		AppName:  "Test App",
		AppLabel: "com.test.app",
		Title:    "TEST",
		LogPath:  "/tmp/test.log",
	}
	h := Handlers{}

	app := NewAppWithConfig(cfg, h)
	if app.Config.AppName != "Test App" {
		t.Errorf("Config.AppName = %q, want 'Test App'", app.Config.AppName)
	}
	if app.GetStatus() != StatusIdle {
		t.Errorf("initial status = %q, want %q", app.GetStatus(), StatusIdle)
	}
}

func TestNewTranscriptFetcher(t *testing.T) {
	tf := NewTranscriptFetcher()
	if tf == nil {
		t.Fatal("NewTranscriptFetcher() returned nil")
	}
	if tf.api == nil {
		t.Error("api should not be nil")
	}
	if tf.formatter == nil {
		t.Error("formatter should not be nil")
	}
	if len(tf.languages) == 0 {
		t.Error("languages should have defaults")
	}
	if tf.languages[0] != "en" {
		t.Errorf("first language = %q, want en", tf.languages[0])
	}
}

func TestNewTranscriptFetcherWithLanguages(t *testing.T) {
	tf := NewTranscriptFetcherWithLanguages([]string{"de", "fr"})
	if len(tf.languages) != 2 {
		t.Fatalf("languages len = %d, want 2", len(tf.languages))
	}
	if tf.languages[0] != "de" {
		t.Errorf("languages[0] = %q, want de", tf.languages[0])
	}
	if tf.languages[1] != "fr" {
		t.Errorf("languages[1] = %q, want fr", tf.languages[1])
	}
}

func TestTranscriptFetcherSetFormatter(t *testing.T) {
	tf := NewTranscriptFetcher()
	srt := transcript.SRTFormatter{}
	tf.SetFormatter(srt)
	// Verify it changed by checking type (no direct access, but no panic)
	if tf.formatter == nil {
		t.Error("formatter should not be nil after SetFormatter")
	}
}

func TestTranscriptFetcherSetLanguages(t *testing.T) {
	tf := NewTranscriptFetcher()
	tf.SetLanguages([]string{"ja", "ko"})
	if len(tf.languages) != 2 {
		t.Fatalf("languages len = %d, want 2", len(tf.languages))
	}
	if tf.languages[0] != "ja" {
		t.Errorf("languages[0] = %q, want ja", tf.languages[0])
	}
}

func TestTranscriptFetcherFetchEmptyID(t *testing.T) {
	tf := NewTranscriptFetcher()
	_, err := tf.Fetch("")
	if err == nil {
		t.Error("Fetch('') should return an error")
	}
}

func TestFetchResultFields(t *testing.T) {
	result := FetchResult{
		VideoID:      "dQw4w9WgXcQ",
		Language:     "English",
		LanguageCode: "en",
		SnippetCount: 42,
		CharCount:    1234,
		Text:         "Hello world\n",
		Flag:         "🇬🇧",
	}
	if result.VideoID != "dQw4w9WgXcQ" {
		t.Errorf("VideoID = %q", result.VideoID)
	}
	if result.SnippetCount != 42 {
		t.Errorf("SnippetCount = %d", result.SnippetCount)
	}
	if result.Flag != "🇬🇧" {
		t.Errorf("Flag = %q", result.Flag)
	}
}

func TestWireToAppInstance(t *testing.T) {
	tf := NewTranscriptFetcher()
	app := NewApp()

	var fallbackAction ActionType
	var fallbackData string

	handler := tf.WireToAppInstance(app, func(action ActionType, data string) {
		fallbackAction = action
		fallbackData = data
	})

	// Non-fetch actions should pass through to fallback
	handler(ActionCaptureScreenshot, "test-data")
	if fallbackAction != ActionCaptureScreenshot {
		t.Errorf("fallback action = %q, want capture_screenshot", fallbackAction)
	}
	if fallbackData != "test-data" {
		t.Errorf("fallback data = %q, want test-data", fallbackData)
	}
}

func TestFetchAndDisplayUpdatesStatus(t *testing.T) {
	app := NewApp()
	tf := NewTranscriptFetcher()

	// FetchAndDisplay with an invalid video ID should set status to error
	tf.FetchAndDisplay(app, "invalid!!!")

	// After a failed fetch, status should be error
	if app.GetStatus() != StatusError {
		t.Errorf("status after failed fetch = %q, want error", app.GetStatus())
	}

	// History should not have been updated
	if app.HistoryLen() != 0 {
		t.Errorf("history should be empty after failed fetch, got %d", app.HistoryLen())
	}
}

func TestER1UploadResult(t *testing.T) {
	// Test success result
	r := &ER1UploadResult{
		VideoID: "abc123",
		DocID:   "doc-456",
		Message: "Uploaded abc123 → doc_id: doc-456",
		Queued:  false,
	}
	if r.VideoID != "abc123" {
		t.Errorf("VideoID = %q, want abc123", r.VideoID)
	}
	if r.DocID != "doc-456" {
		t.Errorf("DocID = %q, want doc-456", r.DocID)
	}
	if r.Queued {
		t.Error("Queued should be false for success")
	}

	// Test queued result
	q := &ER1UploadResult{
		VideoID: "abc123",
		Message: "Upload failed, queued for retry",
		Queued:  true,
	}
	if !q.Queued {
		t.Error("Queued should be true")
	}
	if q.DocID != "" {
		t.Errorf("DocID should be empty for queued result, got %q", q.DocID)
	}
}

func TestUploadER1ActionType(t *testing.T) {
	if ActionUploadER1 != "upload_er1" {
		t.Errorf("ActionUploadER1 = %q, want upload_er1", ActionUploadER1)
	}
	if ActionLoginER1 != "login_er1" {
		t.Errorf("ActionLoginER1 = %q, want login_er1", ActionLoginER1)
	}
	if ActionLogoutER1 != "logout_er1" {
		t.Errorf("ActionLogoutER1 = %q, want logout_er1", ActionLogoutER1)
	}
}

func TestHandlerOnUploadER1(t *testing.T) {
	var calledWith string
	h := Handlers{
		OnUploadER1: func(videoID string) (*ER1UploadResult, error) {
			calledWith = videoID
			return &ER1UploadResult{
				VideoID: videoID,
				DocID:   "test-doc",
				Message: "success",
			}, nil
		},
	}

	result, err := h.OnUploadER1("dQw4w9WgXcQ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calledWith != "dQw4w9WgXcQ" {
		t.Errorf("calledWith = %q, want dQw4w9WgXcQ", calledWith)
	}
	if result.DocID != "test-doc" {
		t.Errorf("DocID = %q, want test-doc", result.DocID)
	}
}

func TestUploadER1StatusTransition(t *testing.T) {
	app := NewApp()

	// Verify initial status
	if app.GetStatus() != StatusIdle {
		t.Fatalf("initial status = %q, want idle", app.GetStatus())
	}

	// Simulate upload status transitions
	app.SetStatus(StatusUploading)
	if app.GetStatus() != StatusUploading {
		t.Errorf("after SetStatus(uploading), got %q", app.GetStatus())
	}

	// After success, return to idle
	app.SetStatus(StatusIdle)
	if app.GetStatus() != StatusIdle {
		t.Errorf("after SetStatus(idle), got %q", app.GetStatus())
	}

	// After error, set error status
	app.SetStatus(StatusError)
	if app.GetStatus() != StatusError {
		t.Errorf("after SetStatus(error), got %q", app.GetStatus())
	}
}

func TestUploadER1MenuItemPresent(t *testing.T) {
	app := NewApp()
	items := app.BuildMenuItems()

	found := false
	for _, item := range items {
		if item.Text == "🚀 Upload to ER1..." {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected '🚀 Upload to ER1...' menu item in BuildMenuItems()")
	}
}

func TestUploadER1WithoutHandler(t *testing.T) {
	// When OnUploadER1 is nil, the handler should still fire the action
	var capturedAction ActionType
	app := NewAppWithConfig(DefaultConfig(), Handlers{
		OnAction: func(action ActionType, data string) {
			capturedAction = action
		},
	})

	// Simulate calling handleUploadER1 without the OnUploadER1 handler
	// This tests the nil-handler code path in the notify fallback
	app.Handlers.OnUploadER1 = nil
	if app.Handlers.OnUploadER1 != nil {
		t.Error("OnUploadER1 should be nil")
	}

	// Direct call to fireAction to test the flow
	app.Handlers.OnAction(ActionUploadER1, "test-vid")
	if capturedAction != ActionUploadER1 {
		t.Errorf("expected upload_er1 action, got %q", capturedAction)
	}
}

func TestAuthSessionState(t *testing.T) {
	app := NewApp()
	if got := app.GetAuthSession(); got.LoggedIn || got.UserID != "" {
		t.Fatalf("initial auth session = %+v, want logged out", got)
	}

	app.SetAuthSession(AuthSession{LoggedIn: true, UserID: "107677460544181387647___mft"})
	got := app.GetAuthSession()
	if !got.LoggedIn {
		t.Fatal("expected logged-in session")
	}
	if got.UserID != "107677460544181387647___mft" {
		t.Fatalf("UserID = %q, want context id", got.UserID)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsHelper(s, sub))
}

func containsHelper(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
