// app.go — menuet-based macOS menu bar application runner.
//
// This file depends on github.com/caseymrm/menuet and must be built
// on macOS (darwin) with cgo enabled.
package menubar

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caseymrm/menuet"
	"github.com/kamir/m3c-tools/pkg/er1"
)

// App holds the runtime state of the menu bar application with
// thread-safe access to mutable fields (status, history).
type App struct {
	Config   MenuConfig
	Handlers Handlers
	history  HistoryStore

	mu             sync.Mutex
	status         Status
	authSession    AuthSession
	importState    AudioImportState
	lastImportMsg  string
	bulkRunState   BulkRunState
	plaudSyncState PlaudSyncState

	// Time tracking (set via SetTimeEngine after login).
	timeEngine      TimeTrackingEngine
	showTimeTracker func()

	// Shutdown callbacks run on app termination.
	shutdownFns []func()
}

// AuthSession captures runtime ER1 login state used by the menu.
type AuthSession struct {
	LoggedIn bool
	UserID   string
}

// PlaudSyncState holds the current Plaud sync snapshot for menu rendering.
type PlaudSyncState struct {
	Items     []PlaudSyncRecord
	UpdatedAt time.Time
	Error     string
}

// AudioImportItem represents one source audio file shown in the menubar list.
type AudioImportItem struct {
	Path   string
	Name   string
	Status string
	Size   int64
	Tags   string
}

// TrackingRecord is a lightweight view of a processed_files row for menu display.
type TrackingRecord struct {
	FileName       string
	Status         string
	TranscriptLen  int
	TranscriptLang string
	UploadDocID    string
	UploadError    string
	ProcessedAt    string
}

// AudioImportState holds the current import-list snapshot for menu rendering.
type AudioImportState struct {
	Items     []AudioImportItem
	UpdatedAt time.Time
	Error     string
}

// NewApp creates an App with the default config and idle status.
func NewApp() *App {
	return &App{
		Config: DefaultConfig(),
		status: StatusIdle,
	}
}

// NewAppWithConfig creates an App with the given config and handlers.
func NewAppWithConfig(cfg MenuConfig, h Handlers) *App {
	return &App{
		Config:   cfg,
		Handlers: h,
		status:   StatusIdle,
	}
}

// SetStatus updates the displayed status. Safe for concurrent use.
func (a *App) SetStatus(s Status) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status = s
}

// GetStatus returns the current status.
func (a *App) GetStatus() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.status
}

// SetAuthSession updates the runtime ER1 auth session displayed in the menu.
func (a *App) SetAuthSession(s AuthSession) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.authSession = s
}

// GetAuthSession returns the current ER1 auth session snapshot.
func (a *App) GetAuthSession() AuthSession {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.authSession
}

// SetAudioImportState updates the current import-list snapshot for the menu.
func (a *App) SetAudioImportState(s AudioImportState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.importState = s
}

// GetAudioImportState returns the current import-list snapshot.
func (a *App) GetAudioImportState() AudioImportState {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.importState
	if len(out.Items) > 0 {
		items := make([]AudioImportItem, len(out.Items))
		copy(items, out.Items)
		out.Items = items
	}
	return out
}

// SetLastImportMessage stores a short status message shown in the import menu.
func (a *App) SetLastImportMessage(msg string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastImportMsg = msg
}

// GetLastImportMessage returns the last import status message.
func (a *App) GetLastImportMessage() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastImportMsg
}

// SetPlaudSyncState updates the current Plaud sync snapshot for the menu.
func (a *App) SetPlaudSyncState(s PlaudSyncState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.plaudSyncState = s
}

// GetPlaudSyncState returns the current Plaud sync snapshot.
func (a *App) GetPlaudSyncState() PlaudSyncState {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.plaudSyncState
	if len(out.Items) > 0 {
		items := make([]PlaudSyncRecord, len(out.Items))
		copy(items, out.Items)
		out.Items = items
	}
	return out
}

// SetBulkRunState updates the current live bulk-run state for UI rendering.
func (a *App) SetBulkRunState(s BulkRunState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.bulkRunState = s
}

// GetBulkRunState returns the current bulk-run state snapshot.
func (a *App) GetBulkRunState() BulkRunState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.bulkRunState
}

// AddHistory appends an entry to the transcript history.
func (a *App) AddHistory(entry HistoryEntry) {
	a.history.Add(entry)
}

// GetHistory returns a snapshot of the current history entries.
func (a *App) GetHistory() []HistoryEntry {
	return a.history.All()
}

// HistoryLen returns the number of history entries.
func (a *App) HistoryLen() int {
	return a.history.Len()
}

// ClearHistory removes all history entries.
func (a *App) ClearHistory() {
	a.history.Clear()
}

// SetShowTimeTrackerFunc registers the callback invoked when the user
// clicks "Show Time Tracker..." in the Projects menu.
func (a *App) SetShowTimeTrackerFunc(fn func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.showTimeTracker = fn
}

// getShowTimeTracker returns the registered show-time-tracker callback.
func (a *App) getShowTimeTracker() func() {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.showTimeTracker
}

// OnShutdown registers a callback to be run when the app terminates.
func (a *App) OnShutdown(fn func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.shutdownFns = append(a.shutdownFns, fn)
}

// RunShutdown executes all registered shutdown callbacks.
func (a *App) RunShutdown() {
	a.mu.Lock()
	fns := a.shutdownFns
	a.shutdownFns = nil
	a.mu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

// Run configures the menuet application and starts the macOS run loop.
// This function blocks forever and must be called from the main goroutine.
func (a *App) Run() {
	mApp := menuet.App()
	mApp.Name = a.Config.AppName
	mApp.Label = a.Config.AppLabel
	mApp.Children = a.buildMenuItems

	// Register the icon file with NSImage so menuet can find it by name.
	state := &menuet.MenuState{Title: a.Config.Title}
	if a.Config.IconPath != "" {
		const iconName = "m3c-menubar-icon"
		if RegisterImage(iconName, a.Config.IconPath) {
			state.Image = iconName
		}
		// Also set the NSApp icon for Cmd+Tab/Dock when we temporarily switch
		// to regular app mode while showing the Observation window.
		_ = SetApplicationIcon(a.Config.IconPath)
	}
	mApp.SetMenuState(state)

	mApp.RunApplication()
}

// BuildMenuItems returns the current menu item tree. Exported for testing
// and inspection without starting the full run loop.
func (a *App) BuildMenuItems() []menuet.MenuItem {
	return a.buildMenuItems()
}

// buildMenuItems constructs the dropdown menu. menuet calls this every
// time the user opens the dropdown.
func (a *App) buildMenuItems() []menuet.MenuItem {
	auth := a.GetAuthSession()
	if !auth.LoggedIn {
		return []menuet.MenuItem{
			{
				Text: "🔐 Login to ER1...",
				Clicked: func() {
					a.fireAction(ActionLoginER1, "")
				},
			},
			{Type: menuet.Separator},
			{
				Text: "⭐ Star on GitHub",
				Clicked: func() {
					_ = exec.Command("open", GitHubRepoURL).Start()
					a.fireAction(ActionStarGitHub, GitHubRepoURL)
				},
			},
		}
	}
	accountText := fmt.Sprintf("Account: %s", auth.UserID)

	items := []menuet.MenuItem{
		{
			Text: "🔓 Logout from ER1",
			Clicked: func() {
				a.fireAction(ActionLogoutER1, "")
			},
		},
		{Type: menuet.Separator},
		{
			Text:    "▶️ Fetch Transcript...",
			Clicked: a.handleFetchTranscript,
		},
		{
			Text: "📷 Capture Screenshot...",
			Clicked: func() {
				a.fireAction(ActionCaptureScreenshot, "")
			},
		},
		{
			Text: "⚡ Quick Impulse",
			Clicked: func() {
				a.fireAction(ActionQuickImpulse, "")
			},
		},
		a.buildAudioImportMenu(),
		{
			Text: "📋 Audio Recording Tracking DB",
			Clicked: func() {
				a.fireAction(ActionShowTrackingDB, "")
			},
		},
		{
			Text: "📝 Plaud Sync",
			Clicked: func() {
				a.fireAction(ActionPlaudSync, "")
			},
		},
		{Type: menuet.Separator},
		a.buildProjectsMenu(),
		{Type: menuet.Separator},
		{Text: fmt.Sprintf("Status: %s", a.GetStatus())},
		{Text: accountText},
		{Type: menuet.Separator},
	}

	items = append(items, a.buildHistoryMenu())

	// menuet automatically appends "Start at Login" and "Quit" items,
	// so we do not add our own Quit here.
	profURL := profileURL()
	items = append(items,
		menuet.MenuItem{Type: menuet.Separator},
		menuet.MenuItem{
			Text: "Open Log File",
			Clicked: func() {
				exec.Command("open", a.Config.LogPath).Run()
				a.fireAction(ActionOpenLog, a.Config.LogPath)
			},
		},
		menuet.MenuItem{Type: menuet.Separator},
		menuet.MenuItem{
			Text: "👤 Mein Nutzerkonto",
			Clicked: func() {
				_ = exec.Command("open", "-a", "Google Chrome", profURL).Start()
			},
		},
		menuet.MenuItem{
			Text: "⭐ Star on GitHub",
			Clicked: func() {
				_ = exec.Command("open", GitHubRepoURL).Start()
				a.fireAction(ActionStarGitHub, GitHubRepoURL)
			},
		},
		menuet.MenuItem{Type: menuet.Separator},
	)

	return items
}

func (a *App) buildAudioImportMenu() menuet.MenuItem {
	state := a.GetAudioImportState()
	bulk := a.GetBulkRunState()
	newCount := 0
	for _, it := range state.Items {
		if strings.EqualFold(strings.TrimSpace(it.Status), "new") {
			newCount++
		}
	}
	title := "🎵 Audio Import"
	if newCount > 0 {
		title = fmt.Sprintf("🎵 Audio Import (%d new)", newCount)
	}
	return menuet.MenuItem{
		Text: title,
		Children: func() []menuet.MenuItem {
			var items []menuet.MenuItem
			if bulk.Active {
				elapsed := time.Since(bulk.StartedAt).Round(time.Second)
				runLine := fmt.Sprintf("⏳ Running %d/%d (ok=%d fail=%d) [%s]",
					bulk.Done, bulk.Total, bulk.Success, bulk.Failed, elapsed)
				items = append(items, menuet.MenuItem{Text: runLine})
				if bulk.CurrentFile != "" {
					items = append(items, menuet.MenuItem{Text: "File: " + filepath.Base(bulk.CurrentFile)})
				}
				if bulk.Phase != "" {
					items = append(items, menuet.MenuItem{Text: "Phase: " + string(bulk.Phase)})
				}
				if bulk.LastError != "" {
					items = append(items, menuet.MenuItem{Text: "⚠️ " + bulk.LastError})
				}
				items = append(items, menuet.MenuItem{Type: menuet.Separator})
			}
			items = append(items, []menuet.MenuItem{
				{
					Text: "▶️ Run Import Pipeline",
					Clicked: func() {
						a.fireAction(ActionBatchImport, "__run_all__")
					},
				},
				{
					Text: "🔄 Refresh list",
					Clicked: func() {
						a.fireAction(ActionBatchImport, "__refresh__")
					},
				},
				{Type: menuet.Separator},
			}...)

			if state.UpdatedAt.IsZero() {
				items = append(items, menuet.MenuItem{Text: "Updated: (not yet)"})
			} else {
				items = append(items, menuet.MenuItem{Text: "Updated: " + state.UpdatedAt.Format("15:04:05")})
			}
			if state.Error != "" {
				items = append(items, menuet.MenuItem{Text: "⚠️ " + state.Error})
			}
			if msg := a.GetLastImportMessage(); msg != "" {
				items = append(items, menuet.MenuItem{Text: msg})
			}
			items = append(items, menuet.MenuItem{Type: menuet.Separator})

			// Show only untracked ("new") files — already imported files are hidden.
			var newItems []AudioImportItem
			for _, it := range state.Items {
				if strings.EqualFold(strings.TrimSpace(it.Status), "new") {
					newItems = append(newItems, it)
				}
			}

			if len(newItems) == 0 {
				items = append(items, menuet.MenuItem{Text: "(no new audio files)"})
				return items
			}

			limit := len(newItems)
			if limit > 25 {
				limit = 25
			}
			for i := 0; i < limit; i++ {
				it := newItems[i]
				filePath := it.Path
				label := filepath.Base(it.Name)
				if bulk.Active {
					label = "🔒 " + label
				}
				items = append(items, menuet.MenuItem{
					Text: label,
					Clicked: func() {
						a.fireAction(ActionBatchImport, filePath)
					},
				})
			}
			if len(newItems) > limit {
				items = append(items, menuet.MenuItem{Text: fmt.Sprintf("… %d more files", len(newItems)-limit)})
			}
			return items
		},
	}
}

// buildHistoryMenu creates the expandable "History (N)" submenu with
// per-entry actions for copying transcripts and recording impressions.
func (a *App) buildHistoryMenu() menuet.MenuItem {
	entries := a.GetHistory()
	return menuet.MenuItem{
		Text: fmt.Sprintf("History (%d)", len(entries)),
		Children: func() []menuet.MenuItem {
			if len(entries) == 0 {
				return []menuet.MenuItem{{Text: "(empty)"}}
			}
			var items []menuet.MenuItem
			for _, h := range entries {
				entry := h // capture for closure
				items = append(items, menuet.MenuItem{
					Text: entry.Label,
					Children: func() []menuet.MenuItem {
						return []menuet.MenuItem{
							{
								Text: "📋 Copy Transcript",
								Clicked: func() {
									CopyToClipboard("Transcript for " + entry.VideoID)
									a.fireAction(ActionCopyTranscript, entry.VideoID)
								},
							},
							{
								Text: "🎤 Record Impression",
								Clicked: func() {
									a.notify("Record", "Would record impression for "+entry.VideoID)
									a.fireAction(ActionRecordImpression, entry.VideoID)
								},
							},
						}
					},
				})
			}
			return items
		},
	}
}

// handleFetchTranscript shows the video ID alert dialog, cleans the input,
// and delegates to the OnAction handler. If no handler is set, it shows
// a notification and adds a placeholder history entry.
func (a *App) handleFetchTranscript() {
	suggested := SuggestedYouTubeVideoID()
	input := "Paste YouTube video ID or URL"
	info := "Enter a YouTube video ID or URL:"
	if suggested != "" {
		info = fmt.Sprintf("Enter a YouTube video ID or URL:\n\nDetected from Chrome: %s\nLeave field empty to use detected ID.", suggested)
	}

	response := menuet.App().Alert(menuet.Alert{
		MessageText:     "YouTube Transcript Grabber",
		InformativeText: info,
		Buttons:         []string{"Fetch", "Cancel"},
		Inputs:          []string{input},
	})

	if response.Button != 0 { // Cancel
		return
	}

	videoID := strings.TrimSpace(firstInput(response.Inputs))
	if videoID == "" && suggested != "" {
		videoID = suggested
	}
	if videoID == "" {
		menuet.App().Alert(menuet.Alert{
			MessageText: "No video ID entered.",
			Buttons:     []string{"OK"},
		})
		return
	}

	videoID = CleanVideoID(videoID)

	if a.Handlers.OnAction != nil {
		a.Handlers.OnAction(ActionFetchTranscript, videoID)
		return
	}

	// Default POC behavior when no handler is registered
	a.notify("Fetching...", fmt.Sprintf("Fetching transcript for %s", videoID))
	a.AddHistory(NewHistoryEntry(videoID, "🇬🇧"))
}

func firstInput(inputs []string) string {
	if len(inputs) == 0 {
		return ""
	}
	return inputs[0]
}

// ShowTranscriptResult displays a post-fetch confirmation alert. Returns
// true if the user chose "Close" (keep clipboard), false for "Trash".
func (a *App) ShowTranscriptResult(videoID string, snippets, chars int) bool {
	result := menuet.App().Alert(menuet.Alert{
		MessageText: "📋 Transcript in Clipboard",
		InformativeText: fmt.Sprintf(
			"Video: %s\n%d snippets, %d chars\n\nClose to keep clipboard content,\nor trash to clear it.",
			videoID, snippets, chars,
		),
		Buttons: []string{"Close", "🗑 Trash"},
	})
	if result.Button == 1 { // Trash
		CopyToClipboard("")
		a.notify("Cleared", "Clipboard cleared")
		return false
	}
	return true
}

// ConfirmRecording shows a dialog asking the user whether to record a voice
// note. Returns true if the user chose to record, false to skip.
func (a *App) ConfirmRecording() bool {
	result := menuet.App().Alert(menuet.Alert{
		MessageText:     "🎤 Record Voice Note",
		InformativeText: "Click Record to start capturing a voice note.\nYou can stop recording at any time.\n\nThe recording will be transcribed and included in the upload.",
		Buttons:         []string{"Record", "Skip"},
	})
	return result.Button == 0 // Record
}

// ShowStopRecording shows a blocking "Stop Recording" dialog.
// Call this while recording runs in a separate goroutine. When the user
// clicks "Stop", this method returns. The caller should then signal
// the recorder to stop.
func (a *App) ShowStopRecording() {
	menuet.App().Alert(menuet.Alert{
		MessageText:     "🎤 Recording...",
		InformativeText: "Speak now. Click Stop when you are done.",
		Buttons:         []string{"🛑 Stop Recording"},
	})
}

// ShowRecordingDetails displays a dialog with recording file details.
// The user clicks "Continue" to proceed with transcription.
func (a *App) ShowRecordingDetails(details string) {
	menuet.App().Alert(menuet.Alert{
		MessageText:     "🎤 Recording Complete",
		InformativeText: details,
		Buttons:         []string{"Continue to Transcribe"},
	})
}

// Notify sends a user-visible notification (exported wrapper).
func (a *App) Notify(title, message string) {
	a.notify(title, message)
}

// notify sends a notification, using the Handlers.Notify callback if set,
// or falling back to menuet.Notification.
func (a *App) notify(title, message string) {
	if a.Handlers.Notify != nil {
		a.Handlers.Notify(title, message)
		return
	}
	ShowNotification(title, message)
}

// profileURL returns the ER1 user profile URL derived from the API URL.
// Pattern: <base>/v2/profile (e.g. https://127.0.0.1:8081/v2/profile).
func profileURL() string {
	cfg := er1.LoadConfig()
	base := strings.TrimSuffix(cfg.APIURL, "/upload_2")
	base = strings.TrimSuffix(base, "/")
	if base == "" {
		return "https://127.0.0.1:8081/v2/profile"
	}
	return base + "/v2/profile"
}

// fireAction invokes the OnAction handler if set.
func (a *App) fireAction(action ActionType, data string) {
	if a.Handlers.OnAction != nil {
		a.Handlers.OnAction(action, data)
	}
}

// ShowNotification sends a macOS notification via menuet.
func ShowNotification(title, message string) {
	menuet.App().Notification(menuet.Notification{
		Title:   title,
		Message: message,
	})
}
