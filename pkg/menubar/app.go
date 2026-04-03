//go:build darwin

// app.go — menuet-based macOS menu bar application runner.
//
// This file depends on github.com/caseymrm/menuet and must be built
// on macOS (darwin) with cgo enabled.
package menubar

import (
	"fmt"
	"os/exec"
	"os"
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

	// Register menu item icons from design system.
	a.registerMenuIcons()

	mApp.RunApplication()
}

// Menu item icon names (registered with NSImage).
const (
	iconLogout      = "m3c-logout"
	iconTranscript  = "m3c-transcript"
	iconScreenshot  = "m3c-screenshot"
	iconImpulse     = "m3c-quick-impulse"
	iconAudioImport = "m3c-audio-import"
	iconTrackingDB  = "m3c-tracking-db"
	iconSync        = "m3c-sync"
	iconProjects    = "m3c-projects"
	iconHistory     = "m3c-history"
	iconLogFile     = "m3c-log-file"
	iconUser        = "m3c-user-account"
	iconStar        = "m3c-star"
)

// registerMenuIcons loads design-system PNGs as NSImage template images.
func (a *App) registerMenuIcons() {
	icons := map[string]string{
		iconLogout:      "menu-logout.png",
		iconTranscript:  "menu-transcript.png",
		iconScreenshot:  "menu-screenshot.png",
		iconImpulse:     "menu-quick-impulse.png",
		iconAudioImport: "menu-audio-import.png",
		iconTrackingDB:  "menu-tracking-db.png",
		iconSync:        "menu-sync.png",
		iconProjects:    "menu-projects.png",
		iconHistory:     "menu-history.png",
		iconLogFile:     "menu-log-file.png",
		iconUser:        "menu-user-account.png",
		iconStar:        "menu-star.png",
	}
	for name, file := range icons {
		path := FindIcon(file)
		if path != "" {
			RegisterImage(name, path)
		}
	}
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
			a.buildSignInMenu(),
			a.buildProfileMenu(),
			{Type: menuet.Separator},
			{
				Text:  "Star on GitHub",
				Image: iconStar,
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
			Text:  "Sign Out",
			Image: iconLogout,
			Clicked: func() {
				a.fireAction(ActionLogoutER1, "")
			},
		},
		a.buildProfileMenu(),
		{Type: menuet.Separator},
		{
			Text:    "Fetch Transcript...",
			Image:   iconTranscript,
			Clicked: a.handleFetchTranscript,
		},
		{Type: menuet.Separator},
		{
			Text:  "Capture Screenshot...",
			Image: iconScreenshot,
			Clicked: func() {
				a.fireAction(ActionCaptureScreenshot, "")
			},
		},
		{
			Text:  "Quick Impulse",
			Image: iconImpulse,
			Clicked: func() {
				a.fireAction(ActionQuickImpulse, "")
			},
		},
		{Type: menuet.Separator},
		a.buildAudioImportMenu(),
		{
			Text:  "Audio Recording Tracking DB",
			Image: iconTrackingDB,
			Clicked: func() {
				a.fireAction(ActionShowTrackingDB, "")
			},
		},
		{Type: menuet.Separator},
		{
			Text:  "Plaud Sync",
			Image: iconSync,
			Clicked: func() {
				a.fireAction(ActionPlaudSync, "")
			},
		},
		{
			Text:  pocketMenuLabel(),
			Image: iconAudioImport,
			Clicked: func() {
				a.fireAction(ActionPocketSync, "")
			},
		},
		{Type: menuet.Separator},
		a.buildProjectsMenu(),
		{Type: menuet.Separator},
	}

	items = append(items, a.buildHistoryMenu())

	// menuet automatically appends "Start at Login" and "Quit" items,
	// so we do not add our own Quit here.
	profURL := profileURL()
	items = append(items,
		menuet.MenuItem{Type: menuet.Separator},
		menuet.MenuItem{
			Text:  "Open Log File",
			Image: iconLogFile,
			Clicked: func() {
				exec.Command("open", a.Config.LogPath).Run()
				a.fireAction(ActionOpenLog, a.Config.LogPath)
			},
		},
		menuet.MenuItem{Type: menuet.Separator},
		menuet.MenuItem{
			Text:  "Mein Nutzerkonto",
			Image: iconUser,
			Children: func() []menuet.MenuItem {
				return []menuet.MenuItem{
					{Text: accountText},
					{Text: fmt.Sprintf("Status: %s", a.GetStatus())},
					{Type: menuet.Separator},
					{
						Text: "Open Profile",
						Clicked: func() {
							_ = exec.Command("open", "-a", "Google Chrome", profURL).Start()
						},
					},
				}
			},
		},
		menuet.MenuItem{
			Text:  "Star on GitHub",
			Image: iconStar,
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
	title := "Audio Import"
	if newCount > 0 {
		title = fmt.Sprintf("Audio Import (%d new)", newCount)
	}
	return menuet.MenuItem{
		Text:  title,
		Image: iconAudioImport,
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
					Text: "Run Import Pipeline",
					Clicked: func() {
						a.fireAction(ActionBatchImport, "__run_all__")
					},
				},
				{
					Text: "Refresh list",
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
					label = "[locked] " + label
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

// observationIcon returns the menu icon constant for an observation type.
func observationIcon(obsType string) string {
	switch obsType {
	case "plaud":
		return iconSync
	case "audio":
		return iconAudioImport
	case "transcript":
		return iconTranscript
	case "screenshot":
		return iconScreenshot
	case "impulse":
		return iconImpulse
	default:
		return iconTrackingDB
	}
}

// observationLabel returns a human-readable type label.
func observationLabel(obsType string) string {
	switch obsType {
	case "plaud":
		return "Plaud"
	case "audio":
		return "Audio"
	case "transcript":
		return "Transcript"
	case "screenshot":
		return "Screenshot"
	case "impulse":
		return "Impulse"
	default:
		return obsType
	}
}

// dateGroup returns a relative date label for grouping.
func dateGroup(t time.Time) string {
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	yesterday := today.AddDate(0, 0, -1)
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())

	switch {
	case day.Equal(today):
		return "Today"
	case day.Equal(yesterday):
		return "Yesterday"
	case day.After(today.AddDate(0, 0, -7)):
		return t.Weekday().String()
	default:
		return t.Format("Jan 2")
	}
}

// buildHistoryMenu creates the unified "History (N)" submenu from the
// tracking DB, showing recent observations across all types grouped by date.
func (a *App) buildHistoryMenu() menuet.MenuItem {
	// Try persistent observations first, fall back to in-memory history.
	if a.Handlers.ListRecentObservations != nil {
		observations, err := a.Handlers.ListRecentObservations(20)
		if err == nil && len(observations) > 0 {
			return a.buildObservationHistoryMenu(observations)
		}
	}

	// Fallback: in-memory session history (transcript fetches only).
	entries := a.GetHistory()
	return menuet.MenuItem{
		Text:  fmt.Sprintf("History (%d)", len(entries)),
		Image: iconHistory,
		Children: func() []menuet.MenuItem {
			if len(entries) == 0 {
				return []menuet.MenuItem{{Text: "(empty)"}}
			}
			var items []menuet.MenuItem
			for _, h := range entries {
				entry := h
				items = append(items, menuet.MenuItem{
					Text: entry.Label,
					Children: func() []menuet.MenuItem {
						return []menuet.MenuItem{
							{
								Text: "Copy Transcript",
								Clicked: func() {
									CopyToClipboard("Transcript for " + entry.VideoID)
									a.fireAction(ActionCopyTranscript, entry.VideoID)
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

// buildObservationHistoryMenu builds the history menu from persistent observations.
func (a *App) buildObservationHistoryMenu(observations []Observation) menuet.MenuItem {
	return menuet.MenuItem{
		Text:  fmt.Sprintf("History (%d)", len(observations)),
		Image: iconHistory,
		Children: func() []menuet.MenuItem {
			var items []menuet.MenuItem
			lastGroup := ""

			er1Cfg := er1.LoadConfig()
			baseURL := strings.TrimSuffix(er1Cfg.APIURL, "/upload_2")
			contextID := er1Cfg.ContextID

			for _, obs := range observations {
				o := obs // capture

				// Date group header.
				group := dateGroup(o.ProcessedAt)
				if group != lastGroup {
					if lastGroup != "" {
						items = append(items, menuet.MenuItem{Type: menuet.Separator})
					}
					items = append(items, menuet.MenuItem{Text: group})
					lastGroup = group
				}

				// Truncate title for menu display.
				title := o.Title
				if len(title) > 45 {
					title = title[:42] + "..."
				}
				label := fmt.Sprintf("%s  %s", title, o.ProcessedAt.Format("15:04"))
				typeLabel := observationLabel(o.Type)

				// Build per-entry submenu.
				entry := menuet.MenuItem{
					Text:  label,
					Image: observationIcon(o.Type),
				}

				if o.DocID != "" {
					docURL := baseURL + "/memory/" + contextID + "/" + o.DocID + "/view"
					entry.Children = func() []menuet.MenuItem {
						sub := []menuet.MenuItem{
							{Text: fmt.Sprintf("Type: %s", typeLabel)},
							{Text: fmt.Sprintf("Status: %s", o.Status)},
							{Type: menuet.Separator},
							{
								Text: "Open in Browser",
								Clicked: func() {
									_ = exec.Command("open", docURL).Start()
								},
							},
						}
						return sub
					}
				}

				items = append(items, entry)
			}

			// Footer: link to full dashboard.
			items = append(items,
				menuet.MenuItem{Type: menuet.Separator},
				menuet.MenuItem{
					Text: "Open Dashboard...",
					Clicked: func() {
						url := baseURL + "/v2/my-personal-assistant"
						_ = exec.Command("open", url).Start()
					},
				},
			)

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
		MessageText: "Transcript in Clipboard",
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

// buildSignInMenu creates the Sign In menu item. If multiple profiles exist,
// shows a submenu letting the user pick which profile to sign into.
func (a *App) buildSignInMenu() menuet.MenuItem {
	// Check if we have multiple profiles to offer a choice.
	if a.Handlers.ListProfiles != nil {
		profiles, _, err := a.Handlers.ListProfiles()
		if err == nil && len(profiles) > 1 {
			return menuet.MenuItem{
				Text:  "Sign In...",
				Image: iconUser,
				Children: func() []menuet.MenuItem {
					var items []menuet.MenuItem
					for _, p := range profiles {
						prof := p
						label := prof.Name
						if prof.Description != "" {
							label = fmt.Sprintf("%s (%s)", prof.Name, prof.Description)
						}
						if prof.IsActive {
							label = "* " + label
						}
						items = append(items, menuet.MenuItem{
							Text: label,
							Clicked: func() {
								// Switch profile first, then trigger login.
								if !prof.IsActive && a.Handlers.SwitchProfile != nil {
									_ = a.Handlers.SwitchProfile(prof.Name)
								}
								a.fireAction(ActionLoginER1, "")
							},
						})
					}
					return items
				},
			}
		}
	}

	// Single profile or no profiles — simple Sign In button.
	return menuet.MenuItem{
		Text:  "Sign In...",
		Image: iconUser,
		Clicked: func() {
			a.fireAction(ActionLoginER1, "")
		},
	}
}

// buildProfileMenu constructs the "Profile Settings" submenu for config profile switching.
func (a *App) buildProfileMenu() menuet.MenuItem {
	if a.Handlers.ListProfiles == nil {
		return menuet.MenuItem{
			Text: "Profile Settings",
		}
	}

	profiles, activeName, err := a.Handlers.ListProfiles()
	if err != nil || len(profiles) == 0 {
		return menuet.MenuItem{
			Text: "Profile Settings",
		}
	}

	return menuet.MenuItem{
		Text: "Profile Settings",
		Children: func() []menuet.MenuItem {
			items := []menuet.MenuItem{
				{Text: fmt.Sprintf("Active: %s", activeName)},
				{Type: menuet.Separator},
			}
			for _, p := range profiles {
				prof := p // capture
				label := prof.Name
				if prof.Description != "" {
					label = fmt.Sprintf("%s — %s", prof.Name, prof.Description)
				}
				if prof.IsActive {
					label = "* " + label
				}
				items = append(items, menuet.MenuItem{
					Text: label,
					Clicked: func() {
						if a.Handlers.SwitchProfile != nil && !prof.IsActive {
							if switchErr := a.Handlers.SwitchProfile(prof.Name); switchErr != nil {
								a.notify("Profile Error", fmt.Sprintf("Failed to switch: %v", switchErr))
							} else {
								a.notify("Profile Switched", fmt.Sprintf("Now using: %s", prof.Name))
							}
						}
					},
				})
			}
			items = append(items,
				menuet.MenuItem{Type: menuet.Separator},
				menuet.MenuItem{
					Text: "Edit Profiles...",
					Clicked: func() {
						if a.Handlers.OpenProfileEditor != nil {
							a.Handlers.OpenProfileEditor()
						} else {
							// Fallback: open profiles directory in Finder.
							home, _ := os.UserHomeDir()
							_ = exec.Command("open", filepath.Join(home, ".m3c-tools", "profiles")).Start()
						}
					},
				},
				menuet.MenuItem{
					Text: "Reload Config",
					Clicked: func() {
						if a.Handlers.SwitchProfile != nil && activeName != "" {
							if switchErr := a.Handlers.SwitchProfile(activeName); switchErr != nil {
								a.notify("Config Reload Error", fmt.Sprintf("Failed: %v", switchErr))
							} else {
								a.notify("Config Reloaded", fmt.Sprintf("Profile: %s", activeName))
							}
						}
					},
				},
			)
			return items
		},
	}
}

// ShowNotification sends a macOS notification via menuet.
func ShowNotification(title, message string) {
	menuet.App().Notification(menuet.Notification{
		Title:   title,
		Message: message,
	})
}
