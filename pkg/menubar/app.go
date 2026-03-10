// app.go — menuet-based macOS menu bar application runner.
//
// This file depends on github.com/caseymrm/menuet and must be built
// on macOS (darwin) with cgo enabled.
package menubar

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/caseymrm/menuet"
)

// App holds the runtime state of the menu bar application with
// thread-safe access to mutable fields (status, history).
type App struct {
	Config   MenuConfig
	Handlers Handlers
	history  HistoryStore

	mu     sync.Mutex
	status Status
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
	items := []menuet.MenuItem{
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
		{
			Text:    "🚀 Upload to ER1...",
			Clicked: a.handleUploadER1,
		},
		{Type: menuet.Separator},
		{Text: fmt.Sprintf("Status: %s", a.GetStatus())},
		{Type: menuet.Separator},
	}

	items = append(items, a.buildHistoryMenu())

	// menuet automatically appends "Start at Login" and "Quit" items,
	// so we do not add our own Quit here.
	items = append(items,
		menuet.MenuItem{Type: menuet.Separator},
		menuet.MenuItem{
			Text: "Open Log File",
			Clicked: func() {
				exec.Command("open", a.Config.LogPath).Run()
				a.fireAction(ActionOpenLog, a.Config.LogPath)
			},
		},
	)

	return items
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

// handleUploadER1 prompts for a video ID and triggers the ER1 upload workflow.
// The upload runs in a goroutine so the menu remains responsive.
func (a *App) handleUploadER1() {
	if a.Handlers.OnUploadER1 == nil {
		a.notify("ER1 Upload", "Upload handler not configured")
		a.fireAction(ActionUploadER1, "")
		return
	}

	suggested := SuggestedYouTubeVideoID()
	input := "Paste YouTube video ID or URL"
	info := "Enter a YouTube video ID or URL to fetch transcript and upload:"
	if suggested != "" {
		info = fmt.Sprintf("Enter a YouTube video ID or URL to fetch transcript and upload:\n\nDetected from Chrome: %s\nLeave field empty to use detected ID.", suggested)
	}

	response := menuet.App().Alert(menuet.Alert{
		MessageText:     "Upload to ER1",
		InformativeText: info,
		Buttons:         []string{"Upload", "Cancel"},
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
	a.SetStatus(StatusUploading)
	a.notify("ER1 Upload", fmt.Sprintf("Uploading %s to ER1...", videoID))
	a.fireAction(ActionUploadER1, videoID)

	go func() {
		result, err := a.Handlers.OnUploadER1(videoID)
		if err != nil {
			a.SetStatus(StatusError)
			a.notify("ER1 Upload Failed", fmt.Sprintf("Error: %v", err))
			return
		}

		if result.Queued {
			a.SetStatus(StatusIdle)
			a.notify("ER1 Queued", result.Message)
		} else {
			a.SetStatus(StatusIdle)
			a.notify("ER1 Upload Complete", result.Message)
		}
		a.AddHistory(NewHistoryEntry(result.VideoID, "🚀"))
	}()
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
