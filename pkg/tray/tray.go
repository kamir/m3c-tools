// tray.go — Cross-platform system tray app using fyne.io/systray.
//
// This file builds on Windows and Linux (!darwin). On macOS, the menuet-based
// pkg/menubar is used instead; see tray_darwin.go for the compile stub.
//
//go:build !darwin

package tray

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"fyne.io/systray"
)

//go:embed icon.png
var iconBytes []byte

// GitHubRepoURL is the project's GitHub repository URL.
const GitHubRepoURL = "https://github.com/kamir/m3c-tools"

// ActionType identifies the kind of menu action triggered by the user.
type ActionType string

const (
	ActionFetchTranscript ActionType = "fetch_transcript"
	ActionQuickImpulse    ActionType = "quick_impulse"
	ActionPlaudSync       ActionType = "plaud_sync"
	ActionPocketSync      ActionType = "pocket_sync"
	ActionOpenLog         ActionType = "open_log"
	ActionStarGitHub      ActionType = "star_github"
	ActionQuit            ActionType = "quit"
)

// Profile represents a configuration profile shown in the tray submenu.
type Profile struct {
	Name        string
	Description string
	IsActive    bool
}

// Observation represents a unified timeline entry from the tracking DB.
type Observation struct {
	Title       string
	Type        string
	ProcessedAt string
}

// TrayHandlers groups the callback functions that the tray app invokes
// in response to user interactions. Each field is optional; nil callbacks
// are treated as no-ops.
type TrayHandlers struct {
	// OnAction is called for every menu action.
	OnAction func(action ActionType, data string)

	// ListProfiles returns available config profiles for the Profile submenu.
	// Returns profiles, active profile name, and any error.
	ListProfiles func() ([]Profile, string, error)

	// SwitchProfile switches to the named profile and reloads config.
	SwitchProfile func(name string) error

	// OpenProfileEditor launches the local web-based profile settings editor.
	OpenProfileEditor func()

	// ListRecentObs returns recent observations for the History submenu.
	ListRecentObs func(limit int) ([]Observation, error)
}

// TrayApp holds the runtime state of the system tray application.
type TrayApp struct {
	Handlers    TrayHandlers
	loggedIn    bool
	userName    string
	profileName string
	logPath     string
}

// New creates a TrayApp with the given handlers.
func New(h TrayHandlers) *TrayApp {
	home, _ := os.UserHomeDir()
	return &TrayApp{
		Handlers: h,
		logPath:  filepath.Join(home, ".m3c-tools", "m3c-tools.log"),
	}
}

// SetLoggedIn updates the login state displayed in the tray.
func (t *TrayApp) SetLoggedIn(loggedIn bool, userName string) {
	t.loggedIn = loggedIn
	t.userName = userName
}

// SetProfile updates the current profile name.
func (t *TrayApp) SetProfile(name string) {
	t.profileName = name
}

// SetLogPath overrides the default log file path.
func (t *TrayApp) SetLogPath(path string) {
	t.logPath = path
}

// Run starts the system tray application. This function blocks forever
// and must be called from the main goroutine.
func (t *TrayApp) Run() {
	systray.Run(t.onReady, t.onExit)
}

// onReady is called by systray.Run when the tray is initialized.
// All menu items must be created here.
func (t *TrayApp) onReady() {
	systray.SetIcon(iconBytes)
	systray.SetTitle("M3C Tools")
	systray.SetTooltip("M3C Tools — Multi-Modal-Memory Capture")

	// --- Sign In / Sign Out ---
	mSignIn := systray.AddMenuItem("Sign In...", "Connect to workspace")

	systray.AddSeparator()

	// --- Profile Settings (submenu) ---
	mProfile := systray.AddMenuItem("Profile Settings", "Configuration profiles")
	var profileItems []*systray.MenuItem
	t.rebuildProfileMenu(mProfile, &profileItems)

	systray.AddSeparator()

	// --- Fetch Transcript ---
	mFetch := systray.AddMenuItem("Fetch Transcript...", "Fetch a YouTube transcript")

	systray.AddSeparator()

	// --- Quick Impulse ---
	mImpulse := systray.AddMenuItem("Quick Impulse", "Record a quick thought")

	systray.AddSeparator()

	// --- Plaud Sync / Pocket Sync ---
	mPlaud := systray.AddMenuItem("Plaud Sync", "Sync Plaud recordings")
	mPocket := systray.AddMenuItem("Pocket Sync", "Sync Pocket articles")

	systray.AddSeparator()

	// --- History (submenu) ---
	mHistory := systray.AddMenuItem("History", "Recent observations")
	var historyItems []*systray.MenuItem
	t.rebuildHistoryMenu(mHistory, &historyItems)

	systray.AddSeparator()

	// --- Open Log File ---
	mLog := systray.AddMenuItem("Open Log File", "Open the application log")
	// --- Settings (profile editor) ---
	mSettings := systray.AddMenuItem("Settings...", "Edit configuration profiles")

	systray.AddSeparator()

	// --- Star on GitHub ---
	mStar := systray.AddMenuItem("Star on GitHub", "Open the project on GitHub")

	systray.AddSeparator()

	// --- Quit ---
	mQuit := systray.AddMenuItem("Quit", "Exit M3C Tools")

	// --- Click handlers (goroutines reading from ClickedCh) ---

	go func() {
		for range mSignIn.ClickedCh {
			log.Println("[tray] Sign In clicked")
			// TODO: implement sign-in flow for Windows
		}
	}()

	go func() {
		for range mFetch.ClickedCh {
			log.Println("[tray] Fetch Transcript clicked")
			t.fireAction(ActionFetchTranscript, "")
		}
	}()

	go func() {
		for range mImpulse.ClickedCh {
			log.Println("[tray] Quick Impulse clicked")
			t.fireAction(ActionQuickImpulse, "")
		}
	}()

	go func() {
		for range mPlaud.ClickedCh {
			log.Println("[tray] Plaud Sync clicked")
			t.fireAction(ActionPlaudSync, "")
		}
	}()

	go func() {
		for range mPocket.ClickedCh {
			log.Println("[tray] Pocket Sync clicked")
			t.fireAction(ActionPocketSync, "")
		}
	}()

	go func() {
		for range mLog.ClickedCh {
			log.Println("[tray] Open Log File clicked")
			t.openFile(t.logPath)
			t.fireAction(ActionOpenLog, t.logPath)
		}
	}()

	go func() {
		for range mSettings.ClickedCh {
			log.Println("[tray] Settings clicked")
			if t.Handlers.OpenProfileEditor != nil {
				t.Handlers.OpenProfileEditor()
			}
		}
	}()

	go func() {
		for range mStar.ClickedCh {
			log.Println("[tray] Star on GitHub clicked")
			t.openURL(GitHubRepoURL)
			t.fireAction(ActionStarGitHub, GitHubRepoURL)
		}
	}()

	go func() {
		for range mQuit.ClickedCh {
			log.Println("[tray] Quit clicked")
			t.fireAction(ActionQuit, "")
			systray.Quit()
		}
	}()

	// Profile sub-menu item click handlers.
	go t.handleProfileClicks(profileItems)

	log.Println("[tray] system tray ready")
}

// onExit is called when the tray application is shutting down.
func (t *TrayApp) onExit() {
	log.Println("[tray] exiting")
}

// fireAction invokes the OnAction handler if set.
func (t *TrayApp) fireAction(action ActionType, data string) {
	if t.Handlers.OnAction != nil {
		t.Handlers.OnAction(action, data)
	}
}

// rebuildProfileMenu populates the Profile Settings submenu with profiles.
func (t *TrayApp) rebuildProfileMenu(parent *systray.MenuItem, items *[]*systray.MenuItem) {
	if t.Handlers.ListProfiles == nil {
		parent.AddSubMenuItem("(no profiles)", "")
		return
	}

	profiles, activeName, err := t.Handlers.ListProfiles()
	if err != nil || len(profiles) == 0 {
		parent.AddSubMenuItem("(no profiles)", "")
		return
	}

	header := parent.AddSubMenuItem(fmt.Sprintf("Active: %s", activeName), "")
	header.Disable()
	*items = nil

	for _, p := range profiles {
		label := p.Name
		if p.Description != "" {
			label = fmt.Sprintf("%s - %s", p.Name, p.Description)
		}
		if p.IsActive {
			label = "* " + label
		}
		item := parent.AddSubMenuItem(label, fmt.Sprintf("Switch to %s", p.Name))
		*items = append(*items, item)
	}
}

// handleProfileClicks listens for clicks on profile submenu items and switches profile.
func (t *TrayApp) handleProfileClicks(items []*systray.MenuItem) {
	if t.Handlers.ListProfiles == nil || t.Handlers.SwitchProfile == nil {
		return
	}

	profiles, _, err := t.Handlers.ListProfiles()
	if err != nil {
		return
	}

	// Create a goroutine per item to listen on its ClickedCh.
	for i, item := range items {
		if i >= len(profiles) {
			break
		}
		go func(mi *systray.MenuItem, prof Profile) {
			for range mi.ClickedCh {
				if !prof.IsActive {
					if switchErr := t.Handlers.SwitchProfile(prof.Name); switchErr != nil {
						log.Printf("[tray] profile switch error: %v", switchErr)
					} else {
						log.Printf("[tray] switched to profile: %s", prof.Name)
					}
				}
			}
		}(item, profiles[i])
	}
}

// rebuildHistoryMenu populates the History submenu with recent observations.
func (t *TrayApp) rebuildHistoryMenu(parent *systray.MenuItem, items *[]*systray.MenuItem) {
	if t.Handlers.ListRecentObs == nil {
		parent.AddSubMenuItem("(empty)", "")
		return
	}

	observations, err := t.Handlers.ListRecentObs(20)
	if err != nil || len(observations) == 0 {
		parent.AddSubMenuItem("(empty)", "")
		return
	}

	*items = nil
	for _, obs := range observations {
		title := obs.Title
		if len(title) > 50 {
			title = title[:47] + "..."
		}
		label := fmt.Sprintf("[%s] %s  %s", obs.Type, title, obs.ProcessedAt)
		item := parent.AddSubMenuItem(label, "")
		*items = append(*items, item)
	}
}

// openURL opens a URL in the default browser.
func (t *TrayApp) openURL(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	default:
		cmd = exec.Command("open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("[tray] failed to open URL %s: %v", url, err)
	}
}

// openFile opens a file with the system default application.
func (t *TrayApp) openFile(path string) {
	// Ensure the parent directory exists.
	if dir := filepath.Dir(path); dir != "" {
		_ = os.MkdirAll(dir, 0700)
	}
	// Ensure the file exists (create empty if needed for log files).
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if strings.HasSuffix(path, ".log") {
			_ = os.WriteFile(path, []byte{}, 0600)
		}
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", path)
	case "linux":
		cmd = exec.Command("xdg-open", path)
	default:
		cmd = exec.Command("open", path)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("[tray] failed to open file %s: %v", path, err)
	}
}
