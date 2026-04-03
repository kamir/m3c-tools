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
	"sync/atomic"
	"time"

	"fyne.io/systray"
)

// iconPNG is used on Linux where systray accepts PNG bytes directly.
//
//go:embed icon.png
var iconPNG []byte

// iconICO is used on Windows where fyne.io/systray v1.12 requires ICO format.
// The ICO contains 16x16, 32x32, and 48x48 BGRA entries generated from the
// app-icon-128 source (see BUG-0087).
//
//go:embed icon.ico
var iconICO []byte

// GitHubRepoURL is the project's GitHub repository URL.
const GitHubRepoURL = "https://github.com/kamir/m3c-tools"

// ActionType identifies the kind of menu action triggered by the user.
type ActionType string

const (
	ActionSignIn          ActionType = "sign_in"
	ActionSignOut         ActionType = "sign_out"
	ActionFetchTranscript ActionType = "fetch_transcript"
	ActionPlaudSync       ActionType = "plaud_sync"
	ActionPocketSync      ActionType = "pocket_sync"
	ActionOpenLog         ActionType = "open_log"
	ActionSetup           ActionType = "setup"
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

// SetupIssue describes a single first-run configuration problem.
type SetupIssue struct {
	Key     string // short identifier, e.g. "no_profiles"
	Message string // human-readable description
}

// TrayApp holds the runtime state of the system tray application.
type TrayApp struct {
	Handlers    TrayHandlers
	loggedIn    bool
	userName    string
	profileName string
	logPath     string

	// plaudSyncing guards against concurrent Plaud Sync invocations.
	// 0 = idle, 1 = syncing. Use atomic CAS to claim.
	plaudSyncing int32

	// SetupIssues holds first-run problems detected at startup.
	// Empty slice means setup is complete.
	SetupIssues []SetupIssue

	// FEAT-0014: Dynamic menu items for state updates.
	mIdentity   *systray.MenuItem
	mLastSync   *systray.MenuItem
	mSignIn     *systray.MenuItem
	mSignOut    *systray.MenuItem
	mSyncPlaud  *systray.MenuItem
	mSyncPocket *systray.MenuItem
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

// UpdateTooltip changes the system tray tooltip text.
// BUG-0092: Provides visible feedback for background operations like Plaud Sync.
func (t *TrayApp) UpdateTooltip(msg string) {
	systray.SetTooltip(msg)
}

// ResetTooltip restores the default tooltip, or shows the first setup issue
// if the setup is incomplete.
func (t *TrayApp) ResetTooltip() {
	if len(t.SetupIssues) > 0 {
		systray.SetTooltip(fmt.Sprintf("M3C Tools — Setup needed: %s", t.SetupIssues[0].Message))
		return
	}
	systray.SetTooltip("M3C Tools — Multi-Modal-Memory Capture")
}

// UpdateLoginState toggles the menu between signed-in and signed-out views.
// FEAT-0014: Dynamic state feedback in the tray menu.
func (t *TrayApp) UpdateLoginState(loggedIn bool, email string) {
	t.loggedIn = loggedIn
	t.userName = email
	if loggedIn {
		if t.mIdentity != nil {
			truncated := email
			if len(truncated) > 30 {
				truncated = truncated[:27] + "..."
			}
			t.mIdentity.SetTitle(truncated)
			t.mIdentity.Show()
		}
		if t.mLastSync != nil {
			t.mLastSync.Show()
		}
		if t.mSignIn != nil {
			t.mSignIn.Hide()
		}
		if t.mSignOut != nil {
			t.mSignOut.Show()
		}
	} else {
		if t.mIdentity != nil {
			t.mIdentity.SetTitle("Not connected")
			t.mIdentity.Hide()
		}
		if t.mLastSync != nil {
			t.mLastSync.Hide()
		}
		if t.mSignIn != nil {
			t.mSignIn.Show()
		}
		if t.mSignOut != nil {
			t.mSignOut.Hide()
		}
	}
}

// UpdateSyncStatus updates a device's status in the Sync Now submenu.
func (t *TrayApp) UpdateSyncStatus(source string, status string) {
	switch source {
	case "plaud":
		if t.mSyncPlaud != nil {
			t.mSyncPlaud.SetTitle(fmt.Sprintf("Plaud: %s", status))
		}
	case "pocket":
		if t.mSyncPocket != nil {
			t.mSyncPocket.SetTitle(fmt.Sprintf("Pocket: %s", status))
		}
	}
}

// UpdateLastSync updates the "Last sync" status line.
func (t *TrayApp) UpdateLastSync(timeStr string) {
	if t.mLastSync != nil {
		t.mLastSync.SetTitle(fmt.Sprintf("Last sync: %s", timeStr))
	}
}

// Notify is defined in notify.go (beeep-based native OS notifications for
// Windows toast and Linux libnotify). The darwin stub is in notify_darwin.go.

// SetSetupIssues records the first-run detection results. Call this before
// Run() so the tray menu reflects the setup state from the start.
func (t *TrayApp) SetSetupIssues(issues []SetupIssue) {
	t.SetupIssues = issues
}

// IsSetupComplete returns true if no first-run issues were detected.
func (t *TrayApp) IsSetupComplete() bool {
	return len(t.SetupIssues) == 0
}

// ClaimPlaudSync attempts to acquire the Plaud Sync lock.
// Returns true if acquired (caller must call ReleasePlaudSync when done).
// Returns false if a sync is already running.
func (t *TrayApp) ClaimPlaudSync() bool {
	return atomic.CompareAndSwapInt32(&t.plaudSyncing, 0, 1)
}

// ReleasePlaudSync releases the Plaud Sync lock.
func (t *TrayApp) ReleasePlaudSync() {
	atomic.StoreInt32(&t.plaudSyncing, 0)
}

// Run starts the system tray application. This function blocks forever
// and must be called from the main goroutine.
func (t *TrayApp) Run() {
	systray.Run(t.onReady, t.onExit)
}

// onReady is called by systray.Run when the tray is initialized.
// FEAT-0014: Streamlined menu — 7 items signed-in, 3 signed-out.
func (t *TrayApp) onReady() {
	// BUG-0087: fyne.io/systray v1.12 on Windows requires ICO format.
	if runtime.GOOS == "windows" {
		systray.SetIcon(iconICO)
	} else {
		systray.SetIcon(iconPNG)
	}
	systray.SetTitle("M3C Tools")
	systray.SetTooltip("M3C Tools — Multi-Modal-Memory Capture")

	// --- Status lines (disabled info rows, dynamic) ---
	t.mIdentity = systray.AddMenuItem("Not connected", "")
	t.mIdentity.Disable()
	t.mLastSync = systray.AddMenuItem("Never synced", "")
	t.mLastSync.Disable()

	systray.AddSeparator()

	// --- Sign In (shown when signed out) ---
	t.mSignIn = systray.AddMenuItem("Sign In with Google...", "Connect to workspace")

	// --- Sync Now (shown when signed in) ---
	mSyncNow := systray.AddMenuItem("Sync Now", "Sync all connected devices")
	t.mSyncPlaud = mSyncNow.AddSubMenuItem("Plaud: not configured", "Sync Plaud recordings")
	t.mSyncPocket = mSyncNow.AddSubMenuItem("Pocket: not connected", "Sync Pocket recordings")

	// --- Fetch YouTube Transcript ---
	mFetch := systray.AddMenuItem("Fetch YouTube Transcript...", "Fetch a YouTube transcript")

	systray.AddSeparator()

	// --- Recent (submenu) ---
	mRecent := systray.AddMenuItem("Recent", "Recent observations")
	var historyItems []*systray.MenuItem
	t.rebuildHistoryMenu(mRecent, &historyItems)

	// --- Preferences ---
	prefsLabel := "Preferences..."
	if !t.IsSetupComplete() {
		prefsLabel = "Preferences... (!)"
	}
	mPrefs := systray.AddMenuItem(prefsLabel, "Settings and configuration")

	// --- Sign Out (shown when signed in) ---
	t.mSignOut = systray.AddMenuItem("Sign Out", "Disconnect from workspace")

	systray.AddSeparator()

	// --- Quit ---
	mQuit := systray.AddMenuItem("Quit", "Exit M3C Tools")

	// --- Set initial visibility based on login state ---
	if t.loggedIn {
		t.mIdentity.Show()
		t.mLastSync.Show()
		t.mSignIn.Hide()
		t.mSignOut.Show()
		mSyncNow.Show()
	} else {
		t.mIdentity.Hide()
		t.mLastSync.Hide()
		t.mSignIn.Show()
		t.mSignOut.Hide()
		mSyncNow.Hide()
	}

	// --- Click handlers ---

	go func() {
		for range t.mSignIn.ClickedCh {
			log.Println("[tray] Sign In clicked")
			t.fireAction(ActionSignIn, "")
		}
	}()

	go func() {
		for range t.mSignOut.ClickedCh {
			log.Println("[tray] Sign Out clicked")
			t.fireAction(ActionSignOut, "")
		}
	}()

	go func() {
		for range t.mSyncPlaud.ClickedCh {
			log.Println("[tray] Plaud Sync clicked")
			t.fireAction(ActionPlaudSync, "")
		}
	}()

	go func() {
		for range t.mSyncPocket.ClickedCh {
			log.Println("[tray] Pocket Sync clicked")
			t.fireAction(ActionPocketSync, "")
		}
	}()

	go func() {
		for range mFetch.ClickedCh {
			log.Println("[tray] Fetch YouTube Transcript clicked")
			t.fireAction(ActionFetchTranscript, "")
		}
	}()

	go func() {
		for range mPrefs.ClickedCh {
			log.Println("[tray] Preferences clicked")
			if t.Handlers.OpenProfileEditor != nil {
				t.Handlers.OpenProfileEditor()
			}
			t.fireAction(ActionSetup, "settings")
		}
	}()

	go func() {
		for range mQuit.ClickedCh {
			log.Println("[tray] Quit clicked")
			t.fireAction(ActionQuit, "")
			systray.Quit()
		}
	}()

	// First-run notification (toast, not menu banner).
	if !t.IsSetupComplete() {
		t.UpdateTooltip(fmt.Sprintf("M3C Tools — Setup needed: %s", t.SetupIssues[0].Message))
		go func() {
			time.Sleep(3 * time.Second)
			t.Notify("M3C Tools", fmt.Sprintf("Setup incomplete: %s — open Preferences to configure", t.SetupIssues[0].Message))
		}()
	}

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
// BUG-0089: Removed stale IsActive guard that prevented switching after the first
// menu build. The profile name is captured directly from the snapshot, and each
// click always calls SwitchProfile (the function itself is idempotent if the
// profile is already active). After switching, the tray's profileName is updated.
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
		go func(mi *systray.MenuItem, profName string) {
			for range mi.ClickedCh {
				log.Printf("[tray] profile click: %s", profName)
				if switchErr := t.Handlers.SwitchProfile(profName); switchErr != nil {
					log.Printf("[tray] profile switch error for %q: %v", profName, switchErr)
					t.Notify("Profile Switch Failed", fmt.Sprintf("Could not switch to %s: %v", profName, switchErr))
				} else {
					log.Printf("[tray] switched to profile: %s", profName)
					t.profileName = profName
					t.Notify("Profile Switched", fmt.Sprintf("Active: %s", profName))
				}
			}
		}(item, profiles[i].Name)
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
// BUG-0088: Windows uses "cmd /c start" instead of rundll32 which silently fails.
func (t *TrayApp) openURL(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// Empty title arg ("") prevents cmd from misinterpreting URLs with & as title.
		cmd = exec.Command("cmd", "/c", "start", "", url)
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
