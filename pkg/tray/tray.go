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
	ActionSignIn    ActionType = "sign_in"
	ActionSignOut   ActionType = "sign_out"
	ActionPlaudSync ActionType = "plaud_sync"
	ActionQuit      ActionType = "quit"
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

// TrayHandlers groups the callback functions that the tray app invokes.
type TrayHandlers struct {
	// OnAction is called for every menu action.
	OnAction func(action ActionType, data string)
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
	mIdentity  *systray.MenuItem
	mLastSync  *systray.MenuItem
	mSignIn    *systray.MenuItem
	mSignOut   *systray.MenuItem
	mSyncPlaud *systray.MenuItem
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
// Windows MVP: Plaud sync only — 5 items signed-in, 2 signed-out.
func (t *TrayApp) onReady() {
	if runtime.GOOS == "windows" {
		systray.SetIcon(iconICO)
	} else {
		systray.SetIcon(iconPNG)
	}
	systray.SetTitle("M3C Tools")
	systray.SetTooltip("M3C Tools — Plaud Sync")

	// --- Status lines (disabled, dynamic) ---
	t.mIdentity = systray.AddMenuItem("Not connected", "")
	t.mIdentity.Disable()
	t.mLastSync = systray.AddMenuItem("Never synced", "")
	t.mLastSync.Disable()

	systray.AddSeparator()

	// --- Sign In (shown when signed out) ---
	t.mSignIn = systray.AddMenuItem("Sign In with Google...", "Connect to workspace")

	// --- Sync Plaud (shown when signed in, flat item) ---
	t.mSyncPlaud = systray.AddMenuItem("Sync Plaud Recordings", "Sync Plaud recordings to workspace")

	systray.AddSeparator()

	// --- Sign Out (shown when signed in) ---
	t.mSignOut = systray.AddMenuItem("Sign Out", "Disconnect from workspace")

	// --- Quit ---
	mQuit := systray.AddMenuItem("Quit", "Exit M3C Tools")

	// --- Initial visibility ---
	if t.loggedIn {
		t.mIdentity.Show()
		t.mLastSync.Show()
		t.mSignIn.Hide()
		t.mSyncPlaud.Show()
		t.mSignOut.Show()
	} else {
		t.mIdentity.Hide()
		t.mLastSync.Hide()
		t.mSignIn.Show()
		t.mSyncPlaud.Hide()
		t.mSignOut.Hide()
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
			log.Println("[tray] Sync Plaud clicked")
			t.fireAction(ActionPlaudSync, "")
		}
	}()

	go func() {
		for range mQuit.ClickedCh {
			log.Println("[tray] Quit clicked")
			t.fireAction(ActionQuit, "")
			systray.Quit()
		}
	}()

	// First-run toast notification.
	if !t.IsSetupComplete() {
		t.UpdateTooltip(fmt.Sprintf("M3C Tools — Setup needed: %s", t.SetupIssues[0].Message))
		go func() {
			time.Sleep(3 * time.Second)
			t.Notify("M3C Tools", fmt.Sprintf("Run 'm3c-tools setup' to configure: %s", t.SetupIssues[0].Message))
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

// (Profile menu and history submenu removed for Windows MVP — Plaud sync only)

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
