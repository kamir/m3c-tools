// tray_darwin.go — Darwin compile stub for the tray package.
//
// On macOS we use pkg/menubar (menuet) instead of fyne.io/systray.
// This stub ensures the package compiles on darwin so that other packages
// can reference tray types without build-tag gymnastics.
//
//go:build darwin

package tray

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

// SetupIssue describes a single first-run configuration problem.
type SetupIssue struct {
	Key     string
	Message string
}

// TrayHandlers groups the callback functions (stub — unused on macOS).
type TrayHandlers struct {
	OnAction func(action ActionType, data string)
}

// TrayApp is a no-op stub on macOS.
type TrayApp struct{}

// New returns a no-op TrayApp on macOS.
func New(h TrayHandlers) *TrayApp { return &TrayApp{} }

// Run is a no-op on macOS (use pkg/menubar instead).
func (t *TrayApp) Run() {}

// SetLoggedIn is a no-op on macOS.
func (t *TrayApp) SetLoggedIn(loggedIn bool, userName string) {}

// SetProfile is a no-op on macOS.
func (t *TrayApp) SetProfile(name string) {}

// SetLogPath is a no-op on macOS.
func (t *TrayApp) SetLogPath(path string) {}

// UpdateTooltip is a no-op on macOS.
// BUG-0092: Stub so the package compiles on darwin.
func (t *TrayApp) UpdateTooltip(msg string) {}

// ResetTooltip is a no-op on macOS.
func (t *TrayApp) ResetTooltip() {}

// Notify is a no-op on macOS (pkg/menubar handles notifications).
func (t *TrayApp) Notify(title, message string) {}

// SetSetupIssues is a no-op on macOS.
func (t *TrayApp) SetSetupIssues(issues []SetupIssue) {}

// IsSetupComplete always returns true on macOS (stub).
func (t *TrayApp) IsSetupComplete() bool { return true }

// ClaimPlaudSync always returns true on macOS (no systray sync guard needed).
func (t *TrayApp) ClaimPlaudSync() bool { return true }

// ReleasePlaudSync is a no-op on macOS.
func (t *TrayApp) ReleasePlaudSync() {}

// FEAT-0014: Dynamic state methods (no-op on macOS).
func (t *TrayApp) UpdateLoginState(loggedIn bool, email string) {}
func (t *TrayApp) UpdateLastSync(timeStr string)                 {}
