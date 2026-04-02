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

// TrayHandlers groups the callback functions (stub — unused on macOS).
type TrayHandlers struct {
	OnAction          func(action ActionType, data string)
	ListProfiles      func() ([]Profile, string, error)
	SwitchProfile     func(name string) error
	OpenProfileEditor func()
	ListRecentObs     func(limit int) ([]Observation, error)
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
