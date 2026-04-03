// notify.go — Native OS notifications for Windows (toast) and Linux (libnotify).
//
// Uses github.com/gen2brain/beeep which is pure Go:
//   - Windows: PowerShell-based toast notifications
//   - Linux: notify-send (libnotify)
//
// Falls back to systray tooltip if notification delivery fails.
//
//go:build !darwin

package tray

import (
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/gen2brain/beeep"
)

// notifyIconPath caches the on-disk path to the app icon extracted from the
// embedded PNG. Toast notifications on Windows need a file path, not bytes.
var (
	notifyIconOnce sync.Once
	notifyIconPath string
)

// ensureNotifyIcon writes the embedded icon.png to a temp file once so that
// beeep can reference it by path in toast notifications.
func ensureNotifyIcon() string {
	notifyIconOnce.Do(func() {
		tmpDir := filepath.Join(os.TempDir(), "m3c-tools")
		_ = os.MkdirAll(tmpDir, 0700)
		iconFile := filepath.Join(tmpDir, "icon.png")

		// Only write if missing or empty (survives across app restarts).
		info, err := os.Stat(iconFile)
		if err != nil || info.Size() == 0 {
			if writeErr := os.WriteFile(iconFile, iconPNG, 0644); writeErr != nil {
				log.Printf("[notify] failed to write icon to %s: %v", iconFile, writeErr)
				return
			}
		}
		notifyIconPath = iconFile
	})
	return notifyIconPath
}

// Notify sends a native OS notification (Windows toast, Linux libnotify).
// Falls back to tooltip if notification delivery fails.
func (t *TrayApp) Notify(title, message string) {
	iconPath := ensureNotifyIcon()
	if err := beeep.Notify(title, message, iconPath); err != nil {
		log.Printf("[notify] native notification failed, falling back to tooltip: %v", err)
		t.UpdateTooltip(message)
	}
}
