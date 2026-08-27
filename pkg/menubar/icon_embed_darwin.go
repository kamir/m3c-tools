//go:build darwin

package menubar

import "embed"

// embeddedIcons carries the menu-bar template icons compiled into the binary, so
// icons resolve in EVERY run mode — the dev bare binary from any directory, and
// (crucially) inside the .app bundle, where the on-disk design/icons/ tree is not
// shipped and FindIcon returns "". Both the top-level menu-bar icon (app.Run)
// and the per-item icons (registerMenuIcons) fall back to these bytes when the
// on-disk design-system file is not reachable.
//
// Source of truth: design/icons/*.png — these are build-time copies; refresh with:
//
//	cp design/icons/menubar-icon.png design/icons/menu-*.png pkg/menubar/assets/
//
//go:embed assets/menubar-icon.png assets/menu-audio-import.png assets/menu-history.png assets/menu-log-file.png assets/menu-logout.png assets/menu-projects.png assets/menu-quick-impulse.png assets/menu-screenshot.png assets/menu-star.png assets/menu-sync.png assets/menu-tracking-db.png assets/menu-transcript.png assets/menu-user-account.png
var embeddedIcons embed.FS

// embeddedIconBytes returns the embedded PNG bytes for an icon file name (e.g.
// "menubar-icon.png"), or nil if it is not embedded.
func embeddedIconBytes(fileName string) []byte {
	b, err := embeddedIcons.ReadFile("assets/" + fileName)
	if err != nil {
		return nil
	}
	return b
}
