//go:build darwin

package menubar

import _ "embed"

// embeddedMenuBarIconPNG is the 22x22 template menu-bar icon compiled into the
// binary. It guarantees the icon is available in every run mode — the dev bare
// binary launched from any directory, and (crucially) inside the .app bundle,
// where the on-disk design/icons/ tree is not shipped and FindIcon would return
// "". app.Run() prefers the on-disk design-system icon and falls back to these
// embedded bytes.
//
// Source of truth: design/icons/menubar-icon.png — this is a build-time copy;
// refresh it with:  cp design/icons/menubar-icon.png pkg/menubar/assets/menubar-icon.png
//
//go:embed assets/menubar-icon.png
var embeddedMenuBarIconPNG []byte
