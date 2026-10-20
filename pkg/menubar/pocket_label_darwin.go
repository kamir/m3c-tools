//go:build darwin

package menubar

// pocketMenuLabel returns the dynamic label for the Pocket Sync menu item.
// Falls back to "Pocket Sync" if no label function is registered.
func pocketMenuLabel() string {
	pocketLabelMu.Lock()
	fn := pocketLabelFunc
	pocketLabelMu.Unlock()
	if fn != nil {
		return fn()
	}
	return "Pocket Sync"
}
