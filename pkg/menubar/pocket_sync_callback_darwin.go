// pocket_sync_callback_darwin.go — Go callback for Pocket Sync window actions.
//
// Separate from pocket_sync_darwin.go because //export requires the cgo
// preamble to contain only declarations, not definitions.
package menubar

/*
extern int pocketSyncRowCount(void);
extern int pocketSyncIsSelected(int row);
extern const char* pocketSyncFilePath(int row);
extern const char* getPocketCustomTags(void);
*/
import "C"
import "strings"

var pocketSyncCallback func(action string, filePaths []string, customTags string)

// SetPocketSyncCallback registers a handler for sync/group actions triggered
// from the Pocket Sync window buttons.
func SetPocketSyncCallback(cb func(action string, filePaths []string, customTags string)) {
	pocketSyncCallback = cb
}

//export goPocketSyncAction
func goPocketSyncAction(cAction *C.char) {
	if pocketSyncCallback == nil {
		return
	}
	action := C.GoString(cAction)
	customTags := C.GoString(C.getPocketCustomTags())
	n := int(C.pocketSyncRowCount())
	var paths []string
	for i := 0; i < n; i++ {
		if C.pocketSyncIsSelected(C.int(i)) != 0 {
			p := C.GoString(C.pocketSyncFilePath(C.int(i)))
			if p != "" {
				paths = append(paths, p)
			}
		}
	}
	// For toggle_group actions, the group ID is in the action string — no selection needed
	if len(paths) == 0 && !strings.HasPrefix(action, "toggle_group:") {
		return
	}
	go pocketSyncCallback(action, paths, customTags)
}
