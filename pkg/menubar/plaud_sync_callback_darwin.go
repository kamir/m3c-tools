// plaud_sync_callback_darwin.go — Go callback for Plaud Sync window actions.
//
// This file is separate from plaud_sync_darwin.go because //export requires
// that the cgo preamble contain only declarations, not definitions.
package menubar

/*
extern int plaudSyncRowCount(void);
extern int plaudSyncIsSelected(int row);
extern const char* plaudSyncRecordingID(int row);
extern const char* getPlaudCustomTags(void);
*/
import "C"

var plaudSyncCallback func(action string, recordingIDs []string, customTags string)

// SetPlaudSyncCallback registers a handler for sync actions triggered
// from the Plaud Sync window's "Sync Selected" button.
// The customTags parameter contains the comma-separated tags from the UI field.
func SetPlaudSyncCallback(cb func(action string, recordingIDs []string, customTags string)) {
	plaudSyncCallback = cb
}

//export goPlaudSyncAction
func goPlaudSyncAction(cAction *C.char) {
	if plaudSyncCallback == nil {
		return
	}
	action := C.GoString(cAction)
	customTags := C.GoString(C.getPlaudCustomTags())
	n := int(C.plaudSyncRowCount())
	var ids []string
	for i := 0; i < n; i++ {
		if C.plaudSyncIsSelected(C.int(i)) != 0 {
			id := C.GoString(C.plaudSyncRecordingID(C.int(i)))
			if id != "" {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return
	}
	go plaudSyncCallback(action, ids, customTags)
}
