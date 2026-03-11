// tracking_bulk_darwin.go — Go callback for tracking window bulk actions.
//
// This file is separate from tracking_darwin.go because //export requires
// that the cgo preamble contain only declarations, not definitions.
package menubar

/*
extern int trackingSrcRowCount(void);
extern int trackingIsSrcSelected(int row);
extern const char* trackingSrcFilename(int row);
extern const char* trackingSrcStatus(int row);
*/
import "C"

var trackingBulkCallback func(action string, filenames []string, statuses []string)

// SetTrackingBulkCallback registers a handler for bulk actions triggered
// from the tracking window buttons (e.g. "Transcribe + Upload", "Re-process").
func SetTrackingBulkCallback(cb func(action string, filenames []string, statuses []string)) {
	trackingBulkCallback = cb
}

//export goTrackingBulkAction
func goTrackingBulkAction(cAction *C.char) {
	if trackingBulkCallback == nil {
		return
	}
	action := C.GoString(cAction)
	n := int(C.trackingSrcRowCount())
	var filenames []string
	var statuses []string
	for i := 0; i < n; i++ {
		if C.trackingIsSrcSelected(C.int(i)) != 0 {
			name := C.GoString(C.trackingSrcFilename(C.int(i)))
			status := C.GoString(C.trackingSrcStatus(C.int(i)))
			if name != "" {
				filenames = append(filenames, name)
				statuses = append(statuses, status)
			}
		}
	}
	if len(filenames) == 0 {
		return
	}
	go trackingBulkCallback(action, filenames, statuses)
}

// SelectedSourceFiles returns the currently selected source file names.
func SelectedSourceFiles() []string {
	n := int(C.trackingSrcRowCount())
	var names []string
	for i := 0; i < n; i++ {
		if C.trackingIsSrcSelected(C.int(i)) != 0 {
			name := C.GoString(C.trackingSrcFilename(C.int(i)))
			if name != "" {
				names = append(names, name)
			}
		}
	}
	return names
}
