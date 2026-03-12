// gantt_callback_darwin.go — Go callback for Gantt chart navigation actions.
//
// This file is separate from gantt_darwin.go because //export requires
// that the cgo preamble contain only declarations, not definitions.
package menubar

/*
// No C definitions — only Go exports in this file.
*/
import "C"

var ganttNavigateCallback func(viewMode, offset int)

// SetGanttNavigateCallback registers the function called when the user
// navigates the Gantt chart (prev/next/today/view mode change).
// The callback receives (viewMode, offset) where viewMode is 0=week, 1=month
// and offset is the number of periods from current (0=current, -1=prev, +1=next).
func SetGanttNavigateCallback(cb func(viewMode, offset int)) {
	ganttNavigateCallback = cb
}

//export goGanttNavigate
func goGanttNavigate(cViewMode C.int, cOffset C.int) {
	if ganttNavigateCallback != nil {
		go ganttNavigateCallback(int(cViewMode), int(cOffset))
	}
}
