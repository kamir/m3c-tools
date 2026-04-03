package menubar

import (
	"fmt"
	"strings"
	"sync"
)

// PocketSyncRecord holds one recording row for the Pocket Sync window.
type PocketSyncRecord struct {
	Num      string
	Date     string
	Time     string
	Duration string
	Size     string
	Status   string
	FilePath string
}

// PocketSyncState holds the current Pocket sync snapshot for menu rendering.
type PocketSyncState struct {
	Items     []PocketSyncRecord
	NewCount  int
	Connected bool
}

// FormatPocketDuration formats seconds into a human-readable string.
func FormatPocketDuration(seconds float64) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", int(seconds))
	}
	return fmt.Sprintf("%dm%ds", int(seconds)/60, int(seconds)%60)
}

// FormatPocketSize formats bytes into a human-readable string.
func FormatPocketSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%dB", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%dKB", bytes/1024)
	}
	return fmt.Sprintf("%.1fMB", float64(bytes)/(1024*1024))
}

// pocketLabelFunc is an optional callback that computes the dynamic menu label.
// Set via SetPocketLabelFunc from main.go.
var (
	pocketLabelMu   sync.Mutex
	pocketLabelFunc func() string
)

// SetPocketLabelFunc registers a function that returns the dynamic Pocket Sync
// menu label. Called from main.go after initialization.
func SetPocketLabelFunc(fn func() string) {
	pocketLabelMu.Lock()
	defer pocketLabelMu.Unlock()
	pocketLabelFunc = fn
}

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

// BuildGroupedRecords creates the display list with collapsed groups.
// Groups show as one summary row with "+" prefix. Individual ungrouped recordings
// are shown as-is. When expandedGroupIDs contains a group ID, its children are shown.
func BuildGroupedRecords(
	recordings []PocketSyncRecord,
	groups []PocketGroupInfo,
	expandedGroupIDs map[string]bool,
) []PocketSyncRecord {
	// Track which file paths belong to groups
	fileToGroup := make(map[string]*PocketGroupInfo)
	for i := range groups {
		for _, fp := range groups[i].MemberPaths {
			fileToGroup[fp] = &groups[i]
		}
	}

	// Track which groups we've already emitted
	emittedGroups := make(map[string]bool)
	var result []PocketSyncRecord

	for _, rec := range recordings {
		gi, isGrouped := fileToGroup[rec.FilePath]
		if !isGrouped {
			// Ungrouped recording — show as-is
			result = append(result, rec)
			continue
		}

		if emittedGroups[gi.GroupID] {
			// Already emitted this group's header (and possibly children)
			continue
		}
		emittedGroups[gi.GroupID] = true

		// Compute totals from actual recording data
		var totalDurStr, totalSizeStr string
		if gi.Duration != "" {
			totalDurStr = gi.Duration
		}
		if gi.Size != "" {
			totalSizeStr = gi.Size
		}

		// Emit group header
		expanded := expandedGroupIDs[gi.GroupID]
		prefix := "+"
		if expanded {
			prefix = "-"
		}
		docShort := gi.DocID
		if len(docShort) > 8 {
			docShort = docShort[:8]
		}
		statusText := fmt.Sprintf("%s [%d items]", docShort, gi.Segments)
		if gi.Tags != "" {
			statusText += " | " + gi.Tags
		}
		header := PocketSyncRecord{
			Num:      prefix,
			Date:     gi.Title,
			Time:     "",
			Duration: totalDurStr,
			Size:     totalSizeStr,
			Status:   statusText,
			FilePath: "group:" + gi.GroupID,
		}
		result = append(result, header)

		// If expanded, emit children (indented)
		if expanded {
			childNum := 1
			for _, crec := range recordings {
				if fileToGroup[crec.FilePath] == gi {
					child := crec
					child.Num = fmt.Sprintf("  %d", childNum)
					child.Status = "  grouped"
					result = append(result, child)
					childNum++
				}
			}
		}
	}

	return result
}

// PocketGroupInfo describes a known group for display purposes.
type PocketGroupInfo struct {
	GroupID     string
	DocID       string
	Title       string
	Duration    string
	Size        string
	Segments    int
	MemberPaths []string
	Tags        string // comma-separated tags used at upload time
}

// ParsePocketTags splits a comma-separated tag string into a slice.
func ParsePocketTags(customTags string, defaults []string) []string {
	if customTags == "" {
		return defaults
	}
	var tags []string
	for _, t := range strings.Split(customTags, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}
