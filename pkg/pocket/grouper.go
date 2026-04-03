package pocket

import (
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

// RecordingGroup represents a set of recordings to be merged and uploaded as one item.
type RecordingGroup struct {
	ID            string      `json:"id"`
	Title         string      `json:"title"`
	Recordings    []Recording `json:"recordings"`
	Tags          []string    `json:"tags"`
	TotalDuration float64     `json:"total_duration_sec"`
	TotalSize     int64       `json:"total_size_bytes"`
}

// SuggestGroups clusters recordings by session proximity.
// Recordings within maxGapMinutes of each other form a group.
// Single recordings are NOT grouped (returned individually).
func SuggestGroups(recordings []Recording, maxGapMinutes int) []RecordingGroup {
	if len(recordings) == 0 {
		return nil
	}

	// Sort by timestamp
	sorted := make([]Recording, len(recordings))
	copy(sorted, recordings)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})

	maxGap := time.Duration(maxGapMinutes) * time.Minute
	var groups []RecordingGroup
	current := []Recording{sorted[0]}

	for i := 1; i < len(sorted); i++ {
		gap := sorted[i].Timestamp.Sub(sorted[i-1].Timestamp)
		if gap <= maxGap {
			current = append(current, sorted[i])
		} else {
			if len(current) > 1 {
				groups = append(groups, buildGroup(current))
			}
			current = []Recording{sorted[i]}
		}
	}
	if len(current) > 1 {
		groups = append(groups, buildGroup(current))
	}

	return groups
}

// CreateGroup creates a named group from selected recordings.
func CreateGroup(title string, recordings []Recording, tags []string) RecordingGroup {
	g := buildGroup(recordings)
	g.Title = title
	if len(tags) > 0 {
		g.Tags = tags
	}
	return g
}

func buildGroup(recordings []Recording) RecordingGroup {
	var totalDur float64
	var totalSize int64
	for _, r := range recordings {
		totalDur += r.DurationSec
		totalSize += r.SizeBytes
	}

	first := recordings[0]
	title := fmt.Sprintf("Session %s %s (%d recordings)",
		first.Date, first.Time, len(recordings))

	return RecordingGroup{
		ID:            uuid.New().String(),
		Title:         title,
		Recordings:    recordings,
		Tags:          []string{"pocket", "fieldnote", "session"},
		TotalDuration: totalDur,
		TotalSize:     totalSize,
	}
}
