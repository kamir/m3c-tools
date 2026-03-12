package timetracking

import (
	"hash/fnv"
	"time"
)

// Session represents a continuous time tracking session for a single project.
type Session struct {
	ProjectID   string
	ProjectName string
	Start       time.Time
	End         time.Time
	IsActive    bool
	DurationSec int
	Trigger     string // e.g. "user", "observation_inferred"
}

// ComputeSessions pairs activate/deactivate events into sessions.
// Events must be sorted by timestamp ascending (as returned by ListAllEvents).
// Open sessions (activate without matching deactivate) extend to the current time.
func ComputeSessions(events []Event) []Session {
	type openActivation struct {
		projectName string
		activatedAt time.Time
		trigger     string
	}
	open := make(map[string]*openActivation)
	var sessions []Session

	for _, e := range events {
		switch e.EventType {
		case "activate":
			if o, ok := open[e.ProjectID]; ok {
				// Close previous unclosed activation for same project.
				sessions = append(sessions, Session{
					ProjectID:   e.ProjectID,
					ProjectName: o.projectName,
					Start:       o.activatedAt,
					End:         e.Timestamp,
					DurationSec: int(e.Timestamp.Sub(o.activatedAt).Seconds()),
					Trigger:     o.trigger,
				})
			}
			open[e.ProjectID] = &openActivation{
				projectName: e.ProjectName,
				activatedAt: e.Timestamp,
				trigger:     e.Trigger,
			}
		case "deactivate":
			if o, ok := open[e.ProjectID]; ok {
				dur := int(e.Timestamp.Sub(o.activatedAt).Seconds())
				if e.DurationSec != nil {
					dur = *e.DurationSec
				}
				sessions = append(sessions, Session{
					ProjectID:   e.ProjectID,
					ProjectName: e.ProjectName,
					Start:       o.activatedAt,
					End:         e.Timestamp,
					DurationSec: dur,
					Trigger:     o.trigger,
				})
				delete(open, e.ProjectID)
			}
		}
	}

	now := time.Now().UTC()
	for pid, o := range open {
		sessions = append(sessions, Session{
			ProjectID:   pid,
			ProjectName: o.projectName,
			Start:       o.activatedAt,
			End:         now,
			IsActive:    true,
			DurationSec: int(now.Sub(o.activatedAt).Seconds()),
			Trigger:     o.trigger,
		})
	}

	return sessions
}

// ProjectColor returns a stable RGB color for a project based on its ID hash.
func ProjectColor(projectID string) (r, g, b float32) {
	palette := [][3]float32{
		{0.25, 0.52, 0.96}, // blue
		{0.20, 0.78, 0.35}, // green
		{0.95, 0.61, 0.07}, // orange
		{0.58, 0.35, 0.83}, // purple
		{0.91, 0.30, 0.24}, // red
		{0.16, 0.71, 0.76}, // teal
		{0.86, 0.44, 0.58}, // pink
		{0.47, 0.65, 0.25}, // olive
	}
	h := fnv.New32a()
	h.Write([]byte(projectID))
	c := palette[h.Sum32()%uint32(len(palette))]
	return c[0], c[1], c[2]
}

// WeekBounds returns the Monday 00:00 and next Monday 00:00 for the week
// containing the reference time, adjusted by offset weeks.
func WeekBounds(ref time.Time, offset int) (from, to time.Time) {
	loc := ref.Location()
	weekday := int(ref.Weekday())
	if weekday == 0 {
		weekday = 7
	}
	monday := ref.AddDate(0, 0, -(weekday-1)+offset*7)
	from = time.Date(monday.Year(), monday.Month(), monday.Day(), 0, 0, 0, 0, loc)
	to = from.AddDate(0, 0, 7)
	return
}

// MonthBounds returns the 1st day 00:00 and next month 1st day 00:00 for the
// month containing the reference time, adjusted by offset months.
func MonthBounds(ref time.Time, offset int) (from, to time.Time) {
	loc := ref.Location()
	y, m, _ := ref.Date()
	from = time.Date(y, m+time.Month(offset), 1, 0, 0, 0, 0, loc)
	to = from.AddDate(0, 1, 0)
	return
}
