package verify

import "time"

// nowISO returns the current UTC date in YYYY-MM-DD form. Split out from
// trustroots.go so tests can swap todayISO without touching the time
// package directly.
func nowISO() string {
	return time.Now().UTC().Format("2006-01-02")
}
