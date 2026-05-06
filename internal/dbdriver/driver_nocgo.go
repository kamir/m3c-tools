// driver_nocgo.go — SQLite driver registration for pure-Go builds.
// Uses modernc.org/sqlite (no C compiler required, cross-platform).
//
//go:build !cgo

package dbdriver

import (
	_ "modernc.org/sqlite"
)

// DriverName returns the SQL driver name for sql.Open().
func DriverName() string { return "sqlite" }
