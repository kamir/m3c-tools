// driver_cgo.go — SQLite driver registration for cgo-enabled builds.
// Uses github.com/mattn/go-sqlite3 (C-backed, faster, production-tested).
//
//go:build cgo

package dbdriver

import (
	_ "github.com/mattn/go-sqlite3"
)

// DriverName returns the SQL driver name for sql.Open().
func DriverName() string { return "sqlite3" }
