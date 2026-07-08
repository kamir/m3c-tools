// driver_hook_nocgo.go — pure-Go (modernc.org/sqlite) hot-path handle.
//
//go:build !cgo

package outbox

import (
	"database/sql"

	"github.com/kamir/m3c-tools/internal/dbdriver"
)

// openHotPathDB opens the outbox handle on the modernc driver. modernc pins
// per-connection pragmas via the `_pragma=` DSN form (distinct from mattn's
// `_busy_timeout` — see driver_hook_cgo.go), applied on EVERY physical
// connection by the driver. 250ms, NOT the 5000ms house default (R-2.4): the
// gate must return quickly and spool rather than freeze the harness open.
// SetMaxOpenConns(1) keeps the single pinned connection from being bypassed.
func openHotPathDB(dbPath string) (*sql.DB, error) {
	dsn := dbPath + "?_pragma=busy_timeout(250)&_pragma=journal_mode(WAL)"
	db, err := sql.Open(dbdriver.DriverName(), dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}
