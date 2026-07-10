// driver_hook_cgo.go — cgo (mattn/go-sqlite3) hot-path handle.
//
//go:build cgo

package outbox

import (
	"database/sql"
	"sync"

	sqlite3 "github.com/mattn/go-sqlite3"
)

// hotPathDriverName is a DISTINCT driver registration wrapping mattn with a
// ConnectHook. We cannot pin busy_timeout via a DSN param alone: mattn parses
// `_busy_timeout` while modernc parses `_pragma=busy_timeout(250)` — a DSN-only
// pin silently fails on one driver. Registering our own driver with a
// ConnectHook makes the pin fire on EVERY physical connection (R-2.4).
const hotPathDriverName = "sqlite3_m3c_outbox"

var registerHookOnce sync.Once

func registerHotPathDriver() {
	registerHookOnce.Do(func() {
		sql.Register(hotPathDriverName, &sqlite3.SQLiteDriver{
			ConnectHook: func(c *sqlite3.SQLiteConn) error {
				// 250ms, NOT the 5000ms house default: a stalled hook would
				// silently fail the harness open (read as ALLOW). The gate must
				// return within ~250ms and spool instead (R-2.4, AC-3).
				_, err := c.Exec("PRAGMA busy_timeout=250", nil)
				return err
			},
		})
	})
}

// openHotPathDB opens the outbox handle with the per-connection busy_timeout pin
// and SetMaxOpenConns(1) so the ONE pinned connection is never bypassed by an
// un-pinned second pool connection.
func openHotPathDB(dbPath string) (*sql.DB, error) {
	registerHotPathDriver()
	db, err := sql.Open(hotPathDriverName, dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}
