// Package tracking provides SQLite-backed export tracking for ER1 uploads.
// It records which videos/observations have been exported, preventing
// duplicate uploads and enabling status queries.
package tracking

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kamir/m3c-tools/internal/dbdriver"
)

const createTableSQL = `
CREATE TABLE IF NOT EXISTS er1_exports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    video_id    TEXT NOT NULL,
    memory_id   TEXT NOT NULL,
    export_type TEXT NOT NULL DEFAULT 'transcript',
    tags        TEXT,
    er1_status  TEXT NOT NULL DEFAULT 'uploaded',
    exported_at TEXT NOT NULL,
    UNIQUE(video_id, export_type)
);`

// ExportRecord represents a row in the er1_exports table.
type ExportRecord struct {
	ID         int64
	VideoID    string
	MemoryID   string
	ExportType string
	Tags       string
	ER1Status  string
	ExportedAt time.Time
}

// ExportsDB manages the er1_exports SQLite table.
type ExportsDB struct {
	db *sql.DB
}

// DefaultDBPath returns the default path for exports.db: ~/.m3c-tools/exports.db.
func DefaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".m3c-tools", "exports.db")
}

// OpenExportsDB opens (or creates) the SQLite database at the given path
// and ensures the er1_exports table exists.
func OpenExportsDB(dbPath string) (*ExportsDB, error) {
	// Ensure parent directory exists.
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	sqlDB, err := sql.Open(dbdriver.DriverName(), dbPath+"?_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	if _, err := sqlDB.Exec(createTableSQL); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("create table: %w", err)
	}

	return &ExportsDB{db: sqlDB}, nil
}

// Close closes the underlying database connection.
func (e *ExportsDB) Close() error {
	return e.db.Close()
}

// RecordExport inserts a new export record. If a record with the same
// (video_id, export_type) already exists, it is replaced.
func (e *ExportsDB) RecordExport(videoID, memoryID, exportType, tags string) (*ExportRecord, error) {
	if exportType == "" {
		exportType = "transcript"
	}
	now := time.Now().UTC().Format(time.RFC3339)

	res, err := e.db.Exec(`
		INSERT INTO er1_exports (video_id, memory_id, export_type, tags, er1_status, exported_at)
		VALUES (?, ?, ?, ?, 'uploaded', ?)
		ON CONFLICT(video_id, export_type) DO UPDATE SET
			memory_id   = excluded.memory_id,
			tags        = excluded.tags,
			er1_status  = excluded.er1_status,
			exported_at = excluded.exported_at
	`, videoID, memoryID, exportType, tags, now)
	if err != nil {
		return nil, fmt.Errorf("insert export: %w", err)
	}

	id, _ := res.LastInsertId()
	exportedAt, _ := time.Parse(time.RFC3339, now)

	return &ExportRecord{
		ID:         id,
		VideoID:    videoID,
		MemoryID:   memoryID,
		ExportType: exportType,
		Tags:       tags,
		ER1Status:  "uploaded",
		ExportedAt: exportedAt,
	}, nil
}

// GetExport returns the export record for a given video_id, or nil if not found.
func (e *ExportsDB) GetExport(videoID string) (*ExportRecord, error) {
	row := e.db.QueryRow(`
		SELECT id, video_id, memory_id, export_type, tags, er1_status, exported_at
		FROM er1_exports WHERE video_id = ? LIMIT 1
	`, videoID)
	return scanRecord(row)
}

// GetExportByType returns the export record for a given (video_id, export_type).
func (e *ExportsDB) GetExportByType(videoID, exportType string) (*ExportRecord, error) {
	row := e.db.QueryRow(`
		SELECT id, video_id, memory_id, export_type, tags, er1_status, exported_at
		FROM er1_exports WHERE video_id = ? AND export_type = ?
	`, videoID, exportType)
	return scanRecord(row)
}

// UpdateStatus updates the er1_status for a given record.
func (e *ExportsDB) UpdateStatus(videoID, exportType, status string) error {
	_, err := e.db.Exec(`
		UPDATE er1_exports SET er1_status = ? WHERE video_id = ? AND export_type = ?
	`, status, videoID, exportType)
	return err
}

// ListExports returns all export records, ordered by exported_at descending.
func (e *ExportsDB) ListExports(limit int) ([]ExportRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := e.db.Query(`
		SELECT id, video_id, memory_id, export_type, tags, er1_status, exported_at
		FROM er1_exports ORDER BY exported_at DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var records []ExportRecord
	for rows.Next() {
		var r ExportRecord
		var exportedAt string
		if err := rows.Scan(&r.ID, &r.VideoID, &r.MemoryID, &r.ExportType, &r.Tags, &r.ER1Status, &exportedAt); err != nil {
			return nil, err
		}
		r.ExportedAt, _ = time.Parse(time.RFC3339, exportedAt)
		records = append(records, r)
	}
	return records, rows.Err()
}

// CountByStatus returns the number of exports with the given status.
func (e *ExportsDB) CountByStatus(status string) (int, error) {
	var count int
	err := e.db.QueryRow(`SELECT COUNT(*) FROM er1_exports WHERE er1_status = ?`, status).Scan(&count)
	return count, err
}

func scanRecord(row *sql.Row) (*ExportRecord, error) {
	var r ExportRecord
	var exportedAt string
	err := row.Scan(&r.ID, &r.VideoID, &r.MemoryID, &r.ExportType, &r.Tags, &r.ER1Status, &exportedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.ExportedAt, _ = time.Parse(time.RFC3339, exportedAt)
	return &r, nil
}
