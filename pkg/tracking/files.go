// Package tracking provides SQLite-backed file tracking for import deduplication.
// The processed_files table records which files have been imported so that
// subsequent scans can skip already-processed files.
package tracking

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const createFilesTableSQL = `
CREATE TABLE IF NOT EXISTS processed_files (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path    TEXT NOT NULL,
    file_hash    TEXT NOT NULL,
    file_size    INTEGER NOT NULL,
    import_type  TEXT NOT NULL DEFAULT 'audio',
    status       TEXT NOT NULL DEFAULT 'imported',
    memory_id    TEXT,
    processed_at TEXT NOT NULL,
    UNIQUE(file_hash, import_type)
);
CREATE INDEX IF NOT EXISTS idx_processed_files_path ON processed_files(file_path);
CREATE INDEX IF NOT EXISTS idx_processed_files_hash ON processed_files(file_hash);`

// ProcessedFile represents a row in the processed_files table.
type ProcessedFile struct {
	ID          int64
	FilePath    string
	FileHash    string
	FileSize    int64
	ImportType  string
	Status      string
	MemoryID    string
	ProcessedAt time.Time
}

// FilesDB manages the processed_files SQLite table.
// It shares the same database file as ExportsDB but operates on a separate table.
type FilesDB struct {
	db *sql.DB
}

// OpenFilesDB opens (or creates) the SQLite database at the given path
// and ensures the processed_files table exists.
func OpenFilesDB(dbPath string) (*FilesDB, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	if _, err := db.Exec(createFilesTableSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create processed_files table: %w", err)
	}

	return &FilesDB{db: db}, nil
}

// Close closes the underlying database connection.
func (f *FilesDB) Close() error {
	return f.db.Close()
}

// HashFile computes the SHA-256 hash of the file at the given path.
func HashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file for hashing: %w", err)
	}
	defer func() { _ = file.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", fmt.Errorf("hash file: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// RecordFile inserts a processed file record. If a record with the same
// (file_hash, import_type) already exists, the insert is skipped and
// the existing record is returned with a nil error.
func (f *FilesDB) RecordFile(filePath, fileHash string, fileSize int64, importType, memoryID string) (*ProcessedFile, error) {
	if importType == "" {
		importType = "audio"
	}
	now := time.Now().UTC().Format(time.RFC3339)

	_, err := f.db.Exec(`
		INSERT OR IGNORE INTO processed_files (file_path, file_hash, file_size, import_type, status, memory_id, processed_at)
		VALUES (?, ?, ?, ?, 'imported', ?, ?)
	`, filePath, fileHash, fileSize, importType, memoryID, now)
	if err != nil {
		return nil, fmt.Errorf("insert processed file: %w", err)
	}

	// Return the record (whether newly inserted or existing).
	return f.GetByHash(fileHash, importType)
}

// IsFileProcessed checks whether a file with the given hash has already been
// processed for the specified import type. This is the primary deduplication
// check used during batch scans.
func (f *FilesDB) IsFileProcessed(fileHash, importType string) (bool, error) {
	var count int
	err := f.db.QueryRow(`
		SELECT COUNT(*) FROM processed_files WHERE file_hash = ? AND import_type = ?
	`, fileHash, importType).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check processed: %w", err)
	}
	return count > 0, nil
}

// IsPathProcessed checks whether the exact file path has been processed
// for the specified import type. Unlike IsFileProcessed, this checks the
// path rather than the content hash.
func (f *FilesDB) IsPathProcessed(filePath, importType string) (bool, error) {
	var count int
	err := f.db.QueryRow(`
		SELECT COUNT(*) FROM processed_files WHERE file_path = ? AND import_type = ?
	`, filePath, importType).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check path processed: %w", err)
	}
	return count > 0, nil
}

// GetByHash returns the processed file record for a given (file_hash, import_type).
func (f *FilesDB) GetByHash(fileHash, importType string) (*ProcessedFile, error) {
	row := f.db.QueryRow(`
		SELECT id, file_path, file_hash, file_size, import_type, status, memory_id, processed_at
		FROM processed_files WHERE file_hash = ? AND import_type = ?
	`, fileHash, importType)
	return scanFileRecord(row)
}

// GetByPath returns the first processed file record matching the given path.
func (f *FilesDB) GetByPath(filePath string) (*ProcessedFile, error) {
	row := f.db.QueryRow(`
		SELECT id, file_path, file_hash, file_size, import_type, status, memory_id, processed_at
		FROM processed_files WHERE file_path = ? LIMIT 1
	`, filePath)
	return scanFileRecord(row)
}

// UpdateStatus updates the status for a processed file record.
func (f *FilesDB) UpdateStatus(fileHash, importType, status string) error {
	_, err := f.db.Exec(`
		UPDATE processed_files SET status = ? WHERE file_hash = ? AND import_type = ?
	`, status, fileHash, importType)
	return err
}

// UpdateMemoryID sets the ER1 memory ID for a processed file after successful upload.
func (f *FilesDB) UpdateMemoryID(fileHash, importType, memoryID string) error {
	_, err := f.db.Exec(`
		UPDATE processed_files SET memory_id = ?, status = 'uploaded' WHERE file_hash = ? AND import_type = ?
	`, memoryID, fileHash, importType)
	return err
}

// ListFiles returns processed file records, ordered by processed_at descending.
func (f *FilesDB) ListFiles(limit int) ([]ProcessedFile, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := f.db.Query(`
		SELECT id, file_path, file_hash, file_size, import_type, status, memory_id, processed_at
		FROM processed_files ORDER BY processed_at DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var records []ProcessedFile
	for rows.Next() {
		r, err := scanFileRows(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, *r)
	}
	return records, rows.Err()
}

// ListByStatus returns processed files with the given status.
func (f *FilesDB) ListByStatus(status string, limit int) ([]ProcessedFile, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := f.db.Query(`
		SELECT id, file_path, file_hash, file_size, import_type, status, memory_id, processed_at
		FROM processed_files WHERE status = ? ORDER BY processed_at DESC LIMIT ?
	`, status, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var records []ProcessedFile
	for rows.Next() {
		r, err := scanFileRows(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, *r)
	}
	return records, rows.Err()
}

// CountFiles returns the total number of processed files.
func (f *FilesDB) CountFiles() (int, error) {
	var count int
	err := f.db.QueryRow(`SELECT COUNT(*) FROM processed_files`).Scan(&count)
	return count, err
}

// CountFilesByStatus returns the number of processed files with the given status.
func (f *FilesDB) CountFilesByStatus(status string) (int, error) {
	var count int
	err := f.db.QueryRow(`SELECT COUNT(*) FROM processed_files WHERE status = ?`, status).Scan(&count)
	return count, err
}

// RemoveByHash removes a processed file record by its content hash and import type.
func (f *FilesDB) RemoveByHash(fileHash, importType string) error {
	_, err := f.db.Exec(`
		DELETE FROM processed_files WHERE file_hash = ? AND import_type = ?
	`, fileHash, importType)
	return err
}

func scanFileRecord(row *sql.Row) (*ProcessedFile, error) {
	var r ProcessedFile
	var processedAt string
	var memoryID sql.NullString
	err := row.Scan(&r.ID, &r.FilePath, &r.FileHash, &r.FileSize, &r.ImportType, &r.Status, &memoryID, &processedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.ProcessedAt, _ = time.Parse(time.RFC3339, processedAt)
	if memoryID.Valid {
		r.MemoryID = memoryID.String
	}
	return &r, nil
}

func scanFileRows(rows *sql.Rows) (*ProcessedFile, error) {
	var r ProcessedFile
	var processedAt string
	var memoryID sql.NullString
	if err := rows.Scan(&r.ID, &r.FilePath, &r.FileHash, &r.FileSize, &r.ImportType, &r.Status, &memoryID, &processedAt); err != nil {
		return nil, err
	}
	r.ProcessedAt, _ = time.Parse(time.RFC3339, processedAt)
	if memoryID.Valid {
		r.MemoryID = memoryID.String
	}
	return &r, nil
}
