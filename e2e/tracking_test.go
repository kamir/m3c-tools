package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/tracking"
)

func TestExportsDBCreateAndQuery(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_exports.db")

	db, err := tracking.OpenExportsDB(dbPath)
	if err != nil {
		t.Fatalf("OpenExportsDB: %v", err)
	}
	defer db.Close()

	// Verify DB file was created.
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("DB file not created: %v", err)
	}

	// Insert a record.
	rec, err := db.RecordExport("dQw4w9WgXcQ", "MEMORY-20260309-120000", "transcript", "youtube,music")
	if err != nil {
		t.Fatalf("RecordExport: %v", err)
	}
	if rec.VideoID != "dQw4w9WgXcQ" {
		t.Errorf("VideoID = %q, want dQw4w9WgXcQ", rec.VideoID)
	}
	if rec.MemoryID != "MEMORY-20260309-120000" {
		t.Errorf("MemoryID = %q, want MEMORY-20260309-120000", rec.MemoryID)
	}
	if rec.ExportType != "transcript" {
		t.Errorf("ExportType = %q, want transcript", rec.ExportType)
	}
	if rec.ER1Status != "uploaded" {
		t.Errorf("ER1Status = %q, want uploaded", rec.ER1Status)
	}
	if rec.ExportedAt.IsZero() {
		t.Error("ExportedAt is zero")
	}

	// Query it back.
	got, err := db.GetExport("dQw4w9WgXcQ")
	if err != nil {
		t.Fatalf("GetExport: %v", err)
	}
	if got == nil {
		t.Fatal("GetExport returned nil")
	}
	if got.Tags != "youtube,music" {
		t.Errorf("Tags = %q, want youtube,music", got.Tags)
	}

	// Query non-existent.
	missing, err := db.GetExport("nonexistent")
	if err != nil {
		t.Fatalf("GetExport for missing: %v", err)
	}
	if missing != nil {
		t.Error("Expected nil for non-existent video_id")
	}
}

func TestExportsDBUpsert(t *testing.T) {
	db, err := tracking.OpenExportsDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenExportsDB: %v", err)
	}
	defer db.Close()

	// Insert initial record.
	_, err = db.RecordExport("vid1", "MEM-001", "transcript", "tag1")
	if err != nil {
		t.Fatalf("First insert: %v", err)
	}

	// Upsert same (video_id, export_type) with new memory_id.
	_, err = db.RecordExport("vid1", "MEM-002", "transcript", "tag1,tag2")
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Should only have one record.
	records, err := db.ListExports(100)
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("Expected 1 record after upsert, got %d", len(records))
	}
	if records[0].MemoryID != "MEM-002" {
		t.Errorf("MemoryID = %q, want MEM-002", records[0].MemoryID)
	}

	// Different export_type should create a new record.
	_, err = db.RecordExport("vid1", "MEM-003", "impression", "tag3")
	if err != nil {
		t.Fatalf("Insert impression: %v", err)
	}
	records, err = db.ListExports(100)
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	if len(records) != 2 {
		t.Errorf("Expected 2 records, got %d", len(records))
	}
}

func TestExportsDBUpdateStatus(t *testing.T) {
	db, err := tracking.OpenExportsDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenExportsDB: %v", err)
	}
	defer db.Close()

	_, err = db.RecordExport("vid1", "MEM-001", "transcript", "tags")
	if err != nil {
		t.Fatal(err)
	}

	// Update status.
	err = db.UpdateStatus("vid1", "transcript", "failed")
	if err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}

	rec, err := db.GetExportByType("vid1", "transcript")
	if err != nil {
		t.Fatal(err)
	}
	if rec.ER1Status != "failed" {
		t.Errorf("ER1Status = %q, want failed", rec.ER1Status)
	}
}

func TestExportsDBCountByStatus(t *testing.T) {
	db, err := tracking.OpenExportsDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenExportsDB: %v", err)
	}
	defer db.Close()

	db.RecordExport("v1", "M1", "transcript", "")
	db.RecordExport("v2", "M2", "transcript", "")
	db.RecordExport("v3", "M3", "impression", "")
	db.UpdateStatus("v2", "transcript", "failed")

	uploaded, err := db.CountByStatus("uploaded")
	if err != nil {
		t.Fatal(err)
	}
	if uploaded != 2 {
		t.Errorf("uploaded count = %d, want 2", uploaded)
	}

	failed, err := db.CountByStatus("failed")
	if err != nil {
		t.Fatal(err)
	}
	if failed != 1 {
		t.Errorf("failed count = %d, want 1", failed)
	}
}

func TestExportsDBDefaultPath(t *testing.T) {
	p := tracking.DefaultDBPath()
	if p == "" {
		t.Error("DefaultDBPath returned empty string")
	}
	if filepath.Base(p) != "exports.db" {
		t.Errorf("DefaultDBPath base = %q, want exports.db", filepath.Base(p))
	}
	t.Logf("Default DB path: %s", p)
}
