package e2e

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/tracking"
)

// buildBinary builds the m3c-tools binary and returns the path.
// It reuses a cached binary within the test temp directory.
func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "m3c-tools")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/m3c-tools/")
	cmd.Dir = filepath.Join("..")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

// TestScheduleCommand tests that the "schedule" CLI command creates an entry
// in the SQLite retry queue with correct fields.
func TestScheduleCommand(t *testing.T) {
	bin := buildBinary(t)
	dbPath := filepath.Join(t.TempDir(), "test-schedule.db")

	// Schedule an entry via CLI
	cmd := exec.Command(bin, "schedule", "upload-e2e-001",
		"--transcript", "/tmp/transcript.txt",
		"--audio", "/tmp/audio.wav",
		"--image", "/tmp/thumb.jpg",
		"--tags", "youtube,e2e-test",
		"--max-attempts", "5",
		"--db", dbPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("schedule command failed: %v\n%s", err, out)
	}

	output := string(out)
	if !strings.Contains(output, "Scheduled retry entry:") {
		t.Errorf("Expected 'Scheduled retry entry:' in output, got:\n%s", output)
	}
	if !strings.Contains(output, "upload-e2e-001") {
		t.Errorf("Expected entry_id in output, got:\n%s", output)
	}
	if !strings.Contains(output, "status:       pending") {
		t.Errorf("Expected status pending in output, got:\n%s", output)
	}

	// Verify SQLite state directly
	db, err := tracking.OpenRetryQueueDB(dbPath)
	if err != nil {
		t.Fatalf("OpenRetryQueueDB: %v", err)
	}
	defer db.Close()

	entry, err := db.GetByEntryID("upload-e2e-001")
	if err != nil {
		t.Fatalf("GetByEntryID: %v", err)
	}
	if entry == nil {
		t.Fatal("Entry not found in SQLite after schedule command")
	}
	if entry.Status != tracking.RetryStatusPending {
		t.Errorf("Status = %q, want pending", entry.Status)
	}
	if entry.TranscriptPath != "/tmp/transcript.txt" {
		t.Errorf("TranscriptPath = %q, want /tmp/transcript.txt", entry.TranscriptPath)
	}
	if entry.AudioPath != "/tmp/audio.wav" {
		t.Errorf("AudioPath = %q, want /tmp/audio.wav", entry.AudioPath)
	}
	if entry.ImagePath != "/tmp/thumb.jpg" {
		t.Errorf("ImagePath = %q, want /tmp/thumb.jpg", entry.ImagePath)
	}
	if entry.Tags != "youtube,e2e-test" {
		t.Errorf("Tags = %q, want youtube,e2e-test", entry.Tags)
	}
	if entry.MaxAttempts != 5 {
		t.Errorf("MaxAttempts = %d, want 5", entry.MaxAttempts)
	}
	if entry.Attempts != 0 {
		t.Errorf("Attempts = %d, want 0", entry.Attempts)
	}
	t.Logf("Schedule command created entry: %s (status=%s, max=%d)", entry.EntryID, entry.Status, entry.MaxAttempts)
}

// TestScheduleCommandDuplicate verifies that scheduling a duplicate entry_id fails.
func TestScheduleCommandDuplicate(t *testing.T) {
	bin := buildBinary(t)
	dbPath := filepath.Join(t.TempDir(), "test-dup.db")

	// First schedule — should succeed
	cmd := exec.Command(bin, "schedule", "dup-001",
		"--transcript", "/tmp/t.txt",
		"--db", dbPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("first schedule failed: %v\n%s", err, out)
	}

	// Second schedule with same ID — should fail
	cmd2 := exec.Command(bin, "schedule", "dup-001",
		"--transcript", "/tmp/t2.txt",
		"--db", dbPath,
	)
	out2, err2 := cmd2.CombinedOutput()
	if err2 == nil {
		t.Fatalf("Expected error for duplicate entry_id, got success:\n%s", out2)
	}
	if !strings.Contains(string(out2), "Error scheduling entry") {
		t.Errorf("Expected scheduling error message, got:\n%s", out2)
	}
	t.Log("Duplicate entry_id correctly rejected")
}

// TestScheduleCommandMissingTranscript verifies that schedule fails without --transcript.
func TestScheduleCommandMissingTranscript(t *testing.T) {
	bin := buildBinary(t)
	dbPath := filepath.Join(t.TempDir(), "test-missing.db")

	cmd := exec.Command(bin, "schedule", "missing-001", "--db", dbPath)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("Expected error for missing --transcript, got success:\n%s", out)
	}
	if !strings.Contains(string(out), "--transcript is required") {
		t.Errorf("Expected transcript required error, got:\n%s", out)
	}
}

// TestStatusCommand tests the "status" CLI command for listing and querying entries.
func TestStatusCommand(t *testing.T) {
	bin := buildBinary(t)
	dbPath := filepath.Join(t.TempDir(), "test-status.db")

	// Schedule two entries
	for _, id := range []string{"status-001", "status-002"} {
		cmd := exec.Command(bin, "schedule", id,
			"--transcript", "/tmp/"+id+".txt",
			"--tags", "test",
			"--db", dbPath,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("schedule %s failed: %v\n%s", id, err, out)
		}
	}

	// Status without --entry — should show summary
	cmd := exec.Command(bin, "status", "--db", dbPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("status command failed: %v\n%s", err, out)
	}

	output := string(out)
	if !strings.Contains(output, "ER1 Retry Queue Status:") {
		t.Errorf("Expected status header, got:\n%s", output)
	}
	if !strings.Contains(output, "pending:   2") {
		t.Errorf("Expected 2 pending, got:\n%s", output)
	}
	if !strings.Contains(output, "total:     2") {
		t.Errorf("Expected total 2, got:\n%s", output)
	}
	if !strings.Contains(output, "status-001") {
		t.Errorf("Expected status-001 in entry list, got:\n%s", output)
	}
	if !strings.Contains(output, "status-002") {
		t.Errorf("Expected status-002 in entry list, got:\n%s", output)
	}

	// Status with --entry — should show specific entry
	cmd2 := exec.Command(bin, "status", "--entry", "status-001", "--db", dbPath)
	out2, err2 := cmd2.CombinedOutput()
	if err2 != nil {
		t.Fatalf("status --entry failed: %v\n%s", err2, out2)
	}

	output2 := string(out2)
	if !strings.Contains(output2, "Entry: status-001") {
		t.Errorf("Expected 'Entry: status-001', got:\n%s", output2)
	}
	if !strings.Contains(output2, "status:       pending") {
		t.Errorf("Expected pending status, got:\n%s", output2)
	}
	if !strings.Contains(output2, "attempts:     0/10") {
		t.Errorf("Expected 0/10 attempts, got:\n%s", output2)
	}

	t.Logf("Status command output:\n%s", output)
}

// TestStatusCommandEntryNotFound verifies that status --entry for non-existent ID fails.
func TestStatusCommandEntryNotFound(t *testing.T) {
	bin := buildBinary(t)
	dbPath := filepath.Join(t.TempDir(), "test-notfound.db")

	// Create DB by scheduling something first
	cmd := exec.Command(bin, "schedule", "exists-001",
		"--transcript", "/tmp/t.txt",
		"--db", dbPath,
	)
	cmd.CombinedOutput()

	// Query non-existent
	cmd2 := exec.Command(bin, "status", "--entry", "nonexistent", "--db", dbPath)
	out, err := cmd2.CombinedOutput()
	if err == nil {
		t.Fatalf("Expected error for non-existent entry, got:\n%s", out)
	}
	if !strings.Contains(string(out), "Entry not found") {
		t.Errorf("Expected 'Entry not found', got:\n%s", out)
	}
}

// TestCancelCommand tests the "cancel" CLI command and verifies SQLite state.
func TestCancelCommand(t *testing.T) {
	bin := buildBinary(t)
	dbPath := filepath.Join(t.TempDir(), "test-cancel.db")

	// Schedule an entry
	cmd := exec.Command(bin, "schedule", "cancel-001",
		"--transcript", "/tmp/t.txt",
		"--tags", "to-cancel",
		"--db", dbPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("schedule failed: %v\n%s", err, out)
	}

	// Cancel it
	cmd2 := exec.Command(bin, "cancel", "cancel-001", "--db", dbPath)
	out2, err2 := cmd2.CombinedOutput()
	if err2 != nil {
		t.Fatalf("cancel command failed: %v\n%s", err2, out2)
	}
	if !strings.Contains(string(out2), "Cancelled entry: cancel-001") {
		t.Errorf("Expected cancellation confirmation, got:\n%s", out2)
	}

	// Verify SQLite state — should be "cancelled"
	db, err := tracking.OpenRetryQueueDB(dbPath)
	if err != nil {
		t.Fatalf("OpenRetryQueueDB: %v", err)
	}
	defer db.Close()

	entry, err := db.GetByEntryID("cancel-001")
	if err != nil {
		t.Fatalf("GetByEntryID: %v", err)
	}
	if entry == nil {
		t.Fatal("Entry not found after cancel")
	}
	if entry.Status != "cancelled" {
		t.Errorf("Status = %q, want cancelled", entry.Status)
	}

	// Cancelled entry should NOT appear in pending queries
	pending, err := db.QueryPending(10)
	if err != nil {
		t.Fatalf("QueryPending: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("Expected 0 pending after cancel, got %d", len(pending))
	}

	t.Logf("Cancel command set status to %q", entry.Status)
}

// TestCancelCommandNotFound verifies that cancelling a non-existent entry fails.
func TestCancelCommandNotFound(t *testing.T) {
	bin := buildBinary(t)
	dbPath := filepath.Join(t.TempDir(), "test-cancel-notfound.db")

	// Create DB
	cmd := exec.Command(bin, "schedule", "exists-001",
		"--transcript", "/tmp/t.txt",
		"--db", dbPath,
	)
	cmd.CombinedOutput()

	// Cancel non-existent
	cmd2 := exec.Command(bin, "cancel", "nonexistent", "--db", dbPath)
	out, err := cmd2.CombinedOutput()
	if err == nil {
		t.Fatalf("Expected error for non-existent entry, got:\n%s", out)
	}
	if !strings.Contains(string(out), "Entry not found") {
		t.Errorf("Expected 'Entry not found', got:\n%s", out)
	}
}

// TestScheduleStatusCancelWorkflow tests the full workflow: schedule → status → cancel → status.
func TestScheduleStatusCancelWorkflow(t *testing.T) {
	bin := buildBinary(t)
	dbPath := filepath.Join(t.TempDir(), "test-workflow.db")

	// Step 1: Schedule
	cmd := exec.Command(bin, "schedule", "workflow-001",
		"--transcript", "/tmp/transcript.txt",
		"--audio", "/tmp/audio.wav",
		"--tags", "workflow,test",
		"--max-attempts", "3",
		"--db", dbPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("schedule failed: %v\n%s", err, out)
	}

	// Step 2: Status — should show 1 pending
	cmd2 := exec.Command(bin, "status", "--db", dbPath)
	out2, err2 := cmd2.CombinedOutput()
	if err2 != nil {
		t.Fatalf("status failed: %v\n%s", err2, out2)
	}
	if !strings.Contains(string(out2), "pending:   1") {
		t.Errorf("Expected 1 pending before cancel, got:\n%s", out2)
	}

	// Step 3: Cancel
	cmd3 := exec.Command(bin, "cancel", "workflow-001", "--db", dbPath)
	out3, err3 := cmd3.CombinedOutput()
	if err3 != nil {
		t.Fatalf("cancel failed: %v\n%s", err3, out3)
	}

	// Step 4: Status after cancel — should show 0 pending, entry listed as cancelled
	cmd4 := exec.Command(bin, "status", "--db", dbPath)
	out4, err4 := cmd4.CombinedOutput()
	if err4 != nil {
		t.Fatalf("status after cancel failed: %v\n%s", err4, out4)
	}
	output4 := string(out4)
	if !strings.Contains(output4, "pending:   0") {
		t.Errorf("Expected 0 pending after cancel, got:\n%s", output4)
	}

	// Verify via SQLite directly
	db, err := tracking.OpenRetryQueueDB(dbPath)
	if err != nil {
		t.Fatalf("OpenRetryQueueDB: %v", err)
	}
	defer db.Close()

	entry, _ := db.GetByEntryID("workflow-001")
	if entry == nil {
		t.Fatal("Entry not found in DB")
	}
	if entry.Status != "cancelled" {
		t.Errorf("Final status = %q, want cancelled", entry.Status)
	}
	if entry.Tags != "workflow,test" {
		t.Errorf("Tags = %q, want workflow,test", entry.Tags)
	}

	t.Logf("Full workflow completed: schedule → status → cancel → verified")
}
