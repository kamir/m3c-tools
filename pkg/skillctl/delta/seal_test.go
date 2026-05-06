package delta

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

func testInventory(skills ...model.SkillDescriptor) *model.Inventory {
	return &model.Inventory{
		ScannedAt:  "2026-04-02T10:00:00Z",
		ScanPaths:  []string{"/tmp/test"},
		Skills:     skills,
		TotalCount: len(skills),
		ByType:     map[string]int{},
		ByProject:  map[string]int{},
	}
}

func TestSealCreatesFiles(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSealStoreAt(dir)
	if err != nil {
		t.Fatalf("NewSealStoreAt: %v", err)
	}

	inv := testInventory(
		skill("proj/alpha", "alpha", "hash-a", "/skills/alpha.md"),
		skill("proj/beta", "beta", "hash-b", "/skills/beta.md"),
	)

	record, err := store.Seal(inv, "test-user")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Verify record fields.
	if record.SealID == "" {
		t.Error("seal ID should not be empty")
	}
	if record.SealedBy != "test-user" {
		t.Errorf("sealed by = %q, want %q", record.SealedBy, "test-user")
	}
	if record.SkillCount != 2 {
		t.Errorf("skill count = %d, want 2", record.SkillCount)
	}
	if record.InventoryHash == "" {
		t.Error("inventory hash should not be empty")
	}

	// Verify files were created.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	sealFiles := 0
	invFiles := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			if len(e.Name()) > 5 && e.Name()[:5] == "seal-" {
				sealFiles++
			}
			if len(e.Name()) > 10 && e.Name()[:10] == "inventory-" {
				invFiles++
			}
		}
	}
	if sealFiles < 1 {
		t.Error("no seal file created")
	}
	if invFiles < 1 {
		t.Error("no inventory file created")
	}
}

func TestLatestSealReturnsMostRecent(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSealStoreAt(dir)
	if err != nil {
		t.Fatalf("NewSealStoreAt: %v", err)
	}

	inv1 := testInventory(
		skill("proj/alpha", "alpha", "hash-a", "/skills/alpha.md"),
	)
	_, err = store.Seal(inv1, "user1")
	if err != nil {
		t.Fatalf("Seal 1: %v", err)
	}

	// Small delay to ensure different timestamps.
	time.Sleep(10 * time.Millisecond)

	inv2 := testInventory(
		skill("proj/alpha", "alpha", "hash-a", "/skills/alpha.md"),
		skill("proj/beta", "beta", "hash-b", "/skills/beta.md"),
	)
	record2, err := store.Seal(inv2, "user2")
	if err != nil {
		t.Fatalf("Seal 2: %v", err)
	}

	latest, latestInv, err := store.LatestSeal()
	if err != nil {
		t.Fatalf("LatestSeal: %v", err)
	}
	if latest == nil {
		t.Fatal("latest seal should not be nil")
	}
	if latest.SealID != record2.SealID {
		t.Errorf("latest seal ID = %q, want %q", latest.SealID, record2.SealID)
	}
	if latest.SealedBy != "user2" {
		t.Errorf("latest sealed by = %q, want %q", latest.SealedBy, "user2")
	}
	if latestInv == nil {
		t.Fatal("latest inventory should not be nil")
	}
	if len(latestInv.Skills) != 2 {
		t.Errorf("latest inventory skills = %d, want 2", len(latestInv.Skills))
	}
}

func TestListSealsInOrder(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSealStoreAt(dir)
	if err != nil {
		t.Fatalf("NewSealStoreAt: %v", err)
	}

	// Create 3 seals with slight delays.
	for i := 0; i < 3; i++ {
		inv := testInventory(
			skill("proj/alpha", "alpha", "hash-a", "/skills/alpha.md"),
		)
		_, err := store.Seal(inv, "user")
		if err != nil {
			t.Fatalf("Seal %d: %v", i, err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	seals, err := store.ListSeals()
	if err != nil {
		t.Fatalf("ListSeals: %v", err)
	}
	if len(seals) != 3 {
		t.Errorf("seal count = %d, want 3", len(seals))
	}

	// Verify chronological order.
	for i := 1; i < len(seals); i++ {
		if seals[i].SealedAt < seals[i-1].SealedAt {
			t.Errorf("seal %d (%s) is before seal %d (%s)",
				i, seals[i].SealedAt, i-1, seals[i-1].SealedAt)
		}
	}
}

func TestSealWithEmptyInventory(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSealStoreAt(dir)
	if err != nil {
		t.Fatalf("NewSealStoreAt: %v", err)
	}

	inv := testInventory()
	record, err := store.Seal(inv, "test-user")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if record.SkillCount != 0 {
		t.Errorf("skill count = %d, want 0", record.SkillCount)
	}

	// Should still be retrievable.
	latest, latestInv, err := store.LatestSeal()
	if err != nil {
		t.Fatalf("LatestSeal: %v", err)
	}
	if latest == nil {
		t.Fatal("latest seal should not be nil")
	}
	if latestInv == nil {
		t.Fatal("latest inventory should not be nil")
	}
	if len(latestInv.Skills) != 0 {
		t.Errorf("latest inventory skills = %d, want 0", len(latestInv.Skills))
	}
}

func TestLatestSealReturnsNilWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSealStoreAt(dir)
	if err != nil {
		t.Fatalf("NewSealStoreAt: %v", err)
	}

	record, inv, err := store.LatestSeal()
	if err != nil {
		t.Fatalf("LatestSeal: %v", err)
	}
	if record != nil {
		t.Error("expected nil record for empty store")
	}
	if inv != nil {
		t.Error("expected nil inventory for empty store")
	}
}

func TestGetSealByID(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSealStoreAt(dir)
	if err != nil {
		t.Fatalf("NewSealStoreAt: %v", err)
	}

	inv := testInventory(
		skill("proj/alpha", "alpha", "hash-a", "/skills/alpha.md"),
	)
	record, err := store.Seal(inv, "user")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, gotInv, err := store.GetSeal(record.SealID)
	if err != nil {
		t.Fatalf("GetSeal: %v", err)
	}
	if got.SealID != record.SealID {
		t.Errorf("got seal ID = %q, want %q", got.SealID, record.SealID)
	}
	if gotInv == nil {
		t.Fatal("got inventory should not be nil")
	}
}

func TestGetSealNotFound(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSealStoreAt(dir)
	if err != nil {
		t.Fatalf("NewSealStoreAt: %v", err)
	}

	_, _, err = store.GetSeal("nonexistent")
	if err == nil {
		t.Error("GetSeal should return error for nonexistent seal")
	}
}
