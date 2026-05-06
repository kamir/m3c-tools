package delta

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

// SealRecord captures metadata about a sealed inventory baseline.
type SealRecord struct {
	SealID        string `json:"seal_id"`
	SealedAt      string `json:"sealed_at"`
	SealedBy      string `json:"sealed_by"`
	SkillCount    int    `json:"skill_count"`
	Approved      int    `json:"approved"`
	Rejected      int    `json:"rejected"`
	Deferred      int    `json:"deferred"`
	InventoryHash string `json:"inventory_hash"`
	InventoryPath string `json:"inventory_path"`
}

// SealStore manages persisted seal records and their associated inventories.
type SealStore struct {
	BaseDir string // defaults to ~/.m3c-tools/skill-seals/
}

// NewSealStore creates a SealStore with the default directory
// (~/.m3c-tools/skill-seals/), creating it if needed.
func NewSealStore() (*SealStore, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".m3c-tools", "skill-seals")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating seal store directory: %w", err)
	}
	return &SealStore{BaseDir: dir}, nil
}

// NewSealStoreAt creates a SealStore at a specific directory (useful for testing).
func NewSealStoreAt(dir string) (*SealStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating seal store directory: %w", err)
	}
	return &SealStore{BaseDir: dir}, nil
}

// Seal persists an inventory as a sealed baseline. It writes both the
// inventory JSON and a SealRecord JSON to the store directory.
func (s *SealStore) Seal(inventory *model.Inventory, sealedBy string) (*SealRecord, error) {
	now := time.Now().UTC()
	ts := now.Format("20060102T150405.000Z")

	// Serialize the inventory.
	invData, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling inventory: %w", err)
	}

	// Compute hash of the inventory JSON.
	h := sha256.Sum256(invData)
	invHash := hex.EncodeToString(h[:])

	// Write inventory file.
	invPath := filepath.Join(s.BaseDir, fmt.Sprintf("inventory-%s.json", ts))
	if err := os.WriteFile(invPath, invData, 0o644); err != nil {
		return nil, fmt.Errorf("writing inventory: %w", err)
	}

	// Build seal record.
	record := &SealRecord{
		SealID:        fmt.Sprintf("seal-%s", ts),
		SealedAt:      now.Format("2006-01-02T15:04:05.000Z07:00"),
		SealedBy:      sealedBy,
		SkillCount:    len(inventory.Skills),
		InventoryHash: invHash,
		InventoryPath: invPath,
	}

	// Write seal record.
	sealData, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling seal record: %w", err)
	}
	sealPath := filepath.Join(s.BaseDir, fmt.Sprintf("seal-%s.json", ts))
	if err := os.WriteFile(sealPath, sealData, 0o644); err != nil {
		return nil, fmt.Errorf("writing seal record: %w", err)
	}

	return record, nil
}

// LatestSeal returns the most recent seal record and its associated inventory.
// Returns nil, nil, nil if no seals exist.
func (s *SealStore) LatestSeal() (*SealRecord, *model.Inventory, error) {
	seals, err := s.ListSeals()
	if err != nil {
		return nil, nil, err
	}
	if len(seals) == 0 {
		return nil, nil, nil
	}

	latest := seals[len(seals)-1]
	inv, err := s.loadInventory(latest.InventoryPath)
	if err != nil {
		return nil, nil, fmt.Errorf("loading inventory for seal %s: %w", latest.SealID, err)
	}
	return &latest, inv, nil
}

// ListSeals returns all seal records sorted by timestamp (oldest first).
func (s *SealStore) ListSeals() ([]SealRecord, error) {
	entries, err := os.ReadDir(s.BaseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading seal store: %w", err)
	}

	var seals []SealRecord
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "seal-") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		// Skip inventory files.
		if strings.HasPrefix(e.Name(), "seal-") && !strings.Contains(e.Name(), "inventory") {
			path := filepath.Join(s.BaseDir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var record SealRecord
			if err := json.Unmarshal(data, &record); err != nil {
				continue
			}
			seals = append(seals, record)
		}
	}

	// Sort by SealedAt timestamp.
	sort.Slice(seals, func(i, j int) bool {
		return seals[i].SealedAt < seals[j].SealedAt
	})

	return seals, nil
}

// GetSeal loads a specific seal by its ID.
func (s *SealStore) GetSeal(sealID string) (*SealRecord, *model.Inventory, error) {
	seals, err := s.ListSeals()
	if err != nil {
		return nil, nil, err
	}

	for _, seal := range seals {
		if seal.SealID == sealID {
			inv, err := s.loadInventory(seal.InventoryPath)
			if err != nil {
				return nil, nil, fmt.Errorf("loading inventory for seal %s: %w", sealID, err)
			}
			return &seal, inv, nil
		}
	}
	return nil, nil, fmt.Errorf("seal %q not found", sealID)
}

// loadInventory reads and parses an inventory JSON file.
func (s *SealStore) loadInventory(path string) (*model.Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading inventory file: %w", err)
	}
	var inv model.Inventory
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("parsing inventory JSON: %w", err)
	}
	return &inv, nil
}
