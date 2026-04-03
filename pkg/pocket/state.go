package pocket

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"
)

// GroupState tracks the mapping between local recording groups and ER1 items.
type GroupState struct {
	Groups []GroupMapping `json:"groups"`
}

// GroupMapping links a local group to its ER1 document.
type GroupMapping struct {
	GroupID    string   `json:"group_id"`
	DocID      string   `json:"doc_id"`       // ER1 document ID
	Title      string   `json:"title"`
	CreatedAt  string   `json:"created_at"`
	FilePaths  []string `json:"file_paths"`   // source recordings in this group
	MergedPath string   `json:"merged_path"`  // local merged file
	Segments   int      `json:"segments"`
	Tags       string   `json:"tags,omitempty"` // comma-separated tags used at upload
}

// SaveGroupMapping persists a group→ER1 item mapping to the state file.
func SaveGroupMapping(group RecordingGroup, docID string, cfg *Config, tags ...string) {
	statePath := filepath.Join(cfg.StagingDir, "groups.json")

	state := loadGroupState(statePath)

	var paths []string
	for _, rec := range group.Recordings {
		paths = append(paths, rec.FilePath)
	}

	tagsStr := ""
	if len(tags) > 0 {
		tagsStr = tags[0]
	}
	mapping := GroupMapping{
		GroupID:    group.ID,
		DocID:      docID,
		Title:      group.Title,
		CreatedAt:  time.Now().Format(time.RFC3339),
		FilePaths:  paths,
		MergedPath: filepath.Join(cfg.MergedDir, group.ID+".mp3"),
		Segments:   len(group.Recordings),
		Tags:       tagsStr,
	}

	state.Groups = append(state.Groups, mapping)

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		log.Printf("[pocket] marshal group state: %v", err)
		return
	}
	if err := os.WriteFile(statePath, data, 0644); err != nil {
		log.Printf("[pocket] write group state: %v", err)
		return
	}
	log.Printf("[pocket] saved group mapping: %s → %s (%d segments)", group.ID, docID, len(group.Recordings))
}

// LoadGroupState reads the group state file.
func LoadGroupState(cfg *Config) *GroupState {
	statePath := filepath.Join(cfg.StagingDir, "groups.json")
	return loadGroupState(statePath)
}

// FindGroupByFilePath returns the group mapping that contains the given file path.
// Checks both the exact path and the staged path variant.
func FindGroupByFilePath(filePath string, cfg *Config) *GroupMapping {
	state := LoadGroupState(cfg)
	for i, g := range state.Groups {
		for _, p := range g.FilePaths {
			if p == filePath {
				return &state.Groups[i]
			}
		}
	}
	return nil
}

// FindGroupByStagedPath returns the group mapping that contains a recording
// by matching both its device path and its staged path against group file paths.
// This handles the case where groups.json stores staged paths while the scan
// returns device paths (or vice versa).
func FindGroupByStagedPath(rec Recording, cfg *Config, state *GroupState) *GroupMapping {
	if state == nil {
		state = LoadGroupState(cfg)
	}
	stagedPath := StagedPath(rec, cfg)
	for i, g := range state.Groups {
		for _, p := range g.FilePaths {
			if p == rec.FilePath || p == stagedPath {
				return &state.Groups[i]
			}
		}
	}
	return nil
}

func loadGroupState(path string) *GroupState {
	data, err := os.ReadFile(path)
	if err != nil {
		return &GroupState{}
	}
	var state GroupState
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("[pocket] parse group state: %v", err)
		return &GroupState{}
	}
	return &state
}
