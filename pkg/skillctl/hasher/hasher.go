// Package hasher provides content hashing and duplicate detection for skills.
package hasher

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

// ContentHash returns the SHA256 hex digest of the raw data.
func ContentHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// ContentID returns the SHA256 hex digest of normalized content
// (trimmed whitespace and lowercased) for fuzzy duplicate detection.
func ContentID(data []byte) string {
	normalized := strings.ToLower(strings.TrimSpace(string(data)))
	h := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(h[:])
}

// DetectDuplicates compares content hashes across skills and sets the
// DuplicateOf field on any skill whose ContentHash matches an earlier skill.
func DetectDuplicates(skills []model.SkillDescriptor) {
	// Map from content hash to the ID of the first skill with that hash.
	seen := make(map[string]string)
	for i := range skills {
		hash := skills[i].ContentHash
		if hash == "" {
			continue
		}
		if firstID, exists := seen[hash]; exists {
			dup := firstID
			skills[i].DuplicateOf = &dup
		} else {
			seen[hash] = skills[i].ID
		}
	}
}
