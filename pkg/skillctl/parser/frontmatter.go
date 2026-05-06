// Package parser extracts YAML frontmatter from markdown skill files.
package parser

import (
	"bytes"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
	"gopkg.in/yaml.v3"
)

// Parse extracts YAML frontmatter from content delimited by --- markers.
// Returns the parsed Frontmatter, the remaining body text, and any error.
// If no frontmatter is found, fm is nil and body is the full content.
func Parse(content []byte) (fm *model.Frontmatter, body string, err error) {
	s := string(content)

	// Frontmatter must start at the very beginning of the file with ---
	if !strings.HasPrefix(s, "---") {
		return nil, s, nil
	}

	// Find the closing --- delimiter.
	// Skip the first line (the opening ---) and look for \n---
	rest := s[3:]
	// Trim the newline after the opening ---
	if len(rest) > 0 && rest[0] == '\n' {
		rest = rest[1:]
	} else if len(rest) > 1 && rest[0] == '\r' && rest[1] == '\n' {
		rest = rest[2:]
	}

	closeIdx := strings.Index(rest, "\n---")
	if closeIdx < 0 {
		// No closing delimiter — treat as no frontmatter
		return nil, s, nil
	}

	yamlBlock := rest[:closeIdx]
	// Body starts after the closing ---\n
	afterClose := rest[closeIdx+4:] // len("\n---") == 4
	if len(afterClose) > 0 && afterClose[0] == '\n' {
		afterClose = afterClose[1:]
	} else if len(afterClose) > 1 && afterClose[0] == '\r' && afterClose[1] == '\n' {
		afterClose = afterClose[2:]
	}

	var parsed model.Frontmatter
	decoder := yaml.NewDecoder(bytes.NewReader([]byte(yamlBlock)))
	if err := decoder.Decode(&parsed); err != nil {
		return nil, s, err
	}

	return &parsed, afterClose, nil
}
