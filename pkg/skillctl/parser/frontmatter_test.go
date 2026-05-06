package parser

import (
	"testing"
)

func TestParseValidFrontmatter(t *testing.T) {
	content := []byte(`---
name: dev-cycle
version: 2.0.0
description: |
  Local dev cycle for builds and testing.
allowed-tools:
  - Bash
  - Read
category: deployment
tags:
  - devops
  - build
---
This is the body text.
`)
	fm, body, err := Parse(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fm == nil {
		t.Fatal("expected frontmatter, got nil")
	}
	if fm.Name != "dev-cycle" {
		t.Errorf("name = %q, want %q", fm.Name, "dev-cycle")
	}
	if fm.Version != "2.0.0" {
		t.Errorf("version = %q, want %q", fm.Version, "2.0.0")
	}
	if len(fm.AllowedTools) != 2 {
		t.Errorf("allowed_tools len = %d, want 2", len(fm.AllowedTools))
	} else {
		if fm.AllowedTools[0] != "Bash" || fm.AllowedTools[1] != "Read" {
			t.Errorf("allowed_tools = %v, want [Bash Read]", fm.AllowedTools)
		}
	}
	if fm.Category != "deployment" {
		t.Errorf("category = %q, want %q", fm.Category, "deployment")
	}
	if len(fm.Tags) != 2 || fm.Tags[0] != "devops" || fm.Tags[1] != "build" {
		t.Errorf("tags = %v, want [devops build]", fm.Tags)
	}
	if body != "This is the body text.\n" {
		t.Errorf("body = %q, want %q", body, "This is the body text.\n")
	}
}

func TestParseNoFrontmatter(t *testing.T) {
	content := []byte("# Just a markdown file\n\nNo frontmatter here.\n")
	fm, body, err := Parse(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fm != nil {
		t.Errorf("expected nil frontmatter, got %+v", fm)
	}
	if body != string(content) {
		t.Errorf("body should equal original content")
	}
}

func TestParseMalformedYAML(t *testing.T) {
	content := []byte(`---
name: [broken
  yaml:: data
---
body text
`)
	fm, _, err := Parse(content)
	if err == nil {
		t.Fatal("expected error for malformed YAML, got nil")
	}
	if fm != nil {
		t.Errorf("expected nil frontmatter on error, got %+v", fm)
	}
}

func TestParseNoClosingDelimiter(t *testing.T) {
	content := []byte(`---
name: orphaned
version: 1.0.0
This never closes
`)
	fm, body, err := Parse(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fm != nil {
		t.Errorf("expected nil frontmatter (no closing ---), got %+v", fm)
	}
	if body != string(content) {
		t.Errorf("body should equal original content when no closing delimiter")
	}
}

func TestParseEmptyFrontmatter(t *testing.T) {
	content := []byte(`---
---
body only
`)
	fm, body, err := Parse(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Empty YAML block: frontmatter is nil because yaml.Decode returns EOF
	// on empty input; we treat that as "no frontmatter parsed"
	if fm != nil && fm.Name != "" {
		t.Errorf("expected empty/nil frontmatter, got %+v", fm)
	}
	_ = body
}

func TestParseMinimalFrontmatter(t *testing.T) {
	content := []byte(`---
name: simple
---
`)
	fm, _, err := Parse(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fm == nil {
		t.Fatal("expected frontmatter, got nil")
	}
	if fm.Name != "simple" {
		t.Errorf("name = %q, want %q", fm.Name, "simple")
	}
	if fm.Version != "" {
		t.Errorf("version should be empty, got %q", fm.Version)
	}
}
