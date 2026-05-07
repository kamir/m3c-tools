package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validSkillBody = `---
name: didactic-session
version: 1.0.0
description: Scaffolds a live training session for a specific role-track
governance_level: yellow
---

# didactic-session

Body content.
`

func writePropSkill(t *testing.T, body string, withSmoke bool) string {
	t.Helper()
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "didactic-session")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if withSmoke {
		smokeDir := filepath.Join(dir, "tests")
		_ = os.MkdirAll(smokeDir, 0o755)
		_ = os.WriteFile(filepath.Join(smokeDir, "smoke.sh"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	}
	return dir
}

func TestRunPropose_DryRunOnPassingGate(t *testing.T) {
	dir := writePropSkill(t, validSkillBody, true)
	var stdout, stderr bytes.Buffer
	args := []string{
		"didactic-session",
		"--source", dir,
		"--intent", "yellow",
		"--rationale", "weekly iteration",
		"--dry-run",
	}
	if got := runPropose(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("exit = %d, want 0; stderr=%q out=%q", got, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "All gate checks passed") {
		t.Errorf("expected pass banner; got: %q", stdout.String())
	}
}

func TestRunPropose_GateFailureExits2(t *testing.T) {
	dir := writePropSkill(t, validSkillBody, false /* no smoke */)
	var stdout, stderr bytes.Buffer
	args := []string{
		"didactic-session",
		"--source", dir,
		"--intent", "yellow",
		"--rationale", "weekly iteration",
		"--dry-run",
	}
	if got := runPropose(args, &stdout, &stderr); got != exitUsage {
		t.Fatalf("exit = %d, want 2 (usage); out=%q", got, stdout.String())
	}
	if !strings.Contains(stdout.String(), "Gate failed") {
		t.Errorf("expected fail banner; got: %q", stdout.String())
	}
}

func TestRunPropose_PostsToProposalsEndpointOnPass(t *testing.T) {
	dir := writePropSkill(t, validSkillBody, true)
	var captured proposalRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/proposals") {
			http.Error(w, "wrong path: "+r.URL.Path, http.StatusBadRequest)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"proposal_id":"` + captured.ProposalID + `","state":"pending","proposed_at":"2026-05-06T15:00:00Z"}`))
	}))
	defer srv.Close()

	// Override HOME so the notify-queue write lands in the test's tmpdir,
	// not the operator's real ~/.m3c-tools.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	var stdout, stderr bytes.Buffer
	args := []string{
		"didactic-session",
		"--source", dir,
		"--intent", "yellow",
		"--rationale", "weekly iteration",
		"--registry", srv.URL + "/api/skills",
	}
	if got := runPropose(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("exit = %d, want 0; stderr=%q out=%q", got, stderr.String(), stdout.String())
	}

	if captured.SkillName != "didactic-session" {
		t.Errorf("skill_name = %q, want didactic-session", captured.SkillName)
	}
	if captured.AuthorIntent != "yellow" {
		t.Errorf("author_intent = %q, want yellow", captured.AuthorIntent)
	}
	if captured.ProposalID == "" {
		t.Errorf("proposal_id should be auto-generated, got empty")
	}
	if captured.SkillVersion != "1.0.0" {
		t.Errorf("skill_version = %q, want 1.0.0 (read from SKILL.md frontmatter)", captured.SkillVersion)
	}

	// Notify queue file should exist with one entry.
	queue, err := os.ReadFile(filepath.Join(tmpHome, ".m3c-tools", "notify-queue.jsonl"))
	if err != nil {
		t.Fatalf("notify queue not written: %v", err)
	}
	if !strings.Contains(string(queue), captured.ProposalID) {
		t.Errorf("notify queue should mention proposal_id; got: %q", string(queue))
	}
}

func TestRunPropose_ServerErrorReturns1(t *testing.T) {
	dir := writePropSkill(t, validSkillBody, true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal", http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("HOME", t.TempDir())

	var stdout, stderr bytes.Buffer
	args := []string{
		"didactic-session",
		"--source", dir,
		"--intent", "yellow",
		"--rationale", "x",
		"--registry", srv.URL + "/api/skills",
	}
	if got := runPropose(args, &stdout, &stderr); got != exitGeneric {
		t.Errorf("exit = %d, want 1 (generic) on server 500", got)
	}
}

func TestRunPropose_MissingSkillNameExits2(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := runPropose([]string{"--intent", "yellow"}, &stdout, &stderr); got != exitUsage {
		t.Errorf("exit = %d, want 2; stderr=%q", got, stderr.String())
	}
}
