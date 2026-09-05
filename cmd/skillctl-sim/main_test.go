package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `make sim` passes -skillctl build/skillctl, a RELATIVE path. Every scenario
// runs in its own throwaway world with its own working directory, so the path
// resolved against a directory that does not hold the binary and every exec
// failed with "no such file or directory". The run still ended 0. Absolutising
// here is what makes the documented entry point work at all.
func TestResolveBinaryAbsolutisesARelativePath(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "skillctl")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	got, err := resolveBinary("skillctl")
	if err != nil {
		t.Fatalf("resolveBinary: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("the binary path must be absolute, got %q", got)
	}
	// It must still point at the same file after a change of directory.
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(got); err != nil {
		t.Errorf("the resolved path must survive a change of working directory: %v", err)
	}
}

// Fail once, here, with the path in hand, rather than a hundred times inside the
// workers where the error was swallowed into a per-scenario field nobody printed.
func TestResolveBinaryRejectsWhatItCannotRun(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope")
	if _, err := resolveBinary(missing); err == nil {
		t.Error("a missing binary must be refused up front")
	}

	notExec := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(notExec, []byte("not a binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := resolveBinary(notExec)
	if err == nil {
		t.Fatal("a non-executable file must be refused up front")
	}
	if !strings.Contains(err.Error(), "not an executable") {
		t.Errorf("the reason should say the file is not executable, got %q", err)
	}

	if _, err := resolveBinary(dir); err == nil {
		t.Error("a directory must be refused up front")
	}
}
