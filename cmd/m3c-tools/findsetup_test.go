//go:build darwin

// findsetup_test.go — SEC-M12 regression tests for findSetupScript.
//
// findSetupScript must anchor to the running binary's directory and must NOT
// pick up a cwd-relative scripts/setup-venv.sh (working-dir hijack). The result
// is fed to `bash <script>`, so a cwd-relative lookup would let anyone who
// controls the working directory execute arbitrary code.
package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFindSetupScript_IgnoresCwdRelativeScript proves the working-dir hijack is
// closed: a malicious scripts/setup-venv.sh in the current working directory
// must NOT be returned (there is no such script next to the test binary).
func TestFindSetupScript_IgnoresCwdRelativeScript(t *testing.T) {
	// Build a fake cwd with a planted scripts/setup-venv.sh.
	cwd := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cwd, "scripts"), 0700); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(cwd, "scripts", "setup-venv.sh")
	if err := os.WriteFile(planted, []byte("#!/bin/sh\necho pwned\n"), 0700); err != nil {
		t.Fatal(err)
	}

	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(orig)
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}

	got := findSetupScript()
	if got == planted {
		t.Fatalf("findSetupScript returned the cwd-relative planted script %q — working-dir hijack not closed", got)
	}
	if got == "scripts/setup-venv.sh" {
		t.Fatalf("findSetupScript returned a relative cwd path %q — must be anchored to the binary", got)
	}
	// Whatever it returns (likely "" in the test env, since no script sits next
	// to the test binary) must never be the planted cwd path.
}

// TestFindSetupScript_FindsScriptNextToBinary proves the anchor works: a script
// placed alongside the running test binary (in scripts/) is found and returned
// as an absolute path.
func TestFindSetupScript_FindsScriptNextToBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot determine test executable: %v", err)
	}
	if resolved, rErr := filepath.EvalSymlinks(exe); rErr == nil {
		exe = resolved
	}
	exeDir := filepath.Dir(exe)

	scriptsDir := filepath.Join(exeDir, "scripts")
	target := filepath.Join(scriptsDir, "setup-venv.sh")

	// Don't clobber a real file if one somehow exists.
	if _, statErr := os.Stat(target); statErr == nil {
		t.Skipf("a setup-venv.sh already exists next to the test binary: %s", target)
	}
	if err := os.MkdirAll(scriptsDir, 0700); err != nil {
		t.Skipf("cannot create scripts dir next to test binary (%v) — read-only test dir", err)
	}
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0700); err != nil {
		t.Skipf("cannot write script next to test binary: %v", err)
	}
	defer os.Remove(target)
	defer os.Remove(scriptsDir)

	got := findSetupScript()
	if got == "" {
		t.Fatal("findSetupScript returned empty even though a script sits next to the binary")
	}
	if !filepath.IsAbs(got) {
		t.Errorf("findSetupScript returned non-absolute path %q", got)
	}
	gotResolved, _ := filepath.EvalSymlinks(got)
	targetResolved, _ := filepath.EvalSymlinks(target)
	if gotResolved != targetResolved && got != target {
		t.Errorf("findSetupScript = %q, want the binary-anchored script %q", got, target)
	}
}
