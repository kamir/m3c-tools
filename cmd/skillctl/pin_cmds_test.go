package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// withGeteuid swaps the geteuid seam so tests can drive the root/non-root paths
// deterministically regardless of the CI user.
func withGeteuid(t *testing.T, v int) {
	t.Helper()
	orig := geteuid
	geteuid = func() int { return v }
	t.Cleanup(func() { geteuid = orig })
}

func TestRunPin_NoArgsOrUnknown(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runPin(nil, &out, &errb); code != pinExitError {
		t.Errorf("no args: want %d got %d", pinExitError, code)
	}
	out.Reset()
	errb.Reset()
	if code := runPin([]string{"frobnicate"}, &out, &errb); code != pinExitError {
		t.Errorf("unknown sub: want %d got %d", pinExitError, code)
	}
}

func TestRunPinGenerate_Default(t *testing.T) {
	var out, errb bytes.Buffer
	code := runPinGenerate([]string{"--binary", "/usr/local/bin/skillctl"}, &out, &errb)
	if code != pinExitOK {
		t.Fatalf("code=%d stderr=%s", code, errb.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
		t.Fatalf("output not JSON: %v\n%s", err, out.String())
	}
	if _, ok := raw["allowManagedHooksOnly"]; ok {
		t.Error("default must not set allowManagedHooksOnly")
	}
	if strings.Contains(errb.String(), "WARNING") {
		t.Error("default (non-strict) should not print the strict warning")
	}
}

func TestRunPinGenerate_StrictWarns(t *testing.T) {
	var out, errb bytes.Buffer
	runPinGenerate([]string{"--strict"}, &out, &errb)
	if !strings.Contains(out.String(), `"allowManagedHooksOnly": true`) {
		t.Errorf("strict missing lock key:\n%s", out.String())
	}
	if !strings.Contains(errb.String(), "WARNING") {
		t.Error("strict must print the user-hooks-disabled warning to stderr")
	}
}

func TestRunPinGenerate_OutFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "managed.json")
	var out, errb bytes.Buffer
	if code := runPinGenerate([]string{"--out", f}, &out, &errb); code != pinExitOK {
		t.Fatalf("code=%d stderr=%s", code, errb.String())
	}
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "verify-hook") {
		t.Errorf("out file missing gate hook:\n%s", b)
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "managed-settings.json")
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestRunPinStatus_Levels(t *testing.T) {
	// pinned → exit 0
	pinned := `{"hooks":{"SessionStart":[{"matcher":"*","hooks":[{"type":"command","command":"skillctl verify --all --quarantine"}]}],"PreToolUse":[{"matcher":"Skill","hooks":[{"type":"command","command":"skillctl verify-hook"}]}]}}`
	var out, errb bytes.Buffer
	if code := runPinStatus([]string{"--path", writeTemp(t, pinned)}, &out, &errb); code != pinExitOK {
		t.Errorf("pinned: want %d got %d (%s)", pinExitOK, code, out.String())
	}
	if !strings.Contains(out.String(), "pinned") {
		t.Errorf("pinned status missing:\n%s", out.String())
	}

	// partial → exit 2
	out.Reset()
	partial := `{"hooks":{"PreToolUse":[{"matcher":"Skill","hooks":[{"type":"command","command":"skillctl verify-hook"}]}]}}`
	if code := runPinStatus([]string{"--path", writeTemp(t, partial)}, &out, &errb); code != pinExitNotPinned {
		t.Errorf("partial: want %d got %d", pinExitNotPinned, code)
	}

	// tampered → exit 2
	out.Reset()
	if code := runPinStatus([]string{"--path", writeTemp(t, "{ not json")}, &out, &errb); code != pinExitNotPinned {
		t.Errorf("tampered: want %d got %d", pinExitNotPinned, code)
	}

	// absent → exit 2
	out.Reset()
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	if code := runPinStatus([]string{"--path", missing}, &out, &errb); code != pinExitNotPinned {
		t.Errorf("absent: want %d got %d", pinExitNotPinned, code)
	}
	if !strings.Contains(out.String(), "ADVISORY") {
		t.Errorf("absent status should warn the gate is advisory:\n%s", out.String())
	}
}

func TestRunPinStatus_JSON(t *testing.T) {
	pinned := `{"allowManagedHooksOnly":true,"hooks":{"SessionStart":[{"matcher":"*","hooks":[{"type":"command","command":"skillctl verify --all --quarantine"}]}],"PreToolUse":[{"matcher":"Skill","hooks":[{"type":"command","command":"skillctl verify-hook"}]}]}}`
	var out, errb bytes.Buffer
	code := runPinStatus([]string{"--path", writeTemp(t, pinned), "--json"}, &out, &errb)
	if code != pinExitOK {
		t.Fatalf("code=%d", code)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("status --json not JSON: %v\n%s", err, out.String())
	}
	if parsed["level"] != "pinned-strict" {
		t.Errorf("want level pinned-strict, got %v", parsed["level"])
	}
}

func TestRunPinInstall_NonRootEmitsRunbook(t *testing.T) {
	withGeteuid(t, 1000) // force non-root, deterministic
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows
	target := filepath.Join(t.TempDir(), "managed-settings.json")

	var out, errb bytes.Buffer
	code := runPinInstall([]string{"--path", target, "--binary", "/usr/local/bin/skillctl"}, &out, &errb)

	if code != pinExitNeedPrivMsg {
		t.Errorf("non-root install: want %d got %d", pinExitNeedPrivMsg, code)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Error("non-root install must NOT write the privileged target")
	}
	staged := filepath.Join(home, ".claude", "skillctl", "managed-settings.staged.json")
	if _, err := os.Stat(staged); err != nil {
		t.Errorf("staged file should exist: %v", err)
	}
	if !strings.Contains(out.String(), "pin status") {
		t.Errorf("runbook should tell the operator to verify with pin status:\n%s", out.String())
	}
}

func TestRunPinInstall_RootMergesPreservesForeignAndReVerifies(t *testing.T) {
	withGeteuid(t, 0) // force root path
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := t.TempDir()
	target := filepath.Join(dir, "managed-settings.json")
	// A pre-existing managed file with a foreign permission block + foreign hook.
	prior := `{"permissions":{"deny":["Bash(rm -rf /)"]},"hooks":{"PostToolUse":[{"matcher":"Edit","hooks":[{"type":"command","command":"/usr/local/bin/audit.sh"}]}]}}`
	if err := os.WriteFile(target, []byte(prior), 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	code := runPinInstall([]string{"--path", target, "--binary", "/usr/local/bin/skillctl", "--confirm"}, &out, &errb)
	if code != pinExitOK {
		t.Fatalf("root install: code=%d stderr=%s", code, errb.String())
	}
	got, _ := os.ReadFile(target)
	s := string(got)
	if !strings.Contains(s, "/usr/local/bin/audit.sh") {
		t.Error("root install DESTROYED the foreign PostToolUse hook (must merge, not clobber)")
	}
	if !strings.Contains(s, "rm -rf /") {
		t.Error("root install dropped the foreign permissions block")
	}
	if !strings.Contains(s, "verify-hook") {
		t.Error("root install did not add the gate")
	}
	// A timestamped backup of the prior file must exist.
	entries, _ := os.ReadDir(dir)
	foundBak := false
	for _, e := range entries {
		if strings.Contains(e.Name(), "managed-settings.json.bak-") {
			foundBak = true
		}
	}
	if !foundBak {
		t.Error("root install must back up the pre-existing file")
	}
	if !strings.Contains(out.String(), "verified on disk") {
		t.Errorf("root install must report the read-back verification:\n%s", out.String())
	}
}

func TestRunPinInstall_RootRefusesSymlinkTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	withGeteuid(t, 0)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	if err := os.WriteFile(real, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "managed-settings.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := runPinInstall([]string{"--path", link, "--confirm"}, &out, &errb)
	if code != pinExitError {
		t.Errorf("root install through a symlink target must be refused (want %d, got %d)", pinExitError, code)
	}
	if !strings.Contains(errb.String(), "symlink") {
		t.Errorf("expected a symlink refusal message:\n%s", errb.String())
	}
}
