package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// doctorOn runs doctor against a throwaway home with the trust-roots lookup
// pointed at a throwaway path, so the result describes the fixture and not the
// developer's own machine.
func doctorOn(t *testing.T, home, trustRoots string) (int, string) {
	t.Helper()
	orig := trustConfigPath
	trustConfigPath = func() string { return trustRoots }
	t.Cleanup(func() { trustConfigPath = orig })

	var out bytes.Buffer
	code := runDoctor([]string{"--home", home}, &out, &out)
	return code, out.String()
}

// THE distinction the whole command is built around.
//
// A fresh machine has no trust roots. That is the expected first-run state and
// must NOT be reported as a failure: a tool that shows red for the normal case
// teaches its users to ignore red. A trust-roots file that EXISTS and cannot be
// parsed is the opposite, and is the one case where continuing is unsafe.
//
// If these two ever collapse into the same verdict, the command has stopped
// being useful in exactly the situation it was written for.
func TestDoctorSeparatesAbsentFromBroken(t *testing.T) {
	// Absent: usable, nothing broken.
	home := t.TempDir()
	code, out := doctorOn(t, home, filepath.Join(t.TempDir(), "no-such-roots.yaml"))
	if code != exitOK {
		t.Errorf("a fresh machine exited %d; absent config is not a failure\n%s", code, out)
	}
	if !lineHasStatus(out, "todo", "trust roots") {
		t.Errorf("absent trust roots were not reported as a next step:\n%s", out)
	}
	if strings.Contains(out, "NOT READY") {
		t.Errorf("a fresh machine was reported as NOT READY:\n%s", out)
	}

	// Present and unparseable: broken.
	bad := filepath.Join(t.TempDir(), "roots.yaml")
	if err := os.WriteFile(bad, []byte("this: [is: not: valid: yaml\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	code, out = doctorOn(t, t.TempDir(), bad)
	if code == exitOK {
		t.Errorf("an unreadable trust-roots file exited 0:\n%s", out)
	}
	// Assert the failure is on the TRUST ROOTS line specifically. A bare
	// "contains FAIL" would also pass if some unrelated check happened to fail,
	// and would then be reporting a green light for a broken measurement.
	if !lineHasStatus(out, "FAIL", "trust roots") {
		t.Errorf("the failure was not reported on the trust-roots line:\n%s", out)
	}
	if !strings.Contains(out, "NOT READY") {
		t.Errorf("the summary did not say NOT READY:\n%s", out)
	}
}

// Every reported gap must carry a next action. This is AC-14 for this surface:
// a diagnostic that states a condition without saying what to do about it leaves
// the reader exactly where they started.
func TestDoctorGivesANextStepForEveryGap(t *testing.T) {
	_, out := doctorOn(t, t.TempDir(), filepath.Join(t.TempDir(), "none.yaml"))
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i, l := range lines {
		if !strings.HasPrefix(l, "todo") && !strings.HasPrefix(l, "FAIL") {
			continue
		}
		if i+1 >= len(lines) || !strings.Contains(lines[i+1], "->") {
			t.Errorf("line %q reports a gap with no next action", strings.TrimSpace(l))
		}
	}
}

// The report must name the platform, not just the version. SPEC-0406 §3.3 asks
// both parties to run the same build, and "0.4.0 on both" is only half an answer
// when one side is Windows and the other macOS.
func TestDoctorReportsPlatform(t *testing.T) {
	_, out := doctorOn(t, t.TempDir(), filepath.Join(t.TempDir(), "none.yaml"))
	if !strings.Contains(out, runtime.GOOS) {
		t.Errorf("the report does not name the platform:\n%s", out)
	}
	if !strings.Contains(out, version) {
		t.Errorf("the report does not name the version:\n%s", out)
	}
}

// doctor is a diagnostic, not a gate. It must not create, move or delete
// anything in the home it inspects. The temp-file probe it uses to test
// writability has to clean up after itself.
func TestDoctorChangesNothing(t *testing.T) {
	home := t.TempDir()
	claude := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claude, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	before, err := os.ReadDir(claude)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}

	doctorOn(t, home, filepath.Join(t.TempDir(), "none.yaml"))

	after, err := os.ReadDir(claude)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(before) != len(after) {
		var names []string
		for _, e := range after {
			names = append(names, e.Name())
		}
		t.Errorf("doctor left something behind in %s: %v", claude, names)
	}
}

// An unwritable audit directory must be reported. It is the one failure the
// producers deliberately swallow (they are fire-and-forget so a logging problem
// can never change a trust decision), which means this command is the ONLY place
// an operator can find out that installs have stopped leaving a record.
func TestDoctorReportsAnUnwritableAuditDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod does not gate directory writes on Windows; ACLs do")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode bits do not restrict this process")
	}
	home := t.TempDir()
	dir := verdictDir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil { // r-x: readable, not writable
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	code, out := doctorOn(t, home, filepath.Join(t.TempDir(), "none.yaml"))
	if code == exitOK {
		t.Errorf("an unwritable audit dir exited 0:\n%s", out)
	}
	if !strings.Contains(out, "stop leaving a record") {
		t.Errorf("the report does not say what the operator actually loses:\n%s", out)
	}
}

// A stray positional argument is a usage error, not a report. Silently ignoring
// it would let `skillctl doctor --home` (flag without value, swallowing the next
// token) look like it worked.
func TestDoctorRejectsExtraArgs(t *testing.T) {
	var out bytes.Buffer
	if code := runDoctor([]string{"unexpected"}, &out, &out); code != exitUsage {
		t.Errorf("exit = %d, want %d (usage)", code, exitUsage)
	}
}

// lineHasStatus reports whether the named check is reported with the given
// status. Matching the pair rather than either half is what stops a test from
// passing because some OTHER check happened to have the status it wanted.
func lineHasStatus(out, status, name string) bool {
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, status) && strings.Contains(l, name) {
			return true
		}
	}
	return false
}
