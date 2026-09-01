package main

// Tests for `skillctl verify --all` (SPEC-0247 P0.2 sweep).
//
// The registry-dependent verification is behind the seams loadRootsFn /
// sweepVerifyManagedFn, stubbed here so the sweep — including the real
// filesystem quarantine move — runs offline.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

func mkSkill(t *testing.T, home, name string, withSkb bool) string {
	t.Helper()
	dir := filepath.Join(home, ".claude", "skills", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# "+name), 0o644); err != nil {
		t.Fatal(err)
	}
	if withSkb {
		if err := os.WriteFile(filepath.Join(dir, name+".skb"), []byte("blob"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func stubRootsOK(t *testing.T) {
	t.Helper()
	orig := loadRootsFn
	loadRootsFn = func(string) (*verify.TrustRoots, *verify.TrustRoot, error) {
		return &verify.TrustRoots{}, &verify.TrustRoot{RegistryURL: "http://test"}, nil
	}
	t.Cleanup(func() { loadRootsFn = orig })
}

func stubVerify(t *testing.T, code int, summary string, err error) {
	t.Helper()
	orig := sweepVerifyManagedFn
	sweepVerifyManagedFn = func(context.Context, string, sweepCtx) (int, string, error) {
		return code, summary, err
	}
	t.Cleanup(func() { sweepVerifyManagedFn = orig })
}

func runSweep(t *testing.T, home string, args ...string) (int, string) {
	t.Helper()
	t.Setenv("HOME", home)
	var out, errb bytes.Buffer
	code := runVerify(append([]string{"--all"}, args...), &out, &errb)
	return code, out.String() + errb.String()
}

func skillExists(home, name string) bool {
	_, err := os.Stat(filepath.Join(home, ".claude", "skills", name))
	return err == nil
}

func quarantined(t *testing.T, home, name string) (bool, string) {
	t.Helper()
	base := filepath.Join(home, ".claude", "skillctl", "quarantine")
	matches, _ := filepath.Glob(filepath.Join(base, name+".*"))
	if len(matches) == 0 {
		return false, ""
	}
	return true, matches[0]
}

func TestSweep_NoSkillsDir_OK(t *testing.T) {
	code, out := runSweep(t, t.TempDir())
	if code != exitOK {
		t.Fatalf("exit=%d want 0", code)
	}
	if !strings.Contains(out, "nothing to sweep") {
		t.Fatalf("want 'nothing to sweep', got %q", out)
	}
}

func TestSweep_UnmanagedSkipped_NotMoved(t *testing.T) {
	home := t.TempDir()
	mkSkill(t, home, "browse", false) // no .skb → unmanaged
	stubRootsOK(t)
	code, out := runSweep(t, home)
	if code != exitOK {
		t.Fatalf("exit=%d", code)
	}
	if !skillExists(home, "browse") {
		t.Fatal("unmanaged skill must NOT be moved under default policy")
	}
	if !strings.Contains(out, "skipped") {
		t.Fatalf("want skipped, got %q", out)
	}
}

func TestSweep_UnmanagedPolicyDeny_Quarantined(t *testing.T) {
	home := t.TempDir()
	mkSkill(t, home, "rando", false)
	stubRootsOK(t)
	t.Setenv("SKILLCTL_GATE_UNMANAGED", "deny")
	code, _ := runSweep(t, home, "--quarantine")
	if code != exitOK {
		t.Fatalf("exit=%d", code)
	}
	if skillExists(home, "rando") {
		t.Fatal("policy=deny + --quarantine should move the unmanaged skill out")
	}
	ok, _ := quarantined(t, home, "rando")
	if !ok {
		t.Fatal("expected rando in quarantine dir")
	}
}

func TestSweep_ManagedBadSig_Quarantined_WithNote(t *testing.T) {
	home := t.TempDir()
	mkSkill(t, home, "evil", true)
	stubRootsOK(t)
	stubVerify(t, 11, "", verify.ErrAuthorSigInvalid) // exit 11 ≥ 10 → trust failure
	code, _ := runSweep(t, home, "--quarantine")
	if code != exitOK {
		t.Fatalf("exit=%d", code)
	}
	if skillExists(home, "evil") {
		t.Fatal("trust-failing managed skill must be moved out")
	}
	ok, dest := quarantined(t, home, "evil")
	if !ok {
		t.Fatal("expected evil in quarantine dir")
	}
	note, err := os.ReadFile(dest + ".QUARANTINE.md")
	if err != nil {
		t.Fatalf("QUARANTINE.md missing: %v", err)
	}
	if !strings.Contains(string(note), "exit code: 11") || !strings.Contains(string(note), "author signature invalid") {
		t.Fatalf("QUARANTINE.md not informative:\n%s", note)
	}
}

func TestSweep_ManagedBadSig_ReportOnly_WithoutQuarantineFlag(t *testing.T) {
	home := t.TempDir()
	mkSkill(t, home, "evil", true)
	stubRootsOK(t)
	stubVerify(t, 11, "", verify.ErrAuthorSigInvalid)
	code, out := runSweep(t, home) // no --quarantine
	if code != exitOK {
		t.Fatalf("exit=%d", code)
	}
	if !skillExists(home, "evil") {
		t.Fatal("without --quarantine the sweep must NOT move anything")
	}
	if !strings.Contains(out, "report-only") {
		t.Fatalf("want report-only note, got %q", out)
	}
}

func TestSweep_AvailabilityFailure_NotQuarantined(t *testing.T) {
	home := t.TempDir()
	mkSkill(t, home, "good", true)
	stubRootsOK(t)
	// exit 1 (< 10) + network error → availability, must NOT quarantine.
	stubVerify(t, exitGeneric, "", errors.New("dial tcp 127.0.0.1: connection refused"))
	code, out := runSweep(t, home, "--quarantine")
	if code != exitOK {
		t.Fatalf("exit=%d", code)
	}
	if !skillExists(home, "good") {
		t.Fatal("a network/availability failure must NEVER quarantine — would nuke skills when offline")
	}
	if !strings.Contains(out, "unverified") {
		t.Fatalf("want 'unverified', got %q", out)
	}
}

func TestSweep_RootsUnavailable_ManagedUnverified_NotMoved(t *testing.T) {
	home := t.TempDir()
	mkSkill(t, home, "good", true)
	orig := loadRootsFn
	loadRootsFn = func(string) (*verify.TrustRoots, *verify.TrustRoot, error) {
		return nil, nil, errors.New("trust roots not configured")
	}
	t.Cleanup(func() { loadRootsFn = orig })
	code, out := runSweep(t, home, "--quarantine")
	if code != exitOK {
		t.Fatalf("exit=%d", code)
	}
	if !skillExists(home, "good") {
		t.Fatal("no trust roots → cannot verify → must not quarantine")
	}
	if !strings.Contains(out, "trust roots unavailable") {
		t.Fatalf("want trust-roots warning, got %q", out)
	}
}

func TestSweep_Verified_PassThrough(t *testing.T) {
	home := t.TempDir()
	mkSkill(t, home, "good", true)
	stubRootsOK(t)
	stubVerify(t, exitOK, "chain ok: author=alice gov=green", nil)
	code, out := runSweep(t, home)
	if code != exitOK {
		t.Fatalf("exit=%d", code)
	}
	if !skillExists(home, "good") || !strings.Contains(out, "verified") {
		t.Fatalf("verified skill should stay + report verified; got %q", out)
	}
}

func stubOffline(t *testing.T, code int, reason string, available bool) {
	t.Helper()
	orig := verifyManagedOfflineFn
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) { return code, reason, available }
	t.Cleanup(func() { verifyManagedOfflineFn = orig })
}

func TestSweep_OnlineDown_OfflineCatchesBadSig_Quarantined(t *testing.T) {
	// Registry unreachable (online exit <10), but the offline path catches a
	// trust failure → quarantine even though we're offline.
	home := t.TempDir()
	mkSkill(t, home, "evil", true)
	stubRootsOK(t)
	stubVerify(t, exitGeneric, "", errors.New("connection refused")) // online availability fail
	stubOffline(t, 11, "author signature invalid", true)            // offline trust fail
	code, _ := runSweep(t, home, "--quarantine")
	if code != exitOK {
		t.Fatalf("exit=%d", code)
	}
	if skillExists(home, "evil") {
		t.Fatal("offline trust-fail must quarantine when registry is down")
	}
	if ok, _ := quarantined(t, home, "evil"); !ok {
		t.Fatal("expected evil quarantined via offline path")
	}
}

func TestSweep_OnlineDown_OfflinePass_VerifiedOffline(t *testing.T) {
	home := t.TempDir()
	mkSkill(t, home, "good", true)
	stubRootsOK(t)
	stubVerify(t, exitGeneric, "", errors.New("connection refused"))
	stubOffline(t, exitOK, "", true)
	code, out := runSweep(t, home, "--quarantine")
	if code != exitOK {
		t.Fatalf("exit=%d", code)
	}
	if !skillExists(home, "good") {
		t.Fatal("offline PASS must keep the skill")
	}
	if !strings.Contains(out, "verified offline") {
		t.Fatalf("want 'verified offline', got %q", out)
	}
}

func TestSweep_SymlinkedSkillIsSeen(t *testing.T) {
	// Regression: e.IsDir() (lstat) silently skips symlinked skill dirs, but
	// their description still loads. The sweep must follow the symlink and
	// count it (here: unmanaged → skipped, but SEEN).
	home := t.TempDir()
	target := mkSkill(t, home, "real-target", false)
	link := filepath.Join(home, ".claude", "skills", "linked")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	stubRootsOK(t)
	t.Setenv("HOME", home)
	var out bytes.Buffer
	if code := runVerify([]string{"--all", "--json"}, &out, &out); code != exitOK {
		t.Fatalf("exit=%d", code)
	}
	var rep sweepReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	seen := false
	for _, e := range rep.Entries {
		if e.Skill == "linked" {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("symlinked skill 'linked' was not seen by the sweep: %+v", rep.Entries)
	}
}

func TestSweep_JSONReport(t *testing.T) {
	home := t.TempDir()
	mkSkill(t, home, "good", true)
	mkSkill(t, home, "browse", false)
	stubRootsOK(t)
	stubVerify(t, exitOK, "ok", nil)
	t.Setenv("HOME", home)
	var out bytes.Buffer
	code := runVerify([]string{"--all", "--json"}, &out, &out)
	if code != exitOK {
		t.Fatalf("exit=%d", code)
	}
	var rep sweepReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out.String())
	}
	if rep.Total != 2 || rep.Verified != 1 || rep.Skipped != 1 {
		t.Fatalf("tally wrong: %+v", rep)
	}
}
