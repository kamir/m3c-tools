package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

func sweepJSON(t *testing.T, home string, args ...string) (int, sweepReport) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	var stdout, stderr bytes.Buffer
	code := runVerify(append([]string{"--json", "--all", "--home", home}, args...), &stdout, &stderr)
	var rep sweepReport
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("invalid JSON: %v stdout=%s stderr=%s", err, &stdout, &stderr)
	}
	if rep.Schema != sweepResultSchema || rep.Operation != "verify_all" || rep.ExitCode != code {
		t.Fatalf("wrong envelope %+v code%d", rep, code)
	}
	if rep.Total != rep.Verified+rep.Invalid+rep.Unverified+rep.Skipped || len(rep.Entries) != rep.Total {
		t.Fatalf("inconsistent counts %+v", rep)
	}
	return code, rep
}

func TestSweepContractEmptyAndEarlyFailures(t *testing.T) {
	for _, args := range [][]string{nil, {"--unknown"}, {"operand"}, {"--budget", "0s"}, {"--governance-min", "nonsense"}} {
		home := t.TempDir()
		code, rep := sweepJSON(t, home, args...)
		if len(args) == 0 {
			if code != 0 || !rep.OK || !rep.Complete || rep.Entries == nil {
				t.Fatalf("empty %+v", rep)
			}
		} else if code != exitUsage || rep.OK || rep.Complete || rep.Error == "" {
			t.Fatalf("early failure %+v", rep)
		}
	}
}

func TestSweepContractEnumerationErrorIsNotEmpty(t *testing.T) {
	for _, obstruction := range []string{"home", "claude", "skills"} {
		t.Run(obstruction, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "home")
			path := home
			if obstruction != "home" {
				path = filepath.Join(home, ".claude")
			}
			if obstruction == "skills" {
				path = filepath.Join(path, "skills")
			}
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("not a directory"), 0600); err != nil {
				t.Fatal(err)
			}
			code, rep := sweepJSON(t, home)
			if code != 1 || rep.OK || rep.Complete || rep.Error == "" {
				t.Fatalf("false empty success %+v", rep)
			}
		})
	}
}

func TestSweepContractMissingInventoryAncestors(t *testing.T) {
	for _, existing := range []string{"none", "home", "claude", "skills"} {
		t.Run(existing, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "home")
			path := home
			if existing == "claude" || existing == "skills" {
				path = filepath.Join(path, ".claude")
			}
			if existing == "skills" {
				path = filepath.Join(path, "skills")
			}
			if existing != "none" {
				if err := os.MkdirAll(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			code, rep := sweepJSON(t, home)
			if code != 0 || !rep.OK || !rep.Complete || rep.Total != 0 || rep.Entries == nil {
				t.Fatalf("missing or empty inventory rejected %+v", rep)
			}
		})
	}
}

func TestSweepContractBrokenInventoryLinkIsNotEmpty(t *testing.T) {
	home := t.TempDir()
	parent := filepath.Join(home, ".claude")
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "missing"), filepath.Join(parent, "skills")); err != nil {
		t.Skip(err)
	}
	code, rep := sweepJSON(t, home)
	if code != 1 || rep.OK || rep.Complete || rep.Error == "" {
		t.Fatalf("broken inventory link reported empty %+v", rep)
	}
}

func TestSweepInventoryDirectoryLink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(filepath.Join(target, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	entries, err := readSweepInventory(link)
	if err != nil || len(entries) != 1 || entries[0].Name() != "child" {
		t.Fatalf("linked directory not read: entries=%v err=%v", entries, err)
	}
	entries, err = readSweepInventory(filepath.Join(link, "missing"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("missing descendant under directory link rejected: entries=%v err=%v", entries, err)
	}
}

func TestSweepContractBrokenLinkVisible(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".claude", "skills")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "missing"), filepath.Join(dir, "broken")); err != nil {
		t.Skip(err)
	}
	stubRootsOK(t)
	code, rep := sweepJSON(t, home)
	if code != 1 || rep.Total != 1 || rep.Unverified != 1 || rep.Entries[0].Skill != "broken" || rep.Complete {
		t.Fatalf("hidden link %+v", rep)
	}
}

func TestSweepContractActualDigestAndMissingChecks(t *testing.T) {
	home := t.TempDir()
	dir := mkSkill(t, home, "good", true)
	stubRootsOK(t)
	stubVerify(t, 0, "synthetic complete chain", nil)
	digest, _, err := inspectSweepBundle(filepath.Join(dir, "good.skb"))
	if err != nil {
		t.Fatal(err)
	}
	code, rep := sweepJSON(t, home)
	e := rep.Entries[0]
	if code != 0 || !rep.OK || !rep.Complete || e.Digest != digest || !e.DigestVerified || e.Scope != "online_trust_chain" || e.RevocationSource != "online" || len(e.Checks) != 5 {
		t.Fatalf("wrong actual result %+v", rep)
	}
	// A metadata-only digest must never replace the measured bundle digest.
	if err := os.WriteFile(filepath.Join(dir, ".m3c-provenance.json"), []byte(`{"bundle_digest":"sha256:forged"}`), 0600); err != nil {
		t.Fatal(err)
	}
	code, rep = sweepJSON(t, home)
	if code != 0 || rep.Entries[0].Digest != digest {
		t.Fatalf("metadata digest trusted %+v", rep)
	}
	// The same successful chain with unconfirmed live revocation is incomplete.
	old := sweepRevokedFn
	sweepRevokedFn = func(string) (map[string]struct{}, bool, error) { return map[string]struct{}{}, false, nil }
	t.Cleanup(func() { sweepRevokedFn = old })
	code, rep = sweepJSON(t, home)
	if code != 1 || rep.OK || rep.Complete || rep.Entries[0].Status != "incomplete" || rep.Entries[0].RevocationSource != "unconfirmed" {
		t.Fatalf("unconfirmed authority passed %+v", rep)
	}
}

func TestSweepContractDependenciesNotResolved(t *testing.T) {
	home := t.TempDir()
	dir := mkSkill(t, home, "dependent", false)
	_, err := skillbundle.Pack(dir, filepath.Join(dir, "dependent.skb"), skillbundle.PackOptions{Manifest: skillbundle.BundleManifest{Name: "dependent", Version: "1.0.0", DependsOn: []skillbundle.Dependency{{Kind: "python", Name: "not-installed", Constraint: ">=999"}}}})
	if err != nil {
		t.Fatal(err)
	}
	stubRootsOK(t)
	stubVerify(t, 0, "chain accepted", nil)
	code, rep := sweepJSON(t, home)
	if code != 1 || rep.Complete || rep.Unverified != 1 {
		t.Fatalf("fake resolution %+v", rep)
	}
	for _, check := range rep.Entries[0].Checks {
		if check.Name == "dependencies" && check.Status != "unconfirmed" {
			t.Fatalf("dependencycheck %+v", check)
		}
	}
}

func TestSweepContractQuarantineDispositions(t *testing.T) {
	for _, mode := range []string{"report", "move", "failed", "note_failed"} {
		t.Run(mode, func(t *testing.T) {
			home := t.TempDir()
			mkSkill(t, home, "bad", true)
			stubRootsOK(t)
			stubVerify(t, 11, "", verify.ErrAuthorSigInvalid)
			args := []string{}
			if mode != "report" {
				args = append(args, "--quarantine")
			}
			if mode == "failed" {
				if err := os.MkdirAll(filepath.Join(home, ".claude", "skillctl"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(home, ".claude", "skillctl", "quarantine"), []byte("occupied"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "note_failed" {
				old := sweepClockFn
				sweepClockFn = func() time.Time { return time.Unix(1234, 0) }
				t.Cleanup(func() { sweepClockFn = old })
				if err := os.MkdirAll(filepath.Join(home, ".claude", "skillctl", "quarantine", "bad.1234.QUARANTINE.md"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			code, rep := sweepJSON(t, home, args...)
			e := rep.Entries[0]
			if code != 1 || rep.Invalid != 1 || rep.QuarantineCandidates != 1 || e.Status != "invalid" {
				t.Fatalf("negative accepted %+v", rep)
			}
			switch mode {
			case "report":
				if e.Disposition != "would_quarantine" || rep.Quarantined != 0 || !skillExists(home, "bad") {
					t.Fatalf("report moved %+v", rep)
				}
			case "move":
				if e.Disposition != "quarantined" || rep.Quarantined != 1 || skillExists(home, "bad") {
					t.Fatalf("move not recorded %+v", rep)
				}
			case "failed":
				if e.Disposition != "quarantine_failed" || rep.Quarantined != 0 || e.ActionError == "" || rep.Complete || !skillExists(home, "bad") {
					t.Fatalf("move failure hidden %+v", rep)
				}
			case "note_failed":
				if e.Disposition != "quarantined" || rep.Quarantined != 1 || e.QuarantinePath == "" || e.ActionError == "" || rep.Complete || skillExists(home, "bad") {
					t.Fatalf("note failure undid move %+v", rep)
				}
			}
		})
	}
}

func TestSweepContractWriterFailure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, args := range [][]string{{"--all", "--json"}, {"--all"}} {
		var stderr bytes.Buffer
		if code := runVerify(args, rejectedTrustWriter{}, &stderr); code != 1 || stderr.Len() == 0 {
			t.Fatalf("writer failure code%d stderr%s", code, &stderr)
		}
	}
}

func TestSweepContractOfflineUsesSelectedPolicy(t *testing.T) {
	f := buildInstallableFixture(t)
	t.Setenv("HOME", f.home)
	t.Setenv("USERPROFILE", f.home)
	if code := runInstall([]string{"--bundle", f.skbPath, "--trust-roots", f.trPath, "--home", f.home}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("fixture install%d", code)
	}
	roots, err := verify.Load(f.trPath)
	if err != nil {
		t.Fatal(err)
	}
	root := &roots.Roots[0]
	sc := sweepCtx{home: f.home, root: root, govMin: "green", registryURL: root.RegistryURL}
	verdict, code, err, available := sweepVerifyOffline("revo-demo", sc, gatePolicy{ManagedMinGovernance: "yellow"})
	if !available || err != nil || code != 0 || verdict.scope != "offline_trust_chain" || verdict.result == nil {
		t.Fatalf("offline selected policy failed %+v code%d err%v", verdict, code, err)
	}

	// A weaker gate-policy floor must not override the selected HTTP policy.
	stashPath := filepath.Join(f.home, ".claude", "skills", "revo-demo", ".skillctl-offline.json")
	data, readErr := os.ReadFile(stashPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var stash map[string]any
	if err := json.Unmarshal(data, &stash); err != nil {
		t.Fatal(err)
	}
	stash["bundle_meta"].(map[string]any)["current_governance"] = "yellow"
	data, err = json.Marshal(stash)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stashPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	_, code, err, available = sweepVerifyOffline("revo-demo", sc, gatePolicy{ManagedMinGovernance: "yellow"})
	if !available || code != verify.ExitGovernanceBelowMin || err == nil {
		t.Fatalf("explicit floor bypassed code%d err%v", code, err)
	}
	sc.govMin = ""
	_, code, err, available = sweepVerifyOffline("revo-demo", sc, gatePolicy{ManagedMinGovernance: "yellow"})
	if !available || code != verify.ExitGovernanceBelowMin || err == nil {
		t.Fatalf("selected root floor bypassed code%d err%v", code, err)
	}
	sc.root = nil
	_, _, _, available = sweepVerifyOffline("revo-demo", sc, gatePolicy{})
	if available {
		t.Fatal("explicit registry silently fell back to another trust root")
	}
}

func TestSweepContractBudgetBeforeOffline(t *testing.T) {
	home := t.TempDir()
	mkSkill(t, home, "late", true)
	oldRoots := loadRootsFn
	loadRootsFn = func(string) (*verify.TrustRoots, *verify.TrustRoot, error) { return nil, nil, errors.New("no roots") }
	t.Cleanup(func() { loadRootsFn = oldRoots })
	oldRev := sweepRevokedFn
	sweepRevokedFn = func(string) (map[string]struct{}, bool, error) { return nil, false, nil }
	t.Cleanup(func() { sweepRevokedFn = oldRev })
	oldClock := sweepClockFn
	now := time.Unix(1, 0)
	sweepClockFn = func() time.Time { now = now.Add(time.Second); return now }
	t.Cleanup(func() { sweepClockFn = oldClock })
	oldOff := sweepVerifyOfflineFn
	sweepVerifyOfflineFn = func(string, sweepCtx, gatePolicy) (sweepVerification, int, error, bool) {
		t.Fatal("offline verify ran beyond budget")
		return sweepVerification{}, 0, nil, false
	}
	t.Cleanup(func() { sweepVerifyOfflineFn = oldOff })
	code, rep := sweepJSON(t, home, "--budget", "1ns")
	if code != 1 || rep.Unverified != 1 || !strings.Contains(rep.Entries[0].Reason, "budget") {
		t.Fatalf("budget incomplete hidden %+v", rep)
	}
}

func TestSweepContractNoChecksInventedWithoutBoundVerifierResult(t *testing.T) {
	for _, result := range []*verify.VerifyResult{nil, {Digest: "sha256:" + strings.Repeat("f", 64)}} {
		entry := newSweepEntry("fixture", "online")
		entry.Digest = "sha256:" + strings.Repeat("a", 64)
		completeSweepVerification(&entry, sweepVerification{scope: "online_trust_chain", result: result}, map[string]any{"depends_on": []any{}})
		if entry.Status != "incomplete" || entry.Complete || entry.DigestVerified {
			t.Fatalf("unbound result trusted %+v", entry)
		}
		for _, check := range entry.Checks {
			if check.Name != "revocation" && check.Status == "pass" {
				t.Fatalf("invented check %+v", check)
			}
		}
	}
}

func TestSweepContractLegacySidecarIsLimited(t *testing.T) {
	home := t.TempDir()
	dir := mkSkill(t, home, "legacy", true)
	blob, err := os.ReadFile(filepath.Join(dir, "legacy.skb"))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := skillbundle.Unpack(blob, skillbundle.UnpackOptions{StripWrapper: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "SKILL.md")); err != nil {
		t.Fatal(err)
	}
	if err := skillbundle.ExtractTo(entries, dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".m3c-provenance.json"), []byte(`{"schema_version":"1.0.0","governance_level":"green"}`), 0600); err != nil {
		t.Fatal(err)
	}
	oldRoots := loadRootsFn
	loadRootsFn = func(string) (*verify.TrustRoots, *verify.TrustRoot, error) {
		return nil, nil, errors.New("no HTTP roots")
	}
	t.Cleanup(func() { loadRootsFn = oldRoots })
	oldRev := sweepRevokedFn
	sweepRevokedFn = func(string) (map[string]struct{}, bool, error) { return nil, false, nil }
	t.Cleanup(func() { sweepRevokedFn = oldRev })
	code, rep := sweepJSON(t, home)
	e := rep.Entries[0]
	if code != 1 || rep.OK || rep.Complete || e.Scope != "sidecar_legacy" || e.DigestVerified || e.GovernanceVerified || e.SelfAttested != nil {
		t.Fatalf("legacy overclaimed %+v", rep)
	}
	for _, check := range e.Checks {
		if check.Name == "content_binding" && check.Status != "pass" {
			t.Fatalf("actual content not checked %+v", e)
		}
		if check.Name != "content_binding" && check.Status == "pass" {
			t.Fatalf("legacy claim %+v", e)
		}
	}
}

func TestSweepContractMissingManagedBlobIsNotUnmanaged(t *testing.T) {
	home := t.TempDir()
	dir := mkSkill(t, home, "missing", false)
	if err := os.WriteFile(filepath.Join(dir, ".skillctl-offline.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	stubRootsOK(t)
	code, rep := sweepJSON(t, home)
	if code != 1 || rep.Invalid != 1 || rep.Skipped != 0 || rep.Entries[0].Digest != "" || rep.Entries[0].DigestVerified || !skillExists(home, "missing") {
		t.Fatalf("missing blob hidden %+v", rep)
	}
}

func TestSweepContractUnboundResultEvictsPriorPass(t *testing.T) {
	home := t.TempDir()
	mkSkill(t, home, "unbound", true)
	stubRootsOK(t)
	recordVerdict(home, "unbound", "old", exitOK, "old pass", time.Now())
	if len(loadVerdictCache(home).Entries) != 1 {
		t.Fatal("fixture did not create prior PASS")
	}
	old := sweepVerifyManagedFn
	sweepVerifyManagedFn = func(context.Context, string, sweepCtx) (sweepVerification, int, error) {
		return sweepVerification{scope: "online_trust_chain"}, 0, nil
	}
	t.Cleanup(func() { sweepVerifyManagedFn = old })
	code, rep := sweepJSON(t, home)
	if code != 1 || rep.Entries[0].Status != "incomplete" {
		t.Fatalf("unbound result accepted %+v", rep)
	}
	if len(loadVerdictCache(home).Entries) != 0 {
		t.Fatal("unbound verifier result left a cached PASS")
	}
}

func TestSweepContractUnreadableBundleRemainsInPlace(t *testing.T) {
	home := t.TempDir()
	dir := mkSkill(t, home, "unreadable", true)
	stubRootsOK(t)
	blob := filepath.Join(dir, "unreadable.skb")
	if err := os.Chmod(blob, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(blob, 0600); err != nil {
			t.Logf("restore synthetic mode: %v", err)
		}
	})
	// Privileged runners can bypass mode bits, so do not claim a permission repro there.
	if data, err := os.ReadFile(blob); err == nil && len(data) > 0 {
		t.Skip("runner can read chmod000 files")
	}
	code, rep := sweepJSON(t, home, "--quarantine")
	entry := rep.Entries[0]
	if code != 1 || entry.Status != "incomplete" || entry.Disposition != "unchanged" || rep.Quarantined != 0 || !skillExists(home, "unreadable") {
		t.Fatalf("availability failure quarantined %+v", rep)
	}
}

func TestSweepContractUnsafeRegistryURLNotReflected(t *testing.T) {
	old := loadRootsFn
	t.Cleanup(func() { loadRootsFn = old })
	for _, url := range []string{"https://user:synthetic-secret@registry.invalid/api/skills", "https://registry.invalid/api/skills?token=synthetic-secret", "https://registry.invalid/api/skills#synthetic-secret"} {
		loadRootsFn = func(string) (*verify.TrustRoots, *verify.TrustRoot, error) {
			t.Fatal("unsafe URL reached root lookup")
			return nil, nil, nil
		}
		code, rep := sweepJSON(t, t.TempDir(), "--registry", url)
		if code != exitUsage || rep.OK || strings.Contains(rep.Error, "synthetic-secret") || strings.Contains(rep.RootsError, "synthetic-secret") {
			t.Fatalf("unsafe URL reflected %+v", rep)
		}
	}
}
