package main

// Tests for the offline verdict cache (SPEC-0247 P1.1, §8).

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDigest_ChangesWhenFileEdited(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".claude", "skills", "s")
	writeFile(t, filepath.Join(dir, "SKILL.md"), "# hello")
	d1, err := computeInstalledDigest(dir)
	if err != nil || d1 == "" {
		t.Fatalf("digest1 err=%v d=%q", err, d1)
	}
	writeFile(t, filepath.Join(dir, "SKILL.md"), "# hello EDITED")
	d2, _ := computeInstalledDigest(dir)
	if d1 == d2 {
		t.Fatal("digest must change when an installed file is edited (tamper-evidence)")
	}
}

func TestVerdict_RoundTripAllowsOffline(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".claude", "skills", "good")
	writeFile(t, filepath.Join(dir, "SKILL.md"), "# good")
	now := time.Unix(1_700_000_000, 0).UTC()
	recordVerdict(home, "good", "sess-1", exitOK, "chain ok", now)
	if !cachedAllow(home, "good", "sess-1", now) {
		t.Fatal("a fresh recorded PASS must allow offline")
	}
}

func TestVerdict_TamperedFile_MissesCache(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".claude", "skills", "good")
	writeFile(t, filepath.Join(dir, "SKILL.md"), "# good")
	now := time.Unix(1_700_000_000, 0).UTC()
	recordVerdict(home, "good", "", exitOK, "ok", now)
	// Tamper the installed body after the PASS was recorded.
	writeFile(t, filepath.Join(dir, "SKILL.md"), "# evil")
	if cachedAllow(home, "good", "", now) {
		t.Fatal("editing the body after a PASS must MISS the cache (digest changed)")
	}
}

func TestVerdict_HMACTamper_Rejected(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".claude", "skills", "good")
	writeFile(t, filepath.Join(dir, "SKILL.md"), "# good")
	now := time.Unix(1_700_000_000, 0).UTC()
	recordVerdict(home, "good", "", exitOK, "ok", now)
	// Forge: flip the verdict to "pass" with a bogus digest by rewriting the
	// file, but the HMAC won't match → must be rejected.
	c := loadVerdictCache(home)
	c.Entries[0].HMAC = "AAAA" // corrupt the MAC
	saveVerdictCache(home, c)
	if cachedAllow(home, "good", "", now) {
		t.Fatal("a row with a bad HMAC must be rejected")
	}
}

func TestVerdict_Expired_MissesCache(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".claude", "skills", "good")
	writeFile(t, filepath.Join(dir, "SKILL.md"), "# good")
	t0 := time.Unix(1_700_000_000, 0).UTC()
	recordVerdict(home, "good", "", exitOK, "ok", t0)
	later := t0.Add(time.Duration(verdictTTLSeconds+1) * time.Second)
	if cachedAllow(home, "good", "", later) {
		t.Fatal("an expired PASS must miss the cache")
	}
}

func TestVerdict_FailRemovesRow(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".claude", "skills", "good")
	writeFile(t, filepath.Join(dir, "SKILL.md"), "# good")
	now := time.Unix(1_700_000_000, 0).UTC()
	recordVerdict(home, "good", "", exitOK, "ok", now)
	recordVerdict(home, "good", "", 11, "", now) // a later FAIL evicts the PASS
	if cachedAllow(home, "good", "", now) {
		t.Fatal("a recorded FAIL must evict the prior PASS")
	}
}

// The hook should hit the cache on the second invocation and NOT re-run the
// online chain.
func TestHook_UsesCache_SkipsSecondVerify(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".claude", "skills", "good")
	writeFile(t, filepath.Join(dir, "SKILL.md"), "# good")
	writeFile(t, filepath.Join(dir, "good.skb"), "blob") // managed

	calls := 0
	orig := verifyManagedFn
	verifyManagedFn = func(string, gatePolicy) (int, string) { calls++; return exitOK, "" }
	t.Cleanup(func() { verifyManagedFn = orig })

	ev := `{"tool_name":"Skill","tool_input":{"skill":"good"},"session_id":"s1"}`
	if c, out, _ := feed(t, ev); c != exitOK || out != "" {
		t.Fatalf("first invoke: exit=%d out=%q", c, out)
	}
	if c, _, _ := feed(t, ev); c != exitOK {
		t.Fatalf("second invoke exit=%d", c)
	}
	if calls != 1 {
		t.Fatalf("online verify ran %d times; cache should have served the 2nd invocation", calls)
	}
}
