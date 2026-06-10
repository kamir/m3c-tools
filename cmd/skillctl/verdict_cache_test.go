package main

// Tests for the offline verdict cache (SPEC-0247 P1.1, §8).

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// SPEC-0251 VERDICT-CACHE TMP RACE: saveVerdictCache must use a UNIQUE temp file
// per write so concurrent writers cannot clobber a shared "verdicts.json.tmp"
// and rename a half-written file into place. With many goroutines writing
// distinct skills at once, the published cache must always be valid JSON and
// must never leave a stray temp file behind. Run with -race to also catch any
// data race on the shared path.
func TestVerdictCache_ConcurrentSaves_NoCorruption(t *testing.T) {
	home := t.TempDir()
	// Pre-create the skill dirs so recordVerdict can compute a digest.
	const n = 24
	for i := 0; i < n; i++ {
		dir := filepath.Join(home, ".claude", "skills", skillName(i))
		writeFile(t, filepath.Join(dir, "SKILL.md"), "# body "+skillName(i))
	}
	now := time.Unix(1_700_000_000, 0).UTC()

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Each writer records a PASS for its own skill, hammering the shared
			// verdicts.json + temp dir concurrently.
			recordVerdict(home, skillName(i), "sess", exitOK, "ok", now)
		}(i)
	}
	wg.Wait()

	// The published cache must parse cleanly (no torn/half-written rename won).
	c := loadVerdictCache(home)
	if c.Version != 1 {
		t.Fatalf("cache version=%d after concurrent saves (corrupt?)", c.Version)
	}
	for _, e := range c.Entries {
		if e.Verdict != "pass" || e.Digest == "" {
			t.Fatalf("corrupt entry survived concurrent saves: %+v", e)
		}
	}

	// No stray temp files must remain in the skillctl dir.
	ents, err := os.ReadDir(verdictDir(home))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "verdicts-") && strings.HasSuffix(e.Name(), ".json") {
			t.Fatalf("stray temp file left behind: %s", e.Name())
		}
	}
}

func skillName(i int) string { return "skill-" + string(rune('a'+i%26)) + "-" + itoa(i) }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
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
