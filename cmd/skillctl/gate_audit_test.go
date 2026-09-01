package main

// Tests for SPEC-0255 gate observability: the append-only audit log + gate-stats.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func mkManagedSkill(t *testing.T, home, name string) {
	t.Helper()
	dir := filepath.Join(home, ".claude", "skills", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# "+name), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".skb"), []byte("blob"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// readGateAudit parses every line of the live log, FAILING the test if any line
// is not valid JSON (catches torn/interleaved writes).
func readGateAudit(t *testing.T, home string) []gateEvent {
	t.Helper()
	b, err := os.ReadFile(gateAuditPath(home))
	if err != nil {
		return nil
	}
	var evs []gateEvent
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var e gateEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("gate-audit line is not valid JSON (torn write?): %q (%v)", line, err)
		}
		evs = append(evs, e)
	}
	return evs
}

func mustJSON(ev gateEvent) string { b, _ := json.Marshal(ev); return string(b) }

// A hook decision appends exactly one schema-valid event.
func TestGateAudit_HookEmitsOneEventPerDecision(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	mkManagedSkill(t, home, "good")
	orig := verifyManagedOfflineFn
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) { return exitOK, "ok", true }
	t.Cleanup(func() { verifyManagedOfflineFn = orig })

	ev := `{"tool_name":"Skill","tool_input":{"skill":"good"},"session_id":"s1"}`
	if c, _, _ := feed(t, ev); c != exitOK {
		t.Fatalf("expected allow, got exit %d", c)
	}
	evs := readGateAudit(t, home)
	if len(evs) != 1 {
		t.Fatalf("want exactly 1 audit event, got %d", len(evs))
	}
	e := evs[0]
	if e.Source != "hook" || e.Skill != "good" || e.Decision != "allow" || e.SessionID != "s1" || e.Ts == "" {
		t.Fatalf("unexpected event: %+v", e)
	}
}

// The CONTRACT: a logging failure must not change the gate decision or exit code.
func TestGateAudit_LoggingFailureDoesNotChangeDecision(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	mkManagedSkill(t, home, "bad")
	orig := verifyManagedOfflineFn
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) {
		return 11, "author signature invalid", true
	}
	t.Cleanup(func() { verifyManagedOfflineFn = orig })

	ev := `{"tool_name":"Skill","tool_input":{"skill":"bad"},"session_id":"s"}`
	codeOK, outOK, _ := feed(t, ev) // real sink

	origSink := gateAuditSink
	gateAuditSink = func(string, []byte) error { return errors.New("disk full") }
	t.Cleanup(func() { gateAuditSink = origSink })
	codeFail, outFail, _ := feed(t, ev) // failing sink

	if codeOK != exitHookBlock || codeFail != exitHookBlock {
		t.Fatalf("exit changed when logging failed: ok=%d fail=%d (want %d)", codeOK, codeFail, exitHookBlock)
	}
	if outOK != outFail {
		t.Fatalf("deny decision JSON changed when logging failed:\n ok=%q\n fail=%q", outOK, outFail)
	}
}

// O_APPEND keeps concurrent hook+sweep writes from tearing; every line parses.
func TestGateAudit_ConcurrentAppendNoTornLines(t *testing.T) {
	home := t.TempDir()
	const n = 40
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			src := "hook"
			if i%2 == 0 {
				src = "sweep"
			}
			appendGateEvent(home, gateEvent{Source: src, Skill: "s", Decision: "allow", SessionID: "x"})
		}(i)
	}
	wg.Wait()
	if evs := readGateAudit(t, home); len(evs) != n {
		t.Fatalf("want %d lines, got %d (lost or torn writes?)", n, len(evs))
	}
}

// Beyond the cap the live log rotates to .1, so on-disk size stays bounded.
func TestGateAudit_RotatesAtCap(t *testing.T) {
	home := t.TempDir()
	old := gateAuditMaxBytes
	gateAuditMaxBytes = 200
	t.Cleanup(func() { gateAuditMaxBytes = old })

	for i := 0; i < 50; i++ {
		appendGateEvent(home, gateEvent{Source: "sweep", Skill: "s", Decision: "leave"})
	}
	live := gateAuditPath(home)
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("no live log: %v", err)
	}
	if _, err := os.Stat(live + ".1"); err != nil {
		t.Fatalf("expected rotation to %s.1: %v", live, err)
	}
	fi, _ := os.Stat(live)
	if fi.Size() > gateAuditMaxBytes+256 {
		t.Errorf("live log not bounded by the cap: %d bytes (cap %d)", fi.Size(), gateAuditMaxBytes)
	}
}

// gate-stats summarises correctly, skips a malformed line, and --json is stable.
func TestGateStats_SummarisesAndSkipsMalformed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(verdictDir(home), 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	lines := []string{
		mustJSON(gateEvent{Ts: now, Source: "hook", Skill: "a", Decision: "allow", CacheHit: true}),
		mustJSON(gateEvent{Ts: now, Source: "hook", Skill: "a", Decision: "allow", CacheHit: false}),
		`{ not valid json ]`, // malformed → must be skipped, not fatal
		mustJSON(gateEvent{Ts: now, Source: "hook", Skill: "evil", Decision: "deny", Reason: "author sig", ExitCode: 11}),
		mustJSON(gateEvent{Ts: now, Source: "sweep", Skill: "evil", Decision: "quarantine", Reason: "revoked", ExitCode: 15}),
	}
	if err := os.WriteFile(gateAuditPath(home), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if code := runGateStats([]string{"--json"}, &out, &out); code != exitOK {
		t.Fatalf("gate-stats exit %d:\n%s", code, out.String())
	}
	var sum gateStatsSummary
	if err := json.Unmarshal(out.Bytes(), &sum); err != nil {
		t.Fatalf("--json output not parseable: %v\n%s", err, out.String())
	}
	if sum.Total != 4 {
		t.Errorf("total=%d, want 4 (malformed line skipped)", sum.Total)
	}
	if sum.ByDecision["allow"] != 2 || sum.ByDecision["deny"] != 1 || sum.ByDecision["quarantine"] != 1 {
		t.Errorf("by_decision=%v", sum.ByDecision)
	}
	if sum.HookCount != 3 {
		t.Errorf("hook_count=%d, want 3", sum.HookCount)
	}
	if sum.HookCacheRate < 0.33 || sum.HookCacheRate > 0.34 {
		t.Errorf("hook_cache_hit_rate=%v, want ~1/3", sum.HookCacheRate)
	}
	if len(sum.TopDenied) == 0 || sum.TopDenied[0].Skill != "evil" || sum.TopDenied[0].Count != 2 {
		t.Errorf("top_denied=%v, want evil×2", sum.TopDenied)
	}

	// --json must be deterministic across runs.
	var out2 bytes.Buffer
	runGateStats([]string{"--json"}, &out2, &out2)
	if out.String() != out2.String() {
		t.Errorf("--json output is not stable across runs")
	}
}

// --since filters by event timestamp.
func TestGateStats_SinceFilter(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(verdictDir(home), 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339)
	recent := time.Now().UTC().Format(time.RFC3339)
	lines := []string{
		mustJSON(gateEvent{Ts: old, Source: "hook", Skill: "old", Decision: "allow"}),
		mustJSON(gateEvent{Ts: recent, Source: "hook", Skill: "new", Decision: "allow"}),
	}
	_ = os.WriteFile(gateAuditPath(home), []byte(strings.Join(lines, "\n")+"\n"), 0o600)

	var out bytes.Buffer
	runGateStats([]string{"--since", "24h", "--json"}, &out, &out)
	var sum gateStatsSummary
	_ = json.Unmarshal(out.Bytes(), &sum)
	if sum.Total != 1 {
		t.Errorf("--since 24h total=%d, want 1 (the 48h-old event excluded)", sum.Total)
	}
}
