package main

// auditlog_cmds_test.go: FR-0111 tests for `skillctl auditlog status|test|flush`.
// Hermetic: a temp $HOME, no network, no ambient managed-settings. Each verb is
// exercised on its happy path and on an unhealthy path (an audit directory that
// cannot be written, forced by making <home>/.claude a regular FILE, so every
// downstream MkdirAll fails deterministically).

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/outbox"
	"github.com/kamir/m3c-tools/pkg/skillgate"
)

// wedgeAuditHome makes <home>/.claude a regular file, so any attempt to create
// <home>/.claude/skillctl (the audit dir) fails. Returns the home.
func wedgeAuditHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".claude"), []byte("not a dir"), 0o600); err != nil {
		t.Fatalf("wedge home: %v", err)
	}
	return home
}

func TestAuditlogStatus_Healthy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	var out, errb bytes.Buffer
	code := runAuditlog([]string{"status"}, &out, &errb)
	if code != auditlogExitOK {
		t.Fatalf("healthy status must exit 0; got %d (stderr=%q)", code, errb.String())
	}
	s := out.String()
	for _, want := range []string{"ENABLED", "HEALTHY", "Sink:", "best-effort"} {
		if !strings.Contains(s, want) {
			t.Fatalf("status output missing %q; got:\n%s", want, s)
		}
	}
}

func TestAuditlogStatus_JSON(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	var out, errb bytes.Buffer
	if code := runAuditlog([]string{"status", "--json"}, &out, &errb); code != auditlogExitOK {
		t.Fatalf("healthy status --json must exit 0; got %d", code)
	}
	var st auditlogStatus
	if err := json.Unmarshal(out.Bytes(), &st); err != nil {
		t.Fatalf("status --json must emit valid JSON; got %v\n%s", err, out.String())
	}
	if !st.Enabled || !st.Healthy {
		t.Fatalf("healthy JSON status must have enabled+healthy true; got %+v", st)
	}
	// REQ-8.3 shape but no Kafka: there must be no fabricated broker fields.
	if strings.Contains(out.String(), "kafka") || strings.Contains(out.String(), "endpoint") || strings.Contains(out.String(), "topic") {
		t.Fatalf("status must NOT fabricate a broker endpoint/topic (FR-0112, EC-blocked); got:\n%s", out.String())
	}
}

func TestAuditlogStatus_Unhealthy(t *testing.T) {
	home := wedgeAuditHome(t)
	t.Setenv("HOME", home)
	var out, errb bytes.Buffer
	code := runAuditlog([]string{"status"}, &out, &errb)
	if code != auditlogExitUnhealthy {
		t.Fatalf("an unwritable audit dir must exit 1; got %d\nstdout=%s", code, out.String())
	}
	if !strings.Contains(out.String(), "UNHEALTHY") || !strings.Contains(out.String(), "not writable") {
		t.Fatalf("unhealthy status must say UNHEALTHY and name the writability failure; got:\n%s", out.String())
	}
}

func TestAuditlogTest_Happy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	var out, errb bytes.Buffer
	code := runAuditlog([]string{"test"}, &out, &errb)
	if code != auditlogExitOK {
		t.Fatalf("test on a writable home must exit 0; got %d (stderr=%q)", code, errb.String())
	}
	if !strings.Contains(out.String(), "ACCEPTED") {
		t.Fatalf("test happy path must report ACCEPTED; got:\n%s", out.String())
	}
	// The synthetic event must have landed in the real default sink, clearly marked.
	logPath := filepath.Join(home, ".claude", "skillctl", "gate-audit.jsonl")
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("expected the synthetic event written to %s; read err=%v", logPath, err)
	}
	if !strings.Contains(string(b), "auditlog-test-") || !strings.Contains(string(b), "audit.sink.connect") {
		t.Fatalf("the written event must be the clearly-synthetic audit.sink.connect with the test marker; got:\n%s", string(b))
	}
	if !strings.Contains(string(b), "\"synthetic\":true") {
		t.Fatalf("the written event must carry the synthetic marker field; got:\n%s", string(b))
	}
}

func TestAuditlogTest_Unhealthy(t *testing.T) {
	home := wedgeAuditHome(t)
	t.Setenv("HOME", home)
	var out, errb bytes.Buffer
	code := runAuditlog([]string{"test"}, &out, &errb)
	if code != auditlogExitUnhealthy {
		t.Fatalf("test with an unwritable sink must exit 1; got %d", code)
	}
	// REQ-8.1: the transport failure is surfaced as an observable audit.sink.fail
	// event, and (REQ-8.2) on stderr, NOT back through the file sink that failed.
	if !strings.Contains(errb.String(), "audit.sink.fail") {
		t.Fatalf("a sink write failure must surface an observable audit.sink.fail on stderr (REQ-8.1); got stderr:\n%s", errb.String())
	}
	// REQ-8.2 no-recursion: nothing must have been written to the (broken) file sink
	// (the path is unwritable, so the file must not exist at all).
	if _, err := os.Stat(filepath.Join(home, ".claude", "skillctl", "gate-audit.jsonl")); err == nil {
		t.Fatal("no audit line must reach the failed file sink (no recursion), but the log file exists")
	}
}

// spoolOne appends one row to the home's spool.jsonl (the hot-path fallback queue).
func spoolOne(t *testing.T, home, eventID, occurredAt string) {
	t.Helper()
	rec := skillgate.InvocationRecord{
		Schema:     skillgate.InvocationSchema,
		EventID:    eventID,
		EventType:  "policy.allow",
		OccurredAt: occurredAt,
		Tool:       "audit",
		Action:     "audit",
	}
	pj, ph, err := outbox.RecordPayload(rec)
	if err != nil {
		t.Fatalf("RecordPayload: %v", err)
	}
	if err := outbox.SpoolTo(home, rec, pj, ph); err != nil {
		t.Fatalf("SpoolTo: %v", err)
	}
}

func TestAuditlogFlush_Happy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	spoolOne(t, home, "flush-a", "2026-09-04T10:00:00Z")
	spoolOne(t, home, "flush-b", "2026-09-04T10:00:01Z")

	var out, errb bytes.Buffer
	code := runAuditlog([]string{"flush", "--json"}, &out, &errb)
	if code != auditlogExitOK {
		t.Fatalf("flush of a writable spool must exit 0; got %d (stderr=%q)", code, errb.String())
	}
	var res auditlogFlushResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("flush --json must emit valid JSON; got %v\n%s", err, out.String())
	}
	if res.SpoolBefore != 2 || res.Drained != 2 || res.SpoolAfter != 0 {
		t.Fatalf("flush must drain both spooled rows and empty the spool; got %+v", res)
	}
	if res.PendingAfter < 2 {
		t.Fatalf("the reconciled rows must be durable (unsynced) in the outbox after flush; got pending_after=%d", res.PendingAfter)
	}
	// REQ-8.1: a normal flush produces the observable audit.queue.flush state.
	if !strings.Contains(errb.String(), "audit.queue.flush") {
		t.Fatalf("flush must surface an observable audit.queue.flush event (REQ-8.1); got stderr:\n%s", errb.String())
	}
}

func TestAuditlogFlush_EmptyIsHealthy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	var out, errb bytes.Buffer
	if code := runAuditlog([]string{"flush"}, &out, &errb); code != auditlogExitOK {
		t.Fatalf("flush with an empty spool must still be healthy (exit 0); got %d", code)
	}
	if !strings.Contains(out.String(), "reconciled:           0 row(s)") {
		t.Fatalf("empty flush must report 0 reconciled; got:\n%s", out.String())
	}
}

func TestAuditlogFlush_Unhealthy(t *testing.T) {
	home := wedgeAuditHome(t)
	t.Setenv("HOME", home)
	var out, errb bytes.Buffer
	code := runAuditlog([]string{"flush"}, &out, &errb)
	if code != auditlogExitUnhealthy {
		t.Fatalf("flush against an unopenable outbox must exit 1; got %d", code)
	}
	if !strings.Contains(errb.String(), "audit.queue.flush") {
		t.Fatalf("a flush transport error must surface an observable audit.queue.flush event (REQ-8.1); got stderr:\n%s", errb.String())
	}
}

func TestAuditlog_UsageErrors(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runAuditlog(nil, &out, &errb); code != auditlogExitUsage {
		t.Fatalf("no subcommand must be a usage error (2); got %d", code)
	}
	if code := runAuditlog([]string{"bogus"}, &out, &errb); code != auditlogExitUsage {
		t.Fatalf("an unknown subcommand must be a usage error (2); got %d", code)
	}
}

// The auditlog verb must NOT collide with `skillctl audit`'s 0/2/3 posture space:
// its own exit space is 0/1 for the health verdict (REQ-8.5/8.6). This asserts the
// constants are the disjoint values the SPEC decided.
func TestAuditlog_ExitSpaceIsOwnAndDisjoint(t *testing.T) {
	if auditlogExitOK != 0 || auditlogExitUnhealthy != 1 {
		t.Fatalf("auditlog health verdict must be 0/1 (REQ-8.6); got ok=%d unhealthy=%d", auditlogExitOK, auditlogExitUnhealthy)
	}
}
