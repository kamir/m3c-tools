package main

// gate_audit.go, SPEC-0255 gate observability: an append-only, advisory record
// of every gate decision (PreToolUse hook + SessionStart sweep).
//
// CRITICAL CONTRACT: this is fire-and-forget telemetry, NOT a trust input.
// appendGateEvent swallows EVERY error and recovers from any panic, so a logging
// failure (read-only home, full disk, marshal panic) can never change the gate
// decision or exit code. The gate calls it as a bare statement and never branches
// on a result. Reading a tampered audit log can mislead an operator but can never
// allow a bad skill. The trust boundary stays the binary + trust roots + §3.2.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/auditevent"
)

// gateEvent is one JSON line in gate-audit.jsonl. Tags are lowercase_snake to
// match sweepEntry/verdictEntry. Treat the schema as an additive contract
// (a downstream SPEC-0192 console may ingest it).
type gateEvent struct {
	Ts            string `json:"ts"`               // RFC3339 UTC
	Source        string `json:"source"`           // "hook" | "sweep"
	Skill         string `json:"skill"`            //
	Decision      string `json:"decision"`         // allow | deny | quarantine | leave
	Reason        string `json:"reason,omitempty"` //
	ExitCode      int    `json:"exit_code"`        //
	ContentDigest string `json:"content_digest,omitempty"`
	Online        bool   `json:"online"`    // the online chain ran (hook path)
	CacheHit      bool   `json:"cache_hit"` // a verdict-cache hit served it (hook path)
	SessionID     string `json:"session_id,omitempty"`
}

// gateAuditMaxBytes bounds the live log; beyond it the file is rotated to
// gate-audit.jsonl.1 (single generation) so disk use stays bounded. A var (not
// const) so tests can exercise rotation without writing megabytes.
var gateAuditMaxBytes int64 = 5 << 20 // 5 MiB

// gateAuditPath reuses verdictDir so the ~/.claude/skillctl 0700 convention is
// identical to the verdict cache.
func gateAuditPath(home string) string { return filepath.Join(verdictDir(home), "gate-audit.jsonl") }

// gateAuditSink is the write seam: tests inject a failing sink to prove the
// gate decision is unchanged when logging fails.
var gateAuditSink = defaultGateAuditSink

func defaultGateAuditSink(home string, line []byte) error {
	dir := verdictDir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := gateAuditPath(home)
	// Best-effort size rotation BEFORE the append. A lost rotation race just
	// means one extra line in the old generation: advisory, never load-bearing.
	if fi, err := os.Stat(path); err == nil && fi.Size() >= gateAuditMaxBytes {
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

// appendGateEvent records one decision. Fire-and-forget: any error or panic is
// swallowed so it can never reach the gate. Fills Ts if the caller left it empty.
//
// SPEC-0403 FR-0110a: the SPEC-0255 gate line is now emitted ON the shared
// skillctl.audit.v1 envelope (policy.allow / policy.deny / policy.evaluate, §4)
// through the best-effort auditevent Dispatcher. The write still goes through the
// SAME gateAuditSink seam (append-only 0600 JSONL + rotation), so decision-
// invariance holds byte-for-byte: this whole function is best-effort, swallows
// every error, and recovers from any panic, so a mapping or sink failure NEVER
// changes the gate decision or exit code (REQ-6.4 / SPEC-0255). No `required`-mode
// fail-close here; that is FR-0110b.
func appendGateEvent(home string, ev gateEvent) {
	defer func() { _ = recover() }()
	if home == "" {
		return // nowhere to write; skip (a pre-home input-validation deny)
	}
	if ev.Ts == "" {
		ev.Ts = time.Now().UTC().Format(time.RFC3339)
	}
	// Map the flat gate line onto the shared envelope. An unknown decision (or any
	// mapping error) is swallowed: the gate is never affected.
	e, err := auditevent.FromGateEvent(auditevent.GateEvent(ev), version)
	if err != nil {
		return
	}
	_ = newGateAuditDispatcher(home).Dispatch(e)
}

// newGateAuditDispatcher builds the best-effort dispatcher for the gate producer.
// Its sole sink marshals the envelope and writes it through the injectable
// gateAuditSink seam, which SPEC-0255's decision-invariance test drives to force a
// logging failure. Best-effort mode: a sink error is returned to Dispatch and
// dropped by appendGateEvent, never reaching the gate (REQ-6.4).
func newGateAuditDispatcher(home string) *auditevent.Dispatcher {
	return auditevent.NewDispatcher(auditevent.DefaultRedactor(), &gateAuditSeamSink{home: home})
}

// gateAuditSeamSink adapts the auditevent.Sink interface onto the SPEC-0255
// gateAuditSink write seam.
type gateAuditSeamSink struct{ home string }

func (s *gateAuditSeamSink) Name() string { return "gate-audit" }
func (s *gateAuditSeamSink) Close() error { return nil }
func (s *gateAuditSeamSink) Write(e *auditevent.Event) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return gateAuditSink(s.home, line)
}

// decisionForExit maps a numeric exit to the allow/deny vocabulary (hook path).
func decisionForExit(code int) string {
	if code == exitOK {
		return "allow"
	}
	return "deny"
}

// decisionForSweepState maps a sweepEntry.State to the gate decision vocabulary.
func decisionForSweepState(state string) string {
	switch state {
	case "verified":
		return "allow"
	case "quarantined":
		return "quarantine"
	default: // "unverified" | "skipped"
		return "leave"
	}
}
