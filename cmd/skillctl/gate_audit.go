package main

// gate_audit.go — SPEC-0255 gate observability: an append-only, advisory record
// of every gate decision (PreToolUse hook + SessionStart sweep).
//
// CRITICAL CONTRACT: this is fire-and-forget telemetry, NOT a trust input.
// appendGateEvent swallows EVERY error and recovers from any panic, so a logging
// failure (read-only home, full disk, marshal panic) can never change the gate
// decision or exit code. The gate calls it as a bare statement and never branches
// on a result. Reading a tampered audit log can mislead an operator but can never
// allow a bad skill — the trust boundary stays the binary + trust roots + §3.2.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
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
	Online        bool   `json:"online"`     // the online chain ran (hook path)
	CacheHit      bool   `json:"cache_hit"`  // a verdict-cache hit served it (hook path)
	SessionID     string `json:"session_id,omitempty"`
}

// gateAuditMaxBytes bounds the live log; beyond it the file is rotated to
// gate-audit.jsonl.1 (single generation) so disk use stays bounded. A var (not
// const) so tests can exercise rotation without writing megabytes.
var gateAuditMaxBytes int64 = 5 << 20 // 5 MiB

// gateAuditPath reuses verdictDir so the ~/.claude/skillctl 0700 convention is
// identical to the verdict cache.
func gateAuditPath(home string) string { return filepath.Join(verdictDir(home), "gate-audit.jsonl") }

// gateAuditSink is the write seam — tests inject a failing sink to prove the
// gate decision is unchanged when logging fails.
var gateAuditSink = defaultGateAuditSink

func defaultGateAuditSink(home string, line []byte) error {
	dir := verdictDir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := gateAuditPath(home)
	// Best-effort size rotation BEFORE the append. A lost rotation race just
	// means one extra line in the old generation — advisory, never load-bearing.
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
func appendGateEvent(home string, ev gateEvent) {
	defer func() { _ = recover() }()
	if home == "" {
		return // nowhere to write; skip (a pre-home input-validation deny)
	}
	if ev.Ts == "" {
		ev.Ts = time.Now().UTC().Format(time.RFC3339)
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	_ = gateAuditSink(home, line)
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
