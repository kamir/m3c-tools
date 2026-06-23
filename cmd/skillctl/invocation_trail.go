package main

// invocation_trail.go — SPEC-0202 §9 signed invocation trail.
//
// This is the DURABLE, append-only, DEVICE-SIGNED evidence log: one JSON line
// per skill invocation in ~/.claude/skillctl/invocation-trail.jsonl. It is kept
// STRICTLY SEPARATE from the unsigned advisory gate-audit.jsonl (SPEC-0255) so
// the trust posture is unambiguous:
//
//   - gate-audit.jsonl  — advisory telemetry, NOT a trust input, unsigned.
//   - invocation-trail.jsonl — SIGNED evidence, the EU AI Act Art.12 record.
//
// Don't retrofit signatures onto the advisory log; don't read this trail back
// into a gate decision. The two never mix (ADR §4.3).
//
// CONTRACT — panic-safe, fire-and-forget, ALWAYS-ON:
// appendSignedInvocation swallows EVERY error and recovers from any panic. It
// sits next to the gate/run hot path; a logging failure (read-only home, full
// disk, a key it cannot create, a marshal panic) must NEVER alter the decision
// or the exit code. The caller invokes it as a bare statement and never branches
// on a result. Emission is unconditional (every invocation → one signed record);
// enforcement (capability tokens) stays a separate, opt-in concern.

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/device"
	"github.com/kamir/m3c-tools/pkg/skillgate"
)

// newInvocationEventID returns a sortable-by-time, replay-resistant event id:
// a millisecond Unix timestamp prefix + a 10-byte random tail (the SPEC-0202
// §4.3 nonce shape). This is the dedup key of the trail — the device signature
// binds it, so a replayed signature can't be re-pointed at a fresh id.
func newInvocationEventID() string {
	var tail [10]byte
	_, _ = rand.Read(tail[:])
	return fmt.Sprintf("inv:%013d:%s", time.Now().UTC().UnixMilli(), hex.EncodeToString(tail[:]))
}

// invocationTrailMaxBytes bounds the live trail; beyond it the file rotates to
// invocation-trail.jsonl.1 (single generation). A var (not const) so tests can
// exercise rotation without writing megabytes. Distinct from gateAuditMaxBytes
// so the two logs rotate independently.
var invocationTrailMaxBytes int64 = 5 << 20 // 5 MiB

// invocationTrailPath reuses verdictDir so the ~/.claude/skillctl 0700
// convention matches the verdict cache and the gate-audit log.
func invocationTrailPath(home string) string {
	return filepath.Join(verdictDir(home), "invocation-trail.jsonl")
}

// invocationTrailSink is the write seam — tests inject a failing sink to prove
// the gate decision is unchanged when the trail write fails.
var invocationTrailSink = defaultInvocationTrailSink

// invocationDeviceKey is the device-key seam. Production points it at
// device.EnsureKey (lazy-create on first use); tests can stub it to force a
// key-acquisition failure and assert fail-safety.
var invocationDeviceKey = device.EnsureKey

func defaultInvocationTrailSink(home string, line []byte) error {
	dir := verdictDir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := invocationTrailPath(home)
	// Best-effort size rotation BEFORE the append. A lost rotation race just
	// means one extra line in the old generation — bounded, never load-bearing.
	if fi, err := os.Stat(path); err == nil && fi.Size() >= invocationTrailMaxBytes {
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

// appendSignedInvocation builds, device-signs, and appends one InvocationRecord
// to the signed trail. Fire-and-forget: any error or panic is swallowed so it
// can NEVER reach the caller's decision path.
//
// The record's transient fields are filled here: Schema, OccurredAt (if empty),
// and DeviceKeyID (from the resolved device key). The agent_identity /
// owner_identity fields (SPEC-0277 P1) are taken AS-SET from the caller — empty
// when no AgentID is configured (byte-identical to v1), or agent:<id> / id:<owner>
// when the gate has an active mandate. The signature covers the canonical bytes;
// the line written is the full JSON including the signature.
func appendSignedInvocation(home string, rec skillgate.InvocationRecord) {
	defer func() { _ = recover() }()
	if home == "" {
		return // nowhere to write (e.g. a pre-home input-validation deny)
	}

	// Resolve (lazily create) the per-machine device key. A failure here is NOT
	// fatal to the caller — we just skip the signed record. Fail-safe for the
	// hot path; the absence of a record is itself observable if the key store
	// is broken.
	key, err := invocationDeviceKey(home)
	if err != nil || key == nil {
		return
	}

	if rec.Schema == "" {
		rec.Schema = skillgate.InvocationSchema
	}
	if rec.EventID == "" {
		rec.EventID = newInvocationEventID()
	}
	if rec.OccurredAt == "" {
		rec.OccurredAt = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	}
	rec.DeviceKeyID = key.KeyID()
	// SPEC-0277 P1: the agent_identity / owner_identity lines are populated by the
	// CALLER when an AgentID is configured (a VALUE change at the fixed canonical
	// line — NOT a format change, see skillgate.CanonicalizeInvocationRecord). We
	// no longer clobber them to "" here, so the gate can stamp agent:<id> /
	// id:<owner> onto the always-on signed evidence. Callers with no AgentID leave
	// them empty and the record is byte-identical to v1.

	if err := skillgate.SignInvocationRecord(&rec, key.Sign, base64.StdEncoding.EncodeToString); err != nil {
		return // refused to sign ambiguous bytes (e.g. newline-smuggled field)
	}

	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	_ = invocationTrailSink(home, line)
}

// trailVerification is the result of reading + verifying the signed trail. It is
// the offline-verifiable evidence summary the compliance report surfaces for the
// EU AI Act Art.12 control.
type trailVerification struct {
	// Path is the trail file path (for the operator).
	Path string
	// Present is true when the trail file exists (even if empty).
	Present bool
	// Total is the number of JSON lines read (parseable records).
	Total int
	// Verified is the number whose device signature verified against the local
	// device key.
	Verified int
	// Unverified is Total - Verified (tampered / wrong-key / unsigned lines).
	Unverified int
	// Replays is the count of records sharing an already-seen event_id —
	// duplicate event ids are the replay signal.
	Replays int
	// DeviceKeyID is the local device key's id ("" if the key is unavailable).
	DeviceKeyID string
}

// readAndVerifyTrail reads the signed invocation trail at home, verifies each
// record's device signature against the LOCAL device key, and counts
// verified / unverified / replayed records. Read-only; never creates the key
// (it Loads an existing one — a machine that never emitted a record has no key
// and no trail, which is a legitimate empty-evidence state, not an error).
//
// Fail-closed counting: any line that does not parse, or whose signature does
// not verify, is counted as Unverified — never silently dropped from the total
// in a way that would inflate the verified ratio.
func readAndVerifyTrail(home string) trailVerification {
	tv := trailVerification{Path: invocationTrailPath(home)}
	if home == "" {
		return tv
	}

	// Load (do not create) the device key. Without it we cannot verify — report
	// the records as present-but-unverified rather than claiming verification.
	var (
		havePub bool
		pubKey  []byte
	)
	if key, err := device.Load(home); err == nil && key != nil {
		tv.DeviceKeyID = key.KeyID()
		pubKey = key.PublicKey()
		havePub = true
	}

	data, err := os.ReadFile(tv.Path)
	if err != nil {
		return tv // absent trail → present=false, zero counts (empty evidence)
	}
	tv.Present = true

	seen := make(map[string]struct{})
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		tv.Total++
		var rec skillgate.InvocationRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			tv.Unverified++
			continue
		}
		// Replay: a second occurrence of an event_id we've already counted is a
		// REPLAY, not new evidence — it must NOT inflate the verified-evidence
		// count (P2 challenge-gate finding). Count it as a replay and move on, so
		// `Verified` reflects DISTINCT verified events only.
		if rec.EventID != "" {
			if _, dup := seen[rec.EventID]; dup {
				tv.Replays++
				continue
			}
			seen[rec.EventID] = struct{}{}
		}
		if havePub && skillgate.VerifyInvocationRecord(&rec, pubKey, base64.StdEncoding.DecodeString) {
			tv.Verified++
		} else {
			tv.Unverified++
		}
	}
	return tv
}
