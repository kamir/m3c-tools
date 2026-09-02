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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

// invocationOutboxSink is an OPTIONAL second sink for the signed invocation
// record (SPEC-0317 P0). It is fed the SAME fully-signed record as the trail —
// transient fields (event_id/occurred_at/device_key_id) filled ONCE and the
// signature computed ONCE, so the projection (invocation-trail.jsonl) and the
// authoritative outbox row can NEVER diverge on id/signature (dual-sink
// consistency).
//
// Production `verify-hook` leaves this nil, so it is byte-identical to the
// pre-SPEC-0317 gate and writes only the trail. `skillctl enforce` installs a
// sink that mirrors the record into the outbox (enforce_cmds.go).
//
// Fire-and-forget, decision-invariant (SPEC-0255): it runs inside
// appendSignedInvocation's recover and its result is discarded, so a full disk /
// SQLITE_BUSY / panic in the outbox sink can NEVER alter the gate decision, exit
// code, or stdout/stderr bytes (AC-2a).
var invocationOutboxSink func(home string, rec skillgate.InvocationRecord)

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

// chainedInvocationRecord is the ON-DISK trail line: a signed
// skillgate.InvocationRecord PLUS three ADDITIVE integrity fields that hash-chain
// the trail (IS-T8, SPEC-0202 §9 / EU AI Act Art.12 tamper-evidence):
//
//   - Seq — a monotonic per-generation sequence number (genesis = 0). A deleted
//     record leaves a gap.
//   - PrevHash — the SHA-256 (hex) of the PREVIOUS record's CANONICAL bytes
//     (skillgate.CanonicalizeInvocationRecord output). Because each record commits
//     to its predecessor's content, deleting a middle record makes the survivor's
//     prev_hash no longer match the recomputed hash of its new predecessor.
//   - ChainSignatureB64 — a SECOND detached ed25519 signature (same device key,
//     DISTINCT domain "invocation_chain_v1") over (seq, prev_hash, self_hash),
//     where self_hash binds the link to THIS record's own canonical bytes so a
//     signed link cannot be transplanted onto a different record.
//
// All three sit OUTSIDE the per-line InvocationRecord canonical message: putting
// them there would change the v1 canonical bytes and invalidate every existing
// per-line signature (and the golden-bytes pin). They are additive/separate — the
// per-line signature proves each record's own integrity; the chain proves the
// trail was not truncated or reordered in the middle.
//
// HONEST SCOPE — read carefully, do NOT overclaim:
//
//   - seq + prev_hash ALONE are keyless SHA-256 over PUBLIC canonical bytes. On
//     their own they are a NAIVE delete/reorder DETECTOR (tamper-EVIDENT for a
//     careless deletion), NOT cryptographic tamper-proofing: a same-uid writer can
//     recompute a fully valid seq+prev_hash chain with NO key, and O_APPEND does
//     not stop a same-uid O_TRUNC rewrite of the whole file.
//   - ChainSignatureB64 is what makes the chain actually tamper-EVIDENT against
//     that same-uid rewrite: the attacker can edit seq/prev_hash but cannot forge
//     the device signature over the new values, and cannot transplant an existing
//     signed link (self_hash pins it to its record). Stripping the signature is
//     itself a break (a chained record MUST carry a verifiable one when the device
//     public key is available). This is the "second detached signature" option
//     from the challenge gate.
//   - STILL out of scope, even with the signature: (a) anyone holding the device
//     signing key can forge any record — key custody, not this chain, is the trust
//     anchor; (b) TAIL truncation — dropping the newest N records leaves a valid,
//     contiguous, fully-signed prefix, so it is NOT detectable here. Detecting
//     wholesale/tail truncation needs an EXTERNAL anchor of the head hash (the
//     SPEC-0358 transparency log), which this local chain does not provide.
//   - CONCURRENCY (gate N1): two concurrent skillctl processes sharing the trail
//     can BOTH stamp seq=N+1, so verification may report a benign ChainBreak on a
//     NON-tampered trail. This is a deliberate FAIL-SAFE over-report — the trail is
//     advisory (never a gate input) and every per-line signature still verifies; we
//     accept a false "break" rather than risk a false "clean".
//
// Each rotation generation (.jsonl vs .jsonl.1) is its own self-contained chain.
type chainedInvocationRecord struct {
	skillgate.InvocationRecord
	// Seq is a pointer so a legacy record written BEFORE this feature (no "seq"
	// key) unmarshals to nil and is excluded from chain verification — avoiding a
	// false break on pre-existing trails. A non-nil pointer to 0 marks genesis.
	Seq               *uint64 `json:"seq,omitempty"`
	PrevHash          string  `json:"prev_hash"`
	ChainSignatureB64 string  `json:"chain_signature_b64,omitempty"`
}

// invocationChainHash returns the hex SHA-256 over a record's canonical bytes —
// the value the NEXT record stores as its prev_hash. ok is false only if the
// record refuses to canonicalize (e.g. a newline-smuggled field), in which case
// the chain intentionally cannot continue across it.
func invocationChainHash(rec skillgate.InvocationRecord) (hash string, ok bool) {
	canon, err := skillgate.CanonicalizeInvocationRecord(&rec)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), true
}

// invocationChainDomain domain-separates the SECOND (chain-link) device signature
// from the per-line InvocationRecord signature (invocation_event_v1) and every
// other signature family, so a signature captured under one can never replay under
// another — even with the same key.
const invocationChainDomain = "invocation_chain_v1"

// invocationChainSigMessage builds the canonical bytes the chain signature covers:
// the link (seq, prev_hash) BOUND to this record's own canonical hash (self_hash),
// so a signed link cannot be transplanted onto a different record. LF-delimited,
// fixed order; every value is a decimal uint or lowercase hex / empty (never
// contains a newline), so the framing is unambiguous.
func invocationChainSigMessage(seq uint64, prevHash, selfHash string) []byte {
	return []byte(fmt.Sprintf("%s\nseq=%d\nprev_hash=%s\nself_hash=%s\n",
		invocationChainDomain, seq, prevHash, selfHash))
}

// verifyChainSignature verifies a record's detached chain-link signature over
// (seq, prev_hash, self_hash) against the local device public key. Fail-closed:
// a wrong-size key, absent/garbage signature, or any mismatch returns false.
func verifyChainSignature(pub []byte, seq uint64, prevHash, selfHash, sigB64 string) bool {
	if len(pub) != ed25519.PublicKeySize || sigB64 == "" {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), invocationChainSigMessage(seq, prevHash, selfHash), sig)
}

// readLastTrailLine returns the last non-empty line of the trail file, reading
// only a bounded tail so an append stays cheap regardless of trail size. Returns
// nil when the file is absent, empty, or unreadable.
func readLastTrailLine(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return nil
	}
	const tail = 256 << 10 // 256 KiB — far larger than one record line
	start := int64(0)
	if fi.Size() > tail {
		start = fi.Size() - tail
	}
	buf := make([]byte, fi.Size()-start)
	if _, err := f.ReadAt(buf, start); err != nil && err != io.EOF {
		return nil
	}
	// The tail may begin mid-line; iterate from the end and take the last COMPLETE
	// non-empty line (the trailing record is always fully within the tail).
	for _, ln := range revLines(buf) {
		if t := bytes.TrimSpace(ln); len(t) > 0 {
			return t
		}
	}
	return nil
}

// revLines splits buf on '\n' and returns the lines in reverse order.
func revLines(buf []byte) [][]byte {
	parts := bytes.Split(buf, []byte{'\n'})
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return parts
}

// nextChainLink computes the (seq, prev_hash) to stamp onto the NEXT appended
// record, from the current live trail. Genesis (0, "") when the trail is fresh,
// unreadable, about to rotate, or its last record predates the chain feature.
func nextChainLink(home string) (seq uint64, prevHash string) {
	path := invocationTrailPath(home)
	// Mirror the default sink's pre-append rotation: an at/over-cap live file is
	// renamed to .jsonl.1 and a fresh file started, so the next record opens a new
	// generation's chain at genesis.
	if fi, err := os.Stat(path); err == nil && fi.Size() >= invocationTrailMaxBytes {
		return 0, ""
	}
	last := readLastTrailLine(path)
	if last == nil {
		return 0, ""
	}
	var prev chainedInvocationRecord
	if err := json.Unmarshal(last, &prev); err != nil || prev.Seq == nil {
		return 0, "" // unreadable, or a legacy predecessor → start a fresh chain
	}
	h, ok := invocationChainHash(prev.InvocationRecord)
	if !ok {
		return 0, ""
	}
	return *prev.Seq + 1, h
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

	// IS-T8: stamp the hash-chain link (seq + prev_hash over the PRIOR record's
	// canonical bytes) so a later deletion/truncation of a middle record is
	// detectable, PLUS a second detached device signature over (seq, prev_hash,
	// self_hash) so a same-uid keyless rewrite of those fields is tamper-evident.
	// All additive/separate — the per-line signature above is unchanged (rec is
	// signed BEFORE it is wrapped).
	seq, prevHash := nextChainLink(home)
	chained := chainedInvocationRecord{
		InvocationRecord: rec,
		Seq:              &seq,
		PrevHash:         prevHash,
	}
	if selfHash, ok := invocationChainHash(rec); ok {
		msg := invocationChainSigMessage(seq, prevHash, selfHash)
		if sig := key.Sign(msg); len(sig) == ed25519.SignatureSize {
			chained.ChainSignatureB64 = base64.StdEncoding.EncodeToString(sig)
		}
	}

	line, err := json.Marshal(chained)
	if err != nil {
		return
	}
	_ = invocationTrailSink(home, line)

	// SPEC-0317 P0: fan the SAME fully-signed record out to the optional outbox
	// sink (installed only by `skillctl enforce`). Called AFTER the trail write
	// with the identical `rec` so the outbox row and the trail projection share
	// event_id / occurred_at / signature. Nil in `verify-hook` (byte-identical to
	// v1). Its result is intentionally ignored — this whole function is
	// fire-and-forget under the top-level recover, so an outbox failure is
	// decision-invariant (AC-2a).
	if sink := invocationOutboxSink; sink != nil {
		sink(home, rec)
	}
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
	// ChainBreaks counts hash-chain integrity violations (IS-T8) — at most one per
	// record. A chained record breaks the chain when EITHER: its seq is not
	// predecessor.seq+1 / its prev_hash does not equal the recomputed hash of the
	// preceding chained record's canonical bytes / it is a first record that is not
	// genesis (seq 0, empty prev_hash) — the keyless contiguity check; OR (when the
	// device public key is available) its chain-link device signature over
	// (seq, prev_hash, self_hash) is missing or does not verify — the check that
	// catches a same-uid keyless rewrite or a stripped signature. A deleted,
	// reordered, or rewritten middle record yields at least one break. NOT detected:
	// tail truncation (a valid signed prefix) — that needs an external SPEC-0358
	// head anchor. Records predating the chain feature (no "seq") are excluded, so a
	// legacy trail reports 0. Concurrent writers can cause a benign over-report (a
	// fail-safe; see chainedInvocationRecord).
	ChainBreaks int
	// ChainSigned counts chained records whose chain-link device signature verified
	// — the number of links backed by cryptographic tamper-evidence (0 when the
	// device public key is unavailable). ChainSigned == number-of-chained-records
	// means every link is device-signed.
	ChainSigned int
	// ChainVerified is true when the trail's chained records form one contiguous
	// hash chain with no breaks (vacuously true for a trail with no chained
	// records). It is the tamper-evidence signal for the Art.12 record-keeping
	// control: false means the append-only trail was truncated (in the middle),
	// reordered, or a link was altered.
	ChainVerified bool
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
	// Hash-chain contiguity state (IS-T8). Tracked across the PHYSICAL order of
	// chained records (independent of replay dedup / signature validity) so a
	// deleted or truncated middle record is detected even when every surviving
	// record still signs cleanly.
	var (
		chainStarted  bool
		expectSeq     uint64 // predecessor.seq + 1
		prevChainHash string // hash of the predecessor's canonical bytes
	)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		tv.Total++
		var rec chainedInvocationRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			// An unparseable line is counted Unverified; it also breaks the chain
			// for the following record (whose prev_hash can no longer be recomputed
			// here), which surfaces as a ChainBreak there — never a silent drop.
			tv.Unverified++
			continue
		}

		// --- hash-chain integrity (IS-T8) ---------------------------------------
		// Only records carrying the chain fields participate; legacy records
		// (no "seq") are excluded so pre-feature trails do not report false breaks.
		if rec.Seq != nil {
			thisHash, okHash := invocationChainHash(rec.InvocationRecord)
			broke := false
			// (1) Keyless contiguity — detects a naive delete/reorder even with no key.
			if !chainStarted {
				// The first chained record must be genesis (seq 0, empty prev_hash).
				// A non-genesis first record means the trail head was truncated.
				if *rec.Seq != 0 || rec.PrevHash != "" {
					broke = true
				}
				chainStarted = true
			} else if *rec.Seq != expectSeq || rec.PrevHash != prevChainHash {
				// A gap in seq OR a prev_hash that does not match the recomputed hash
				// of the preceding record → a deleted/truncated/reordered record.
				broke = true
			}
			// (2) Chain-link device signature — the cryptographic layer. When the
			// device public key is available, a chained record MUST carry a chain
			// signature that verifies over (seq, prev_hash, self_hash); a missing or
			// invalid one is a break (this is what catches a same-uid KEYLESS rewrite
			// of seq/prev_hash, and a downgrade that strips the signature). When the
			// key is unavailable we cannot verify — fall back to contiguity only,
			// exactly as the per-line signature path reports present-but-unverified.
			if havePub {
				if okHash && verifyChainSignature(pubKey, *rec.Seq, rec.PrevHash, thisHash, rec.ChainSignatureB64) {
					tv.ChainSigned++
				} else {
					broke = true
				}
			}
			if broke {
				tv.ChainBreaks++
			}
			expectSeq = *rec.Seq + 1
			if okHash {
				prevChainHash = thisHash
			} else {
				prevChainHash = "" // cannot recompute → the next record will mismatch
			}
		}

		// Replay: a second occurrence of an event_id we've already counted is a
		// REPLAY, not new evidence — it must NOT inflate the verified-evidence
		// count (P2 challenge-gate finding). Count it as a replay and move on, so
		// `Verified` reflects DISTINCT verified events only. (Chain state was
		// already advanced above, so a replayed line does not corrupt contiguity.)
		if rec.EventID != "" {
			if _, dup := seen[rec.EventID]; dup {
				tv.Replays++
				continue
			}
			seen[rec.EventID] = struct{}{}
		}
		if havePub && skillgate.VerifyInvocationRecord(&rec.InvocationRecord, pubKey, base64.StdEncoding.DecodeString) {
			tv.Verified++
		} else {
			tv.Unverified++
		}
	}
	// Vacuously true for a legacy/empty trail (no chained records → no breaks).
	tv.ChainVerified = tv.ChainBreaks == 0
	return tv
}
