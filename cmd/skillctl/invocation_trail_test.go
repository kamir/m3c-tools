package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/device"
	"github.com/kamir/m3c-tools/pkg/skillgate"
)

func sampleInvocation() skillgate.InvocationRecord {
	return skillgate.InvocationRecord{
		EventID:      "01HZTRAILEVENT00000000000",
		EventType:    "skill.invocation",
		SkillName:    "didactic-session",
		SkillVersion: "1.0.0",
		Action:       "invoke",
		Tool:         "skill",
		SessionID:    "sess:abc",
		ExitCode:     0,
	}
}

func TestAppendSignedInvocation_WritesVerifiableLine(t *testing.T) {
	home := t.TempDir()
	rec := sampleInvocation()
	appendSignedInvocation(home, rec)

	path := invocationTrailPath(home)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("trail not written: %v", err)
	}
	if !strings.Contains(string(data), "device_signature_b64") {
		t.Errorf("trail line missing signature; got %q", string(data))
	}
	// 0600 file, 0700 dir (POSIX).
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(path)
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("trail file mode = %#o, want 0600", fi.Mode().Perm())
		}
		di, _ := os.Stat(filepath.Dir(path))
		if di.Mode().Perm() != 0o700 {
			t.Errorf("trail dir mode = %#o, want 0700", di.Mode().Perm())
		}
	}

	// The record verifies under the lazily-created device key.
	tv := readAndVerifyTrail(home)
	if !tv.Present || tv.Total != 1 || tv.Verified != 1 || tv.Unverified != 0 {
		t.Fatalf("verification = %+v, want 1 verified", tv)
	}
	if !strings.HasPrefix(tv.DeviceKeyID, "device:") {
		t.Errorf("device key id %q lacks prefix", tv.DeviceKeyID)
	}
}

func TestAppendSignedInvocation_AppendOnly(t *testing.T) {
	home := t.TempDir()
	appendSignedInvocation(home, sampleInvocation())
	r2 := sampleInvocation()
	r2.EventID = "01HZTRAILEVENT00000000002"
	appendSignedInvocation(home, r2)

	tv := readAndVerifyTrail(home)
	if tv.Total != 2 || tv.Verified != 2 {
		t.Fatalf("expected 2 verified records, got %+v", tv)
	}
}

func TestReadAndVerifyTrail_DetectsTamper(t *testing.T) {
	home := t.TempDir()
	appendSignedInvocation(home, sampleInvocation())
	// Tamper: append a hand-rolled line claiming a verified invocation but with
	// a bogus signature.
	path := invocationTrailPath(home)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"schema":"m3c-skill-invocation/v1","event_id":"forged","event_type":"skill.invocation","skill_name":"evil","skill_version":"9","action":"invoke","tool":"x","session_id":"s","occurred_at":"2026-06-23T00:00:00Z","device_key_id":"device:dead","exit_code":0,"refusal_code":"","device_signature_b64":"AAAA"}` + "\n")
	_ = f.Close()

	tv := readAndVerifyTrail(home)
	if tv.Total != 2 {
		t.Fatalf("total = %d, want 2", tv.Total)
	}
	if tv.Verified != 1 || tv.Unverified != 1 {
		t.Errorf("tampered line not flagged: %+v", tv)
	}
}

func TestReadAndVerifyTrail_DetectsReplay(t *testing.T) {
	home := t.TempDir()
	rec := sampleInvocation()
	appendSignedInvocation(home, rec)
	appendSignedInvocation(home, rec) // SAME event_id → replay

	tv := readAndVerifyTrail(home)
	if tv.Total != 2 {
		t.Fatalf("total = %d, want 2", tv.Total)
	}
	if tv.Replays != 1 {
		t.Errorf("duplicate event_id not flagged as replay: %+v", tv)
	}
}

// TestReadAndVerifyTrail_HashChainDetectsMiddleDeletion is the IS-T8 acceptance
// test: append three signed records, delete the MIDDLE line, and assert the
// hash-chain contiguity check reports a break. Before IS-T8 this excision passed
// clean: each surviving line still carries a valid per-line device signature, so
// nothing flagged the removed record. The seq + prev_hash chain now bites.
func TestReadAndVerifyTrail_HashChainDetectsMiddleDeletion(t *testing.T) {
	home := t.TempDir()
	for i, id := range []string{
		"01HZTRAILEVENT0000000000A",
		"01HZTRAILEVENT0000000000B",
		"01HZTRAILEVENT0000000000C",
	} {
		rec := sampleInvocation()
		rec.EventID = id
		rec.ExitCode = i // distinct content per record
		appendSignedInvocation(home, rec)
	}

	// Intact chain: three verified records, zero breaks.
	if tv := readAndVerifyTrail(home); tv.Total != 3 || tv.Verified != 3 || tv.ChainBreaks != 0 || !tv.ChainVerified {
		t.Fatalf("intact 3-record chain should verify clean, got %+v", tv)
	}

	// Excise the MIDDLE line (the seq=1 record).
	path := invocationTrailPath(home)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read trail: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 trail lines, got %d", len(lines))
	}
	kept := lines[0] + "\n" + lines[2] + "\n" // drop the middle record
	if err := os.WriteFile(path, []byte(kept), 0o600); err != nil {
		t.Fatalf("rewrite trail: %v", err)
	}

	tv := readAndVerifyTrail(home)
	// Both survivors STILL pass their per-line signature (that is exactly why the
	// deletion was previously invisible)...
	if tv.Total != 2 || tv.Verified != 2 || tv.Unverified != 0 {
		t.Fatalf("surviving lines should still individually sign: %+v", tv)
	}
	// ...but the hash chain now reports the gap the deletion opened: the seq=2
	// survivor's seq is not 0+1 and its prev_hash points at the deleted record.
	if tv.ChainBreaks == 0 || tv.ChainVerified {
		t.Errorf("middle-record deletion not detected as a chain/sequence gap: %+v", tv)
	}
}

// Re-gate residual bite (audit fail-open): a chained trail whose DEVICE KEY has
// been removed must NOT report ChainVerified=true. A same-uid actor who deletes the
// device key can then keyless-recompute a fully contiguous chain (seq/prev_hash/
// self_hash) that passes every contiguity check; the chain SIGNATURE is what stops
// that, and it cannot be checked without the key. So a chained-but-keyless trail is
// present-but-UNVERIFIED (ChainSigned==0), not verified. Pre-fix, ChainVerified was
// ChainBreaks==0 alone, so removing the key upgraded a forgeable trail to "verified".
func TestReadAndVerifyTrail_ChainedTrailWithoutDeviceKeyIsUnverified(t *testing.T) {
	home := t.TempDir()
	for i, id := range []string{
		"01HZTRAILEVENT0000000000A",
		"01HZTRAILEVENT0000000000B",
		"01HZTRAILEVENT0000000000C",
	} {
		rec := sampleInvocation()
		rec.EventID = id
		rec.ExitCode = i
		appendSignedInvocation(home, rec)
	}
	// Baseline: with the device key present the intact chain verifies clean.
	if tv := readAndVerifyTrail(home); !tv.ChainVerified || tv.ChainSigned != 3 {
		t.Fatalf("baseline intact chain should be signed+verified, got %+v", tv)
	}

	// Remove the device key material (both priv + pub): the state after a same-uid
	// key wipe. readAndVerifyTrail loads the key directly, so this forces havePub=false.
	_ = os.Remove(device.PrivPath(home))
	_ = os.Remove(device.PubPath(home))

	tv := readAndVerifyTrail(home)
	if !tv.Present {
		t.Fatal("trail should still be present")
	}
	if tv.ChainVerified {
		t.Fatalf("a chained trail with the device key removed must not report ChainVerified=true (keyless contiguity is forgeable); got ChainSigned=%d Total=%d", tv.ChainSigned, tv.Total)
	}
	if tv.ChainSigned != 0 {
		t.Errorf("no chain signatures are verifiable without the device key; ChainSigned=%d, want 0", tv.ChainSigned)
	}
}

// TestReadAndVerifyTrail_ChainSignatureDetectsKeylessRewrite is the hardening
// bite-test for the SECOND (chain-link) device signature. A same-uid attacker
// with NO key deletes the middle record and rewrites the survivor's seq/prev_hash
// so the KEYLESS contiguity check passes again, but cannot re-sign the link, so
// the chain-signature layer must still report a break. Case B covers the downgrade
// where the attacker strips the signature entirely to fall back to keyless-only.
func TestReadAndVerifyTrail_ChainSignatureDetectsKeylessRewrite(t *testing.T) {
	buildTrail := func(t *testing.T) (home string, rec0, rec2 chainedInvocationRecord) {
		t.Helper()
		home = t.TempDir()
		for i, id := range []string{
			"01HZREWRITE000000000000A",
			"01HZREWRITE000000000000B",
			"01HZREWRITE000000000000C",
		} {
			r := sampleInvocation()
			r.EventID = id
			r.ExitCode = i
			appendSignedInvocation(home, r)
		}
		data, err := os.ReadFile(invocationTrailPath(home))
		if err != nil {
			t.Fatalf("read trail: %v", err)
		}
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		if len(lines) != 3 {
			t.Fatalf("want 3 trail lines, got %d", len(lines))
		}
		if err := json.Unmarshal([]byte(lines[0]), &rec0); err != nil {
			t.Fatalf("parse rec0: %v", err)
		}
		if err := json.Unmarshal([]byte(lines[2]), &rec2); err != nil {
			t.Fatalf("parse rec2: %v", err)
		}
		return home, rec0, rec2
	}
	writeTwo := func(t *testing.T, home string, a, b chainedInvocationRecord) {
		t.Helper()
		la, _ := json.Marshal(a)
		lb, _ := json.Marshal(b)
		var buf []byte
		buf = append(buf, la...)
		buf = append(buf, '\n')
		buf = append(buf, lb...)
		buf = append(buf, '\n')
		if err := os.WriteFile(invocationTrailPath(home), buf, 0o600); err != nil {
			t.Fatalf("rewrite trail: %v", err)
		}
	}

	// Case A: rewrite seq/prev_hash to look contiguous, keep the OLD signature
	// (which signed seq=2). The device-signature check must catch it.
	home, rec0, rec2 := buildTrail(t)
	h0, ok := invocationChainHash(rec0.InvocationRecord)
	if !ok {
		t.Fatal("canonicalize rec0")
	}
	one := uint64(1)
	rec2.Seq = &one    // was 2 → now 1, so keyless contiguity now PASSES
	rec2.PrevHash = h0 // points at rec0 instead of the deleted rec1
	writeTwo(t, home, rec0, rec2)

	tv := readAndVerifyTrail(home)
	if tv.Total != 2 || tv.Verified != 2 {
		t.Fatalf("per-line signatures should still verify (attack does not touch them): %+v", tv)
	}
	if tv.ChainBreaks == 0 || tv.ChainVerified {
		t.Errorf("keyless seq/prev_hash rewrite not caught by the chain signature: %+v", tv)
	}

	// Case B: same rewrite but STRIP the signature (downgrade to keyless-only).
	home2, rec0b, rec2b := buildTrail(t)
	h0b, _ := invocationChainHash(rec0b.InvocationRecord)
	one2 := uint64(1)
	rec2b.Seq = &one2
	rec2b.PrevHash = h0b
	rec2b.ChainSignatureB64 = "" // a chained record with no verifiable sig is a break
	writeTwo(t, home2, rec0b, rec2b)

	if tv2 := readAndVerifyTrail(home2); tv2.ChainBreaks == 0 || tv2.ChainVerified {
		t.Errorf("stripped chain signature (downgrade) not caught: %+v", tv2)
	}
}

// TestReadAndVerifyTrail_OversizedLineIsFailClosed is the IS-RS-05(a) bite-test.
// A single line larger than the 4 MiB per-line scanner cap makes bufio.Scan()
// stop with bufio.ErrTooLong. PRE-FIX, sc.Err() was never checked after the loop:
// the scan ended SILENTLY, every record after the oversized line was dropped from
// the counts, and ChainVerified still read TRUE for the surviving prefix (a clean,
// signed, contiguous chain). POST-FIX, the scan error is surfaced as a chain break
// so the trail is reported present-but-UNVERIFIED, never a silent truncation.
func TestReadAndVerifyTrail_OversizedLineIsFailClosed(t *testing.T) {
	home := t.TempDir()
	for _, id := range []string{
		"01HZBIGLINE00000000000A",
		"01HZBIGLINE00000000000B",
		"01HZBIGLINE00000000000C",
	} {
		rec := sampleInvocation()
		rec.EventID = id
		appendSignedInvocation(home, rec)
	}
	path := invocationTrailPath(home)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read trail: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 trail lines, got %d", len(lines))
	}
	// Isolate IS-RS-05(a) from the IS-RS-04 high-water-mark: drop the sidecar so the
	// ONLY reason the trail can be reported unverified is the scan error itself.
	_ = os.Remove(trailHWMPath(home))

	// A single line > 4 MiB (the scanner's per-line cap) inserted AFTER the genesis
	// record. Scan() reads record0, then errors on the oversized line and stops,
	// records 1 and 2 (after it) are never read.
	giant := strings.Repeat("x", (4<<20)+1024)
	rewritten := lines[0] + "\n" + giant + "\n" + lines[1] + "\n" + lines[2] + "\n"
	if err := os.WriteFile(path, []byte(rewritten), 0o600); err != nil {
		t.Fatalf("rewrite trail: %v", err)
	}

	tv := readAndVerifyTrail(home)
	// The oversized line stopped the scan: only the genesis record was read (the two
	// records after it were dropped): proof the scan halted mid-file.
	if tv.Total != 1 {
		t.Fatalf("scan should have stopped after the genesis record, Total=%d (%+v)", tv.Total, tv)
	}
	// Load-bearing: the surviving prefix must NOT be reported as a verified, intact
	// chain. Pre-fix this read true (the silent stop was invisible).
	if tv.ChainVerified {
		t.Errorf("oversized line silently truncated the scan yet ChainVerified stayed true (IS-RS-05a): %+v", tv)
	}
	if tv.ScanError == "" || !strings.Contains(tv.ScanError, "too long") {
		t.Errorf("scan error not surfaced; ScanError=%q", tv.ScanError)
	}
}

// TestReadAndVerifyTrail_OversizedFileIsRefused is the IS-RS-05(b) bite-test. An
// unbounded same-uid writer can grow the trail past all rotation; PRE-FIX
// os.ReadFile would slurp the whole file into memory (OOM). POST-FIX the read is
// refused above a hard ceiling: present-but-UNVERIFIED, no records counted.
func TestReadAndVerifyTrail_OversizedFileIsRefused(t *testing.T) {
	home := t.TempDir()
	for _, id := range []string{"01HZBIGFILE0000000000A", "01HZBIGFILE0000000000B"} {
		rec := sampleInvocation()
		rec.EventID = id
		appendSignedInvocation(home, rec)
	}
	// Lower the ceiling below the (tiny) real file so the refusal path triggers
	// without writing tens of megabytes.
	orig := invocationTrailReadCeilingBytes
	defer func() { invocationTrailReadCeilingBytes = orig }()
	fi, err := os.Stat(invocationTrailPath(home))
	if err != nil {
		t.Fatalf("stat trail: %v", err)
	}
	invocationTrailReadCeilingBytes = fi.Size() - 1 // file now exceeds the ceiling

	tv := readAndVerifyTrail(home)
	if !tv.Present {
		t.Fatal("an oversized trail is still present")
	}
	if !tv.Oversize {
		t.Errorf("oversized trail not flagged Oversize: %+v", tv)
	}
	// Load-bearing: the file was REFUSED, not slurped, no records counted and the
	// trail is not reported as a clean verify. Pre-fix Total would be > 0 and
	// ChainVerified true.
	if tv.Total != 0 {
		t.Errorf("refused trail must not count records, Total=%d", tv.Total)
	}
	if tv.ChainVerified {
		t.Errorf("a refused (unread) trail must not report ChainVerified=true: %+v", tv)
	}
}

// TestReadAndVerifyTrail_TailTruncationDetectedViaHWM is the IS-RS-04 bite-test.
// Deleting the trailing records leaves a VALID, contiguous, fully-signed prefix:
// the hash chain re-verifies clean (ChainVerified stays true, even keyless), so
// the chain alone cannot see tail truncation. The local high-water-mark sidecar
// remembers how far the trail once reached and flags the regression.
//
// HONEST SCOPE: this is LOCAL, cross-run, and best-effort. It is NOT tamper-proof
//. A same-uid actor who truncates the trail can also edit/delete the sidecar to
// erase the high-water-mark; the non-repudiable close is an EXTERNAL SPEC-0358
// head anchor, not this sidecar.
func TestReadAndVerifyTrail_TailTruncationDetectedViaHWM(t *testing.T) {
	home := t.TempDir()
	const n = 4
	for i, id := range []string{
		"01HZTAIL00000000000000A",
		"01HZTAIL00000000000000B",
		"01HZTAIL00000000000000C",
		"01HZTAIL00000000000000D",
	} {
		rec := sampleInvocation()
		rec.EventID = id
		rec.ExitCode = i
		appendSignedInvocation(home, rec)
	}
	// Baseline: intact, clean, and the high-water-mark now records max seq n-1.
	if tv := readAndVerifyTrail(home); !tv.ChainVerified || tv.TailTruncated {
		t.Fatalf("intact %d-record trail should verify clean and untruncated: %+v", n, tv)
	}
	if hwm, ok := readTrailHWM(home); !ok || hwm.MaxSeq != uint64(n-1) {
		t.Fatalf("high-water-mark should record max seq %d, got %+v (ok=%v)", n-1, hwm, ok)
	}

	// Truncate the tail: keep only the first n-2 records (drop seq 2 and seq 3).
	data, err := os.ReadFile(invocationTrailPath(home))
	if err != nil {
		t.Fatalf("read trail: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != n {
		t.Fatalf("want %d trail lines, got %d", n, len(lines))
	}
	kept := strings.Join(lines[:n-2], "\n") + "\n"
	if err := os.WriteFile(invocationTrailPath(home), []byte(kept), 0o600); err != nil {
		t.Fatalf("truncate trail: %v", err)
	}

	tv := readAndVerifyTrail(home)
	// The surviving prefix is a VALID signed chain. The hash-chain check cannot see
	// the tail deletion. This is exactly the gap IS-RS-04 fills.
	if !tv.ChainVerified {
		t.Fatalf("truncated prefix should still be a clean hash chain (the chain cannot see tail truncation): %+v", tv)
	}
	// ...but the high-water-mark caught the regression.
	if !tv.TailTruncated {
		t.Errorf("tail truncation not detected against the high-water-mark (IS-RS-04): %+v", tv)
	}
	if tv.HWMSeq != uint64(n-1) {
		t.Errorf("HWMSeq = %d, want %d", tv.HWMSeq, n-1)
	}
	// The high-water-mark must NOT be lowered by a truncated verify, or the
	// truncation would hide itself on the next run.
	if hwm, ok := readTrailHWM(home); !ok || hwm.MaxSeq != uint64(n-1) {
		t.Errorf("high-water-mark must not regress after a truncated verify: %+v (ok=%v)", hwm, ok)
	}
}

func TestAppendSignedInvocation_SinkFailureIsSwallowed(t *testing.T) {
	home := t.TempDir()
	orig := invocationTrailSink
	defer func() { invocationTrailSink = orig }()
	invocationTrailSink = func(string, []byte) error { return errors.New("disk full") }
	// Must not panic / must return normally even though the sink errors.
	appendSignedInvocation(home, sampleInvocation())
}

func TestAppendSignedInvocation_KeyFailureIsSwallowed(t *testing.T) {
	home := t.TempDir()
	orig := invocationDeviceKey
	defer func() { invocationDeviceKey = orig }()
	invocationDeviceKey = func(string) (*device.Key, error) { return nil, errors.New("no key") }
	appendSignedInvocation(home, sampleInvocation())
	// With no key, nothing should have been written.
	if _, err := os.Stat(invocationTrailPath(home)); err == nil {
		t.Errorf("trail written despite key failure")
	}
}

func TestAppendSignedInvocation_EmptyHomeNoop(t *testing.T) {
	// Must not panic with an empty home.
	appendSignedInvocation("", sampleInvocation())
}

func TestAppendSignedInvocation_RefusesNewlineSmuggling(t *testing.T) {
	home := t.TempDir()
	rec := sampleInvocation()
	rec.Tool = "x\nrefusal_code=token_revoked" // newline smuggle
	appendSignedInvocation(home, rec)
	// SignInvocationRecord refuses ambiguous bytes → no line written.
	if _, err := os.Stat(invocationTrailPath(home)); err == nil {
		t.Errorf("a newline-smuggled record was written to the trail")
	}
}
