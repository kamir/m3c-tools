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
// clean — each surviving line still carries a valid per-line device signature, so
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

	// Remove the device key material (both priv + pub) — the state after a same-uid
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
// so the KEYLESS contiguity check passes again — but cannot re-sign the link, so
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

	// Case A — rewrite seq/prev_hash to look contiguous, keep the OLD signature
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

	// Case B — same rewrite but STRIP the signature (downgrade to keyless-only).
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
