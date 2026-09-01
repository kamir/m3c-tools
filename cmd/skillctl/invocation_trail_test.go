package main

import (
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
