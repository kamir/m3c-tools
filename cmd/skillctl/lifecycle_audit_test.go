package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/auditevent"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// THE test of this feature, and the reason the whole producer is fire-and-forget.
//
// An audit layer that can change a trust decision has become a trust component,
// and then its availability is part of the attack surface: an attacker who can
// fill the disk could steer an install. This pins the opposite property. The
// same run is executed twice, once with a working sink and once with a sink that
// fails every write, and the exit code, stdout and stderr must be identical
// byte for byte.
func TestLifecycleAuditFailureDoesNotChangeTheDecision(t *testing.T) {
	home := t.TempDir()
	hermeticTrustRoots(t)

	run := func(sink func(string, []byte) error) (int, string, string) {
		orig := lifecycleAuditSink
		lifecycleAuditSink = sink
		defer func() { lifecycleAuditSink = orig }()

		var stdout, stderr bytes.Buffer
		// A name that cannot resolve against any configured trust root: the run
		// reaches a verdict and refuses, which is exactly the path an audit
		// failure could plausibly disturb.
		code := runVerify([]string{"--home", home, "--offline", "no-such-skill"}, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}

	// Anti-vacuity: a test that compares two runs which never emitted anything
	// would compare nothing twice and pass. Count the writes and require them.
	okCalls, badCalls := 0, 0
	okCode, okOut, okErr := run(func(string, []byte) error { okCalls++; return nil })
	badCode, badOut, badErr := run(func(string, []byte) error { badCalls++; return errors.New("disk full") })
	if okCalls == 0 || badCalls == 0 {
		t.Fatalf("the audit sink was never reached (ok=%d, bad=%d): this test would pass while measuring nothing", okCalls, badCalls)
	}

	if okCode != badCode {
		t.Errorf("exit code changed when the audit sink failed: %d then %d", okCode, badCode)
	}
	if okOut != badOut {
		t.Errorf("stdout changed when the audit sink failed:\n ok: %q\nbad: %q", okOut, badOut)
	}
	if okErr != badErr {
		t.Errorf("stderr changed when the audit sink failed:\n ok: %q\nbad: %q", okErr, badErr)
	}
}

// A panicking sink is the harsher version of the same property: a marshal panic
// or a nil map deep in a sink must not take the command down with it.
func TestLifecycleAuditPanicIsContained(t *testing.T) {
	home := t.TempDir()
	hermeticTrustRoots(t)
	orig := lifecycleAuditSink
	lifecycleAuditSink = func(string, []byte) error { panic("sink exploded") }
	defer func() { lifecycleAuditSink = orig }()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a panicking audit sink escaped into the command: %v", r)
		}
	}()

	var stdout, stderr bytes.Buffer
	_ = runVerify([]string{"--home", home, "--offline", "no-such-skill"}, &stdout, &stderr)
}

// The mapping from a verifier sentinel to an audit reason must agree with the
// mapping from that same sentinel to an exit code. If they drift, an operator
// reads one cause in the shell and a different one in the evidence log, and the
// log is the one that outlives the shell.
func TestReasonAgreesWithExitCode(t *testing.T) {
	cases := []struct {
		err      error
		wantCode int
		wantRsn  auditevent.ReasonCode
	}{
		{verify.ErrDigestMismatch, verify.ExitDigestMismatch, auditevent.ReasonDigestMismatch},
		{verify.ErrAuthorSigInvalid, verify.ExitAuthorSigInvalid, auditevent.ReasonAuthorSigInvalid},
		{verify.ErrRegistryNotTrusted, verify.ExitRegistryNotTrusted, auditevent.ReasonRegistryNotTrusted},
		{verify.ErrGovernanceBelowMin, verify.ExitGovernanceBelowMin, auditevent.ReasonGovernanceBelowMin},
		{verify.ErrDepsUnsatisfied, verify.ExitDepsUnsatisfied, auditevent.ReasonDepsUnsatisfied},
		{verify.ErrBlobMissing, verify.ExitBlobMissing, auditevent.ReasonBlobMissing},
		{verify.ErrTenantBlocked, verify.ExitTenantBlocked, auditevent.ReasonTenantBlocked},
		{verify.ErrIntentInconsistent, verify.ExitIntentInconsistent, auditevent.ReasonIntentInconsistent},
		{verify.ErrIdentityMismatch, verify.ExitIdentityMismatch, auditevent.ReasonIdentityMismatch},
		{verify.ErrDataSourceDenied, verify.ExitDataSourceDenied, auditevent.ReasonDataSourceDenied},
		{verify.ErrSelfAttested, verify.ExitSelfAttested, auditevent.ReasonSelfAttested},
		{verify.ErrRevocationStale, verify.ExitRevocationStale, auditevent.ReasonRevocationStale},
		{verify.ErrLogInclusionMissing, verify.ExitLogInclusionMissing, auditevent.ReasonLogInclusionMissing},
	}
	for _, tc := range cases {
		if got := verify.ExitCode(tc.err); got != tc.wantCode {
			t.Errorf("%v: exit code = %d, want %d", tc.err, got, tc.wantCode)
		}
		if got := lifecycleReason(tc.err); got != tc.wantRsn {
			t.Errorf("%v: reason = %q, want %q", tc.err, got, tc.wantRsn)
		}
	}
	if got := lifecycleReason(nil); got != auditevent.ReasonOK {
		t.Errorf("nil error mapped to %q, want %q", got, auditevent.ReasonOK)
	}
	// An error nobody classified must be an internal fault, never a refusal.
	if got := lifecycleReason(errors.New("some transport hiccup")); got != auditevent.ReasonInternalError {
		t.Errorf("unclassified error mapped to %q, want %q", got, auditevent.ReasonInternalError)
	}
}

// The written line must be a valid event on the shared envelope, at 0600, in the
// dedicated lifecycle file. SPEC-0406 Phase 9 asks a reader to find the refusal;
// this proves there is something to find and that it parses.
func TestLifecycleEventIsWrittenAndParses(t *testing.T) {
	home := t.TempDir()
	appendLifecycleEvent(home, auditevent.LifecycleEvent{
		Op:       auditevent.OpInstall,
		Skill:    "eric-demo-skill",
		Digest:   "sha256:deadbeef",
		Reason:   auditevent.ReasonDigestMismatch,
		ExitCode: verify.ExitDigestMismatch,
	})

	path := lifecycleAuditPath(home)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("no lifecycle audit file at %s: %v", path, err)
	}
	// 0600 file (POSIX). Windows has no Unix permission bits: Go reports 0666
	// there regardless, and access is governed by ACLs instead. Asserting the
	// bits on Windows would test Go's mapping, not our security property. Same
	// guard as invocation_trail_test.go.
	if runtime.GOOS != "windows" {
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("lifecycle audit file mode = %o, want 600", perm)
		}
	}
	if got := filepath.Base(path); got != "lifecycle-audit.jsonl" {
		t.Errorf("audit file is named %q; it must stay separate from gate-audit.jsonl", got)
	}

	data, err := os.ReadFile(path) // #nosec G304 -- path is under the test's own TempDir.
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	line := strings.TrimSpace(string(data))
	var e auditevent.Event
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatalf("the written line is not a valid event: %v\nline: %s", err, line)
	}
	if e.Schema != auditevent.SchemaV1 {
		t.Errorf("schema = %q, want %q", e.Schema, auditevent.SchemaV1)
	}
	if e.EventType != auditevent.EventSignatureReject {
		t.Errorf("event_type = %q, want %q", e.EventType, auditevent.EventSignatureReject)
	}
	if e.Outcome == auditevent.OutcomeSuccess {
		t.Error("a refusal was recorded as a success")
	}
	if e.Error == nil || e.Error.Code != string(auditevent.ReasonDigestMismatch) {
		t.Errorf("the record does not name the cause: %+v", e.Error)
	}
}

// An empty home means there is nowhere to write. It must be a skip, not a panic
// and not a write into the current directory.
func TestEmptyHomeWritesNothing(t *testing.T) {
	called := false
	orig := lifecycleAuditSink
	lifecycleAuditSink = func(string, []byte) error { called = true; return nil }
	defer func() { lifecycleAuditSink = orig }()

	appendLifecycleEvent("", auditevent.LifecycleEvent{Op: auditevent.OpInstall, Reason: auditevent.ReasonOK})
	if called {
		t.Error("an empty home still reached the sink")
	}
}

// hermeticTrustRoots points the trust-roots lookup at an empty temp dir for the
// duration of one test.
//
// Without it these tests read the DEVELOPER's ~/.claude/skill-trust-roots.yaml,
// so the path they exercise depends on whose laptop runs them: an engineer with
// a configured root walks a different branch than CI, and the test would pass
// for both while measuring two different things. That exact shape of
// non-hermeticity once let an over-broad fail-closed through two adversarial
// review rounds; only a hermetic run caught it.
func hermeticTrustRoots(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	orig := trustConfigPath
	trustConfigPath = func() string { return filepath.Join(dir, "skill-trust-roots.yaml") }
	t.Cleanup(func() { trustConfigPath = orig })
}

// REGRESSION. A non-zero exit must never be recorded as a success, no matter
// which branch produced it.
//
// The first end-to-end run of the real binary wrote `outcome: success` next to
// `lifecycle.exit_code: 1`, because one refusal branch returned a code without
// routing its error through the audit variable. Relying on every return to
// remember was the wrong mechanism; lifecycleReasonFor makes it structural, and
// this test is what stops the property from eroding again.
func TestNonZeroExitIsNeverASuccess(t *testing.T) {
	for _, code := range []int{1, 2, 10, 11, 12, 13, 17, 23} {
		if got := lifecycleReasonFor(code, nil); got == auditevent.ReasonOK {
			t.Errorf("exit %d with no captured error mapped to %q: a failure would be logged as a success", code, got)
		}
	}
	if got := lifecycleReasonFor(exitOK, nil); got != auditevent.ReasonOK {
		t.Errorf("exit 0 mapped to %q, want %q", got, auditevent.ReasonOK)
	}
	// A captured error still wins over the code: the specific cause beats the
	// generic fallback.
	if got := lifecycleReasonFor(10, verify.ErrDigestMismatch); got != auditevent.ReasonDigestMismatch {
		t.Errorf("a captured error was overridden by the code fallback: got %q", got)
	}
}
