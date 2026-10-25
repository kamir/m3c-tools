package mutationstate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

func heldFixture(t *testing.T, f stateFixture) *Session {
	t.Helper()
	session, err := f.store.Begin(context.Background(), verify.MutationInstall, f.digest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := session.Close(); err != nil {
			t.Error(err)
		}
	})
	return session
}

func TestSessionRecheckFreshClockFloorAndOriginalBinding(t *testing.T) {
	f := newStateFixture(t)
	enrollFixture(t, f, 7)
	session := heldFixture(t, f)
	f.clock.set(f.clock.now().Add(time.Minute))
	additional := "sha256:" + strings.Repeat("a", 64)
	decision, err := session.Recheck(context.Background(), additional, f.digest, additional)
	if err != nil || !decision.Allowed || decision.SubjectDigest != f.digest || decision.Action != verify.MutationInstall {
		t.Fatalf("original subject/action not preserved: %+v %v", decision, err)
	}
	if !decision.EvaluatedAt.Equal(f.clock.now()) {
		t.Fatal("returned old Begin observation")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	status, err := f.reopen(t).Status(context.Background())
	if err != nil || !status.LastSeen.Equal(f.clock.now()) {
		t.Fatalf("rechecked floor not durable: %+v %v", status, err)
	}
	if session.Decision().Allowed {
		t.Fatal("closed session retains an allowed decision")
	}
}

func TestSessionRecheckStaleFloorPreventsClockRecovery(t *testing.T) {
	f := newStateFixture(t)
	initial := enrollFixture(t, f, 7)
	session := heldFixture(t, f)
	late := initial.IssuedAt.Add(24*time.Hour + time.Nanosecond)
	f.clock.set(late)
	decision, err := session.Recheck(context.Background())
	if !errors.Is(err, verify.ErrRevocationStale) || decision.Allowed || session.Decision().Allowed {
		t.Fatalf("stale held session allowed: %+v %v", decision, err)
	}
	f.clock.set(initial.LastSeen)
	decision, err = session.Recheck(context.Background())
	if !errors.Is(err, verify.ErrRevocationStale) || decision.Reason != "clock_rollback" || decision.Allowed {
		t.Fatalf("return to earlier fresh time was allowed: %+v %v", decision, err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	status, err := f.reopen(t).Status(context.Background())
	if err != nil || !status.LastSeen.Equal(late) {
		t.Fatalf("denial lost observed clock floor: %+v %v", status, err)
	}
}

func TestSessionRecheckRevokedAdditionalSubjectPersistsClock(t *testing.T) {
	f := newStateFixture(t)
	additional := "sha256:" + strings.Repeat("b", 64)
	if _, err := f.store.Enroll(context.Background(), f.list(t, 7, f.clock.now().Add(-time.Hour), additional)); err != nil {
		t.Fatal(err)
	}
	session := heldFixture(t, f)
	f.clock.set(f.clock.now().Add(time.Minute))
	decision, err := session.Recheck(context.Background(), additional)
	if !errors.Is(err, verify.ErrIdentityRevoked) || decision.Allowed || decision.SubjectDigest != additional || session.Decision().Allowed {
		t.Fatalf("revoked dependency not refused: %+v %v", decision, err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	status, err := f.reopen(t).Status(context.Background())
	if err != nil || !status.LastSeen.Equal(f.clock.now()) {
		t.Fatalf("revoked denial zeroed or lost clock floor: %+v %v", status, err)
	}
}

func TestSessionRecheckInvalidInputsDoNotWrite(t *testing.T) {
	for _, mode := range []string{"too_many", "large_digest", "uppercase", "canceled", "clock_rollback", "clock_zero"} {
		t.Run(mode, func(t *testing.T) {
			f := newStateFixture(t)
			enrollFixture(t, f, 7)
			session := heldFixture(t, f)
			before, err := os.ReadFile(f.store.statePath)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			var subjects []string
			switch mode {
			case "too_many":
				subjects = make([]string, MaxSessionSubjects)
			case "large_digest":
				subjects = []string{strings.Repeat("x", 1<<20)}
			case "uppercase":
				subjects = []string{strings.ToUpper(f.digest)}
			case "canceled":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			case "clock_rollback":
				f.clock.set(f.clock.now().Add(-time.Second))
			case "clock_zero":
				f.clock.set(time.Time{})
			}
			decision, err := session.Recheck(ctx, subjects...)
			if err == nil || decision.Allowed || session.Decision().Allowed {
				t.Fatalf("invalid recheck allowed: %+v %v", decision, err)
			}
			after, err := os.ReadFile(f.store.statePath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("invalid input changed durable history")
			}
		})
	}
}

func TestSessionRecheckRejectsHistoryReplacement(t *testing.T) {
	for _, mode := range []string{"valid_new_epoch", "clock_floor_replay", "bad_signature", "missing"} {
		t.Run(mode, func(t *testing.T) {
			f := newStateFixture(t)
			enrollFixture(t, f, 7)
			session := heldFixture(t, f)
			r, _, err := f.store.load()
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "valid_new_epoch":
				raw := f.list(t, 8, f.clock.now())
				list, err := f.store.authority(raw, f.clock.now(), true)
				if err != nil {
					t.Fatal(err)
				}
				r = f.store.newRecord(raw, list, f.clock.now())
			case "clock_floor_replay":
				r.LastSeen = r.LastSeen.Add(-time.Minute)
			case "bad_signature":
				r.FullList = []byte(`{}`)
				r.EvidenceFingerprint = fingerprint(r.FullList)
			case "missing":
				if err := os.Remove(f.store.statePath); err != nil {
					t.Fatal(err)
				}
			}
			if mode != "missing" {
				if err := f.store.publish(context.Background(), r); err != nil {
					t.Fatal(err)
				}
			}
			decision, err := session.Recheck(context.Background())
			if err == nil || decision.Allowed || session.Decision().Allowed {
				t.Fatalf("unexpected record replacement accepted: %+v %v", decision, err)
			}
		})
	}
}

func TestSessionRecheckPersistenceUncertaintyInvalidatesSession(t *testing.T) {
	for _, fault := range []string{"write", "sync", "close", "replace", "dir_sync"} {
		t.Run(fault, func(t *testing.T) {
			f := newStateFixture(t)
			enrollFixture(t, f, 7)
			session := heldFixture(t, f)
			original := f.store.ops
			injected := errors.New("synthetic recheck persistence failure")
			switch fault {
			case "write":
				f.store.ops.write = func(*os.File, []byte) (int, error) { return 0, injected }
			case "sync":
				f.store.ops.sync = func(*os.File) error { return injected }
			case "close":
				f.store.ops.close = func(f *os.File) error { return errors.Join(f.Close(), injected) }
			case "replace":
				f.store.ops.replace = func(string, string) error { return injected }
			case "dir_sync":
				f.store.ops.syncDir = func(string) error { return injected }
			}
			decision, err := session.Recheck(context.Background())
			if !errors.Is(err, ErrPersistence) || !errors.Is(err, injected) || decision.Allowed || session.Decision().Allowed {
				t.Fatalf("uncertain persistence allowed: %+v %v", decision, err)
			}
			f.store.ops = original
			decision, err = session.Recheck(context.Background())
			if !errors.Is(err, ErrPersistence) || decision.Allowed {
				t.Fatal("uncertain session reused after restoring I/O")
			}
		})
	}
}

func TestSessionRecheckCloseAndDecisionConcurrent(t *testing.T) {
	f := newStateFixture(t)
	enrollFixture(t, f, 7)
	session := heldFixture(t, f)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = session.Recheck(context.Background())
			_ = session.Decision()
			if err := session.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	decision, err := session.Recheck(context.Background())
	if err == nil || decision.Allowed || session.Decision().Allowed {
		t.Fatal("closed session reused")
	}
	var zero Session
	if decision, err := zero.Recheck(context.Background()); err == nil || decision.Allowed {
		t.Fatal("zero session accepted")
	}
	firstClose, repeatedClose := zero.Close(), zero.Close()
	if !errors.Is(firstClose, ErrInvalidState) || repeatedClose != firstClose {
		t.Fatal("invalid zero-session close hidden or not idempotent")
	}
	var absent *Session
	if absent.Decision().Allowed || absent.Close() == nil {
		t.Fatal("nil session accepted")
	}
	if decision, err := absent.Recheck(context.Background()); err == nil || decision.Allowed {
		t.Fatal("nil recheck accepted")
	}
}
