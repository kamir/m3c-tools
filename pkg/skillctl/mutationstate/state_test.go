package mutationstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

type fixtureClock struct {
	mu    sync.Mutex
	value time.Time
}

func (c *fixtureClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.value }
func (c *fixtureClock) set(value time.Time) { c.mu.Lock(); defer c.mu.Unlock(); c.value = value }

type stateFixture struct {
	dir    string
	root   *verify.TrustRoot
	key    ed25519.PrivateKey
	clock  *fixtureClock
	store  *Store
	digest string
}

func newStateFixture(t *testing.T) stateFixture {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &verify.TrustRoot{RegistryURL: "https://registry.invalid/skills", RegistryKeys: []verify.RegistryKey{{ID: "fixture-registry", Pubkey: public, PubkeyB64: base64.StdEncoding.EncodeToString(public)}}, MinRevocationEpoch: 1, MaxStaleness: "24h"}
	clock := &fixtureClock{value: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)}
	dir := filepath.Join(t.TempDir(), "state")
	store, err := New(dir, root)
	if err != nil {
		t.Fatal(err)
	}
	store.now = clock.now
	sum := sha256.Sum256([]byte("synthetic installed skill"))
	return stateFixture{dir: dir, root: root, key: key, clock: clock, store: store, digest: "sha256:" + hex.EncodeToString(sum[:])}
}
func (f stateFixture) list(t *testing.T, epoch int, issued time.Time, revoked ...string) []byte {
	t.Helper()
	list, err := verify.NewSignedRevocationList(f.root.RegistryURL, issued.Format(time.RFC3339Nano), epoch, revoked, f.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify.VerifyRevocationList(list, f.root, 0); err != nil && epoch >= f.root.MinRevocationEpoch {
		t.Fatalf("fixture signature invalid: %v", err)
	}
	raw, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func (f stateFixture) reopen(t *testing.T) *Store {
	t.Helper()
	s, err := New(f.dir, f.root)
	if err != nil {
		t.Fatal(err)
	}
	s.now = f.clock.now
	return s
}
func enrollFixture(t *testing.T, f stateFixture, epoch int) Status {
	t.Helper()
	status, err := f.store.Enroll(context.Background(), f.list(t, epoch, f.clock.now().Add(-time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	return status
}
func stateJSONPath(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(p)
		if err == nil && bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
			found = append(found, p)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected one JSON state record, found %d", len(found))
	}
	return found[0]
}

func TestStateEnrollmentRestartAndDecisionIsolation(t *testing.T) {
	f := newStateFixture(t)
	now := f.clock.now()
	raw := f.list(t, 7, now.Add(-time.Hour))
	first, err := f.store.Enroll(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if first.Epoch != 7 || first.Registry != f.root.RegistryURL || first.RootFingerprint == "" || first.EvidenceFingerprint == "" || !first.LastSeen.Equal(now) {
		t.Fatalf("incomplete enrollment: %+v", first)
	}
	reopened := f.reopen(t)
	status, err := reopened.Status(context.Background())
	if err != nil || status != first {
		t.Fatalf("restart changed authority: %+v error=%v", status, err)
	}
	if _, err := reopened.Enroll(context.Background(), raw); err == nil {
		t.Fatal("reenrollment overwrote existing history")
	}
	session, err := reopened.Begin(context.Background(), verify.MutationInstall, f.digest)
	if err != nil {
		t.Fatal(err)
	}
	decision := session.Decision()
	if !decision.Allowed || decision.Epoch != 7 || decision.SubjectDigest != f.digest {
		t.Fatalf("wrong bound decision: %+v", decision)
	}
	decision.Allowed = false
	decision.Epoch = 0
	if !session.Decision().Allowed || session.Decision().Epoch != 7 {
		t.Fatal("caller modified stored decision")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStateMissingAndCorruptNeverInitializeImplicitly(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		f := newStateFixture(t)
		if _, err := f.store.Status(context.Background()); err == nil {
			t.Fatal("missing history reported enrolled")
		}
		if session, err := f.store.Begin(context.Background(), verify.MutationInstall, f.digest); err == nil || session != nil {
			t.Fatal("missing history authorized mutation")
		}
		if _, err := f.store.Adopt(context.Background(), f.list(t, 7, f.clock.now().Add(-time.Hour))); err == nil {
			t.Fatal("adopt initialized missing history")
		}
		if _, err := os.Lstat(f.dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read/begin/adopt created absent store: %v", err)
		}
	})
	for _, kind := range []string{"truncated", "version", "unknown_field", "duplicate_schema", "escaped_duplicate", "case_alias", "missing_clock", "missing_full_list", "evidence_hash", "wrong_registry", "record_epoch"} {
		t.Run(kind, func(t *testing.T) {
			f := newStateFixture(t)
			enrollFixture(t, f, 7)
			p := stateJSONPath(t, f.store.dir)
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			var record map[string]json.RawMessage
			if err := json.Unmarshal(raw, &record); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "truncated":
				raw = []byte("{")
			case "version":
				record["schema"] = json.RawMessage(`"unsupported-state-schema"`)
				raw, err = json.Marshal(record)
			case "unknown_field":
				record["unknown_authority"] = json.RawMessage(`true`)
				raw, err = json.Marshal(record)
			case "duplicate_schema":
				raw = append([]byte(`{"schema":"forged",`), bytes.TrimSpace(raw)[1:]...)
			case "escaped_duplicate":
				raw = append([]byte(`{"\u0073chema":"forged",`), bytes.TrimSpace(raw)[1:]...)
			case "case_alias":
				raw = append([]byte(`{"Schema":"forged",`), bytes.TrimSpace(raw)[1:]...)
			case "missing_clock":
				delete(record, "last_seen")
				raw, err = json.Marshal(record)
			case "missing_full_list":
				delete(record, "full_list")
				raw, err = json.Marshal(record)
			case "evidence_hash":
				record["evidence_fingerprint"] = json.RawMessage(`"invalid"`)
				raw, err = json.Marshal(record)
			case "wrong_registry":
				record["registry"] = json.RawMessage(`"https://foreign.invalid/skills"`)
				raw, err = json.Marshal(record)
			case "record_epoch":
				record["epoch"] = json.RawMessage(`6`)
				raw, err = json.Marshal(record)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, raw, 0600); err != nil {
				t.Fatal(err)
			}
			s := f.reopen(t)
			if _, err := s.Status(context.Background()); err == nil {
				t.Fatal("corrupt record accepted")
			}
			if _, err := s.Enroll(context.Background(), f.list(t, 8, f.clock.now())); err == nil {
				t.Fatal("corrupt record silently reenrolled")
			}
			if _, err := s.Adopt(context.Background(), f.list(t, 8, f.clock.now())); err == nil {
				t.Fatal("adopt repaired corrupt history implicitly")
			}
			if session, err := s.Begin(context.Background(), verify.MutationInstall, f.digest); err == nil || session != nil {
				t.Fatal("corrupt history authorized mutation")
			}
		})
	}
}

func TestStateSignedEvidenceBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		age   time.Duration
		epoch int
		deny  bool
	}{
		{"fresh", time.Hour, 7, false}, {"exact24h", 24 * time.Hour, 7, false}, {"over24h", 24*time.Hour + time.Nanosecond, 7, true}, {"future", -time.Nanosecond, 7, true}, {"unversioned", time.Hour, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newStateFixture(t)
			_, err := f.store.Enroll(context.Background(), f.list(t, tc.epoch, f.clock.now().Add(-tc.age)))
			if (err != nil) != tc.deny {
				t.Fatalf("enrollment boundary deny=%t error=%v", tc.deny, err)
			}
		})
	}
	for _, kind := range []string{"unsigned", "foreign_registry", "foreign_key", "duplicate_field", "checkpoint_instead_of_list", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			f := newStateFixture(t)
			raw := f.list(t, 7, f.clock.now().Add(-time.Hour))
			var list verify.RevocationList
			if err := json.Unmarshal(raw, &list); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "unsigned":
				list.SignatureB64 = ""
				raw, _ = json.Marshal(list)
			case "foreign_registry":
				foreign := f
				copyRoot := *f.root
				copyRoot.RegistryURL = "https://other.invalid/skills"
				foreign.root = &copyRoot
				raw = foreign.list(t, 7, f.clock.now().Add(-time.Hour))
			case "foreign_key":
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				list, err := verify.NewSignedRevocationList(f.root.RegistryURL, f.clock.now().Format(time.RFC3339Nano), 7, nil, key)
				if err != nil {
					t.Fatal(err)
				}
				raw, _ = json.Marshal(list)
			case "duplicate_field":
				raw = append([]byte(`{"epoch":7,`), bytes.TrimSpace(raw)[1:]...)
			case "checkpoint_instead_of_list":
				checkpoint, err := verify.NewSignedFreshnessCheckpoint(f.root.RegistryURL, 8, f.clock.now().Format(time.RFC3339Nano), f.key)
				if err != nil {
					t.Fatal(err)
				}
				raw, _ = json.Marshal(checkpoint)
			case "oversize":
				raw = bytes.Repeat([]byte(" "), (1<<20)+1)
			}
			if _, err := f.store.Enroll(context.Background(), raw); err == nil {
				t.Fatal("invalid authority enrolled")
			}
		})
	}
}

func TestStateEpochClockAndSubjectPersistAcrossRestart(t *testing.T) {
	f := newStateFixture(t)
	first := enrollFixture(t, f, 7)
	initial := f.clock.now()
	f.clock.set(initial.Add(time.Hour))
	adopted, err := f.store.Adopt(context.Background(), f.list(t, 8, f.clock.now()))
	if err != nil || adopted.Epoch != 8 {
		t.Fatalf("advance failed: %+v error=%v", adopted, err)
	}
	s := f.reopen(t)
	if _, err := s.Adopt(context.Background(), f.list(t, 7, f.clock.now())); err == nil {
		t.Fatal("epoch rollback adopted after restart")
	}
	f.clock.set(initial.Add(30 * time.Minute))
	if session, err := s.Begin(context.Background(), verify.MutationInstall, f.digest); err == nil || session != nil {
		t.Fatal("clock rollback authorized after restart")
	}
	if _, err := s.Adopt(context.Background(), f.list(t, 9, f.clock.now())); err == nil {
		t.Fatal("clock rollback accepted during adopt")
	}
	f.clock.set(initial.Add(2 * time.Hour))
	if _, err := s.Adopt(context.Background(), f.list(t, 9, f.clock.now(), f.digest)); err != nil {
		t.Fatal(err)
	}
	for _, action := range []verify.MutationAction{verify.MutationInstall, verify.MutationAdmit, verify.MutationAttest} {
		if session, err := s.Begin(context.Background(), action, f.digest); !errors.Is(err, verify.ErrIdentityRevoked) || verify.ExitCode(err) != 17 || session != nil {
			t.Fatalf("revoked subject did not fail closed with exit17: action=%s err=%v", action, err)
		}
	}
	last, err := s.Status(context.Background())
	if err != nil || last.Epoch < first.Epoch || last.Epoch != 9 {
		t.Fatalf("persisted floor lost: %+v %v", last, err)
	}
}

func TestStateSameEpochCannotChangeSignedSet(t *testing.T) {
	f := newStateFixture(t)
	now := f.clock.now()
	raw := f.list(t, 7, now.Add(-time.Hour))
	if _, err := f.store.Enroll(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Adopt(context.Background(), raw); err != nil {
		t.Fatalf("identical same epoch refused: %v", err)
	}
	if _, err := f.store.Adopt(context.Background(), f.list(t, 7, now.Add(-time.Hour), f.digest)); err == nil {
		t.Fatal("same epoch changed revocation set")
	}
	if _, err := f.store.Adopt(context.Background(), f.list(t, 7, now.Add(-30*time.Minute))); err != nil {
		t.Fatalf("same normalized set with newer signed issuance refused: %v", err)
	}
	if _, err := f.store.Adopt(context.Background(), raw); err == nil {
		t.Fatal("same epoch rolled issuance backward after refresh")
	}
}

func TestStateRootBindingCannotShareAuthority(t *testing.T) {
	for _, kind := range []string{"registry_path", "registry_host", "key_rotation", "epoch_floor"} {
		t.Run(kind, func(t *testing.T) {
			f := newStateFixture(t)
			enrollFixture(t, f, 7)
			root := *f.root
			root.RegistryKeys = append([]verify.RegistryKey(nil), f.root.RegistryKeys...)
			switch kind {
			case "registry_path":
				root.RegistryURL += "/different"
			case "registry_host":
				root.RegistryURL = "https://other.invalid/skills"
			case "key_rotation":
				public, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				root.RegistryKeys[0].Pubkey = public
				root.RegistryKeys[0].PubkeyB64 = base64.StdEncoding.EncodeToString(public)
			case "epoch_floor":
				root.MinRevocationEpoch = 8
			}
			s, err := New(f.dir, &root)
			if err != nil {
				return
			}
			s.now = f.clock.now
			if _, err := s.Status(context.Background()); err == nil {
				t.Fatal("changed root accepted existing authority")
			}
			if session, err := s.Begin(context.Background(), verify.MutationInstall, f.digest); err == nil || session != nil {
				t.Fatal("changed root authorized mutation")
			}
		})
	}
}

func TestStateSessionLockAndCanceledWaiter(t *testing.T) {
	f := newStateFixture(t)
	enrollFixture(t, f, 7)
	active, err := f.store.Begin(context.Background(), verify.MutationInstall, f.digest)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = active.Close()
		}
	}()
	other := f.reopen(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := other.Adopt(ctx, f.list(t, 8, f.clock.now())); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("competing writer bypassed lock or lost cancellation: %v", err)
	}
	if err := active.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if _, err := other.Adopt(ctx2, f.list(t, 8, f.clock.now())); err != nil {
		t.Fatalf("closed session failed to release lock: %v", err)
	}
}

func TestStateWriteFailuresNeverAuthorize(t *testing.T) {
	for _, operation := range []string{"enroll", "adopt", "begin"} {
		for _, fault := range []string{"short_write", "write", "sync", "close", "replace", "dir_sync"} {
			t.Run(operation+"/"+fault, func(t *testing.T) {
				f := newStateFixture(t)
				if operation != "enroll" {
					enrollFixture(t, f, 7)
					f.clock.set(f.clock.now().Add(time.Minute))
				}
				calls := 0
				injected := errors.New("synthetic persistence failure")
				switch fault {
				case "short_write":
					f.store.ops.write = func(*os.File, []byte) (int, error) { calls++; return 0, nil }
				case "write":
					f.store.ops.write = func(*os.File, []byte) (int, error) { calls++; return 0, injected }
				case "sync":
					f.store.ops.sync = func(*os.File) error { calls++; return injected }
				case "close":
					f.store.ops.close = func(file *os.File) error { calls++; _ = file.Close(); return injected }
				case "replace":
					f.store.ops.replace = func(string, string) error { calls++; return injected }
				case "dir_sync":
					original := f.store.ops.syncDir
					f.store.ops.syncDir = func(path string) error {
						if path == f.store.dir {
							if _, err := os.Stat(f.store.statePath); err == nil {
								calls++
								return injected
							}
						}
						return original(path)
					}
				}
				var err error
				switch operation {
				case "enroll":
					_, err = f.store.Enroll(context.Background(), f.list(t, 7, f.clock.now().Add(-time.Hour)))
				case "adopt":
					_, err = f.store.Adopt(context.Background(), f.list(t, 8, f.clock.now()))
				case "begin":
					var session *Session
					session, err = f.store.Begin(context.Background(), verify.MutationInstall, f.digest)
					if session != nil {
						t.Error("failed durable commit returned session")
						_ = session.Close()
					}
				}
				if err == nil || !errors.Is(err, ErrPersistence) || calls == 0 {
					t.Fatalf("fault not reached or not denied as persistence error: calls=%d err=%v", calls, err)
				}
				// Failure after rename/dir-sync may leave an advanced state. Never promise
				// rollback; check that any surviving state can only preserve/raise floors.
				reopened := f.reopen(t)
				status, readErr := reopened.Status(context.Background())
				if readErr == nil && operation != "enroll" && status.Epoch < 7 {
					t.Fatalf("fault lowered epoch: %+v", status)
				}
				if operation == "enroll" {
					if _, err := reopened.Enroll(context.Background(), f.list(t, 8, f.clock.now())); err == nil {
						t.Fatal("failed enrollment reservation was silently reused")
					}
				}
			})
		}
	}
}

func TestStateBeginRechecksAgeAfterTimePasses(t *testing.T) {
	f := newStateFixture(t)
	enrollFixture(t, f, 7)
	f.clock.set(f.clock.now().Add(23 * time.Hour))
	session, err := f.store.Begin(context.Background(), verify.MutationInstall, f.digest)
	if err != nil {
		t.Fatalf("exact24h refused: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	f.clock.set(f.clock.now().Add(time.Nanosecond))
	if session, err := f.reopen(t).Begin(context.Background(), verify.MutationInstall, f.digest); err == nil || session != nil {
		t.Fatal("expired decision reused after restart")
	}
}

func TestStateInvalidActionAndDigestNeverAuthorize(t *testing.T) {
	f := newStateFixture(t)
	enrollFixture(t, f, 7)
	for _, tc := range []struct {
		action verify.MutationAction
		digest string
	}{{"execute", f.digest}, {verify.MutationInstall, ""}, {verify.MutationInstall, "sha256:invalid"}} {
		if session, err := f.store.Begin(context.Background(), tc.action, tc.digest); err == nil || session != nil {
			t.Fatal("invalid mutation authorized")
		}
	}
}

func TestStateLostRecordIsNotFreshEnrollment(t *testing.T) {
	f := newStateFixture(t)
	enrollFixture(t, f, 7)
	if err := os.Remove(stateJSONPath(t, f.store.dir)); err != nil {
		t.Fatal(err)
	}
	reopened := f.reopen(t)
	if _, err := reopened.Enroll(context.Background(), f.list(t, 8, f.clock.now())); err == nil {
		t.Fatal("lost record silently reenrolled reserved directory")
	}
	if _, err := reopened.Adopt(context.Background(), f.list(t, 8, f.clock.now())); err == nil {
		t.Fatal("lost record silently repaired by adopt")
	}
	if session, err := reopened.Begin(context.Background(), verify.MutationInstall, f.digest); err == nil || session != nil {
		t.Fatal("lost record authorized mutation")
	}
}

func TestStateFreshAdoptionAfterStaleHistory(t *testing.T) {
	f := newStateFixture(t)
	enrollFixture(t, f, 7)
	f.clock.set(f.clock.now().Add(26 * time.Hour))
	if session, err := f.reopen(t).Begin(context.Background(), verify.MutationInstall, f.digest); err == nil || session != nil {
		t.Fatal("old full snapshot remained fresh")
	}
	checkpoint, err := verify.NewSignedFreshnessCheckpoint(f.root.RegistryURL, 8, f.clock.now().Format(time.RFC3339Nano), f.key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Adopt(context.Background(), raw); err == nil {
		t.Fatal("checkpoint replaced expired complete list")
	}
	if session, err := f.reopen(t).Begin(context.Background(), verify.MutationInstall, f.digest); err == nil || session != nil {
		t.Fatal("checkpoint refreshed stale history")
	}
	status, err := f.store.Adopt(context.Background(), f.list(t, 8, f.clock.now()))
	if err != nil || status.Epoch != 8 {
		t.Fatalf("fresh complete-list recovery refused: %+v %v", status, err)
	}
	session, err := f.reopen(t).Begin(context.Background(), verify.MutationInstall, f.digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStateConstructorSnapshotsRoot(t *testing.T) {
	f := newStateFixture(t)
	registry := f.root.RegistryURL
	raw := f.list(t, 7, f.clock.now().Add(-time.Hour))
	f.root.RegistryURL = "https://foreign.invalid/skills"
	f.root.RegistryKeys[0].Pubkey[0] ^= 1
	f.root.MaxStaleness = "1ns"
	status, err := f.store.Enroll(context.Background(), raw)
	if err != nil || status.Registry != registry {
		t.Fatalf("caller mutated constructed trust snapshot: %+v error=%v", status, err)
	}
	session, err := f.store.Begin(context.Background(), verify.MutationInstall, f.digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStateEvidenceAndRecordSizeBoundaries(t *testing.T) {
	const evidenceCap = 1 << 20
	const recordCap = 2 << 20
	for _, extra := range []int{0, 1} {
		t.Run(map[int]string{0: "exact_evidence_cap", 1: "evidence_cap_plus_one"}[extra], func(t *testing.T) {
			f := newStateFixture(t)
			raw := f.list(t, 7, f.clock.now().Add(-time.Hour))
			raw = append(raw, bytes.Repeat([]byte(" "), evidenceCap+extra-len(raw))...)
			// Padding preserves syntactically valid JSON and the authenticated full list.
			var list verify.RevocationList
			if err := json.Unmarshal(raw, &list); err != nil {
				t.Fatal(err)
			}
			if _, err := verify.VerifyRevocationList(&list, f.root, 0); err != nil {
				t.Fatal(err)
			}
			status, err := f.store.Enroll(context.Background(), raw)
			if extra == 1 {
				if err == nil {
					t.Fatal("oversize valid signed evidence accepted")
				}
			} else if err != nil || status.Epoch != 7 {
				t.Fatalf("exact-cap valid signed evidence refused: %+v %v", status, err)
			}
		})
	}
	for _, extra := range []int{0, 1} {
		t.Run(map[int]string{0: "exact_record_cap", 1: "record_cap_plus_one"}[extra], func(t *testing.T) {
			f := newStateFixture(t)
			enrollFixture(t, f, 7)
			path := stateJSONPath(t, f.store.dir)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			raw = append(raw, bytes.Repeat([]byte(" "), recordCap+extra-len(raw))...)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			var syntax map[string]any
			if err := json.Unmarshal(raw, &syntax); err != nil {
				t.Fatal(err)
			}
			status, err := f.reopen(t).Status(context.Background())
			if extra == 1 {
				if err == nil {
					t.Fatal("oversize valid JSON record accepted")
				}
			} else if err != nil || status.Epoch != 7 {
				t.Fatalf("exact-cap record refused: %+v %v", status, err)
			}
		})
	}
}

func TestStateCancellationAfterDurableCommitDoesNotAuthorize(t *testing.T) {
	for _, operation := range []string{"enroll", "adopt", "begin"} {
		t.Run(operation, func(t *testing.T) {
			f := newStateFixture(t)
			if operation != "enroll" {
				enrollFixture(t, f, 7)
				f.clock.set(f.clock.now().Add(time.Minute))
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			original := f.store.ops.syncDir
			calls := 0
			f.store.ops.syncDir = func(path string) error {
				err := original(path)
				if err == nil && path == f.store.dir {
					if _, readErr := os.Stat(f.store.statePath); readErr == nil {
						calls++
						cancel()
					}
				}
				return err
			}
			var err error
			switch operation {
			case "enroll":
				_, err = f.store.Enroll(ctx, f.list(t, 7, f.clock.now().Add(-time.Hour)))
			case "adopt":
				_, err = f.store.Adopt(ctx, f.list(t, 8, f.clock.now()))
			case "begin":
				var session *Session
				session, err = f.store.Begin(ctx, verify.MutationInstall, f.digest)
				if session != nil {
					_ = session.Close()
					t.Fatal("canceled commit granted a session")
				}
			}
			if calls == 0 || !errors.Is(err, context.Canceled) {
				t.Fatalf("post-commit cancellation not refused: calls=%d err=%v", calls, err)
			}
			// Cancellation does not promise an undo after rename and directory flush.
			// A fresh process must see the conservative committed epoch, not a reset.
			status, err := f.reopen(t).Status(context.Background())
			if err != nil || status.Epoch < 7 {
				t.Fatalf("committed authority lost after canceled response: %+v %v", status, err)
			}
		})
	}
}
