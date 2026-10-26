package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/dependencies"
)

type journalFixture struct {
	j         *NativeJournal
	selection *NativeInstallSelection
	key       ed25519.PrivateKey
	rootsRaw  []byte
	now       time.Time
}

func newJournalFixture(t *testing.T) *journalFixture {
	t.Helper()
	roots, key, raw := nativeFixtureRoots(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	canonical, _, err := nativePhysicalDirectory(home)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewNativeRevocationAuthority("self", nil, roots)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := NewNativeInstallSelection(strings.Repeat("a", 64), strings.Repeat("b", 64), canonical, canonical, roots, authority, dependencies.Profile{Schema: dependencies.ProfileSchema, ProjectRoot: canonical, Tools: []dependencies.Tool{}})
	if err != nil {
		t.Fatal(err)
	}
	j, err := OpenNativeJournal(selection)
	if err != nil {
		t.Fatal(err)
	}
	f := &journalFixture{j, selection, key, raw, time.Now().UTC().Truncate(time.Second)}
	j.now = func() time.Time { return f.now }
	return f
}
func (f *journalFixture) evidence(t *testing.T, epoch int, age time.Duration, set []string) []byte {
	t.Helper()
	return nativeEvidenceBytes(t, f.key, f.now.Add(-age), epoch, set, nil)
}
func journalEmpty() []string { return []string{} }
func TestNativeJournalEnrollmentAndHistory(t *testing.T) {

	t.Run("cancellation-and-invalid-context", func(t *testing.T) {
		f := newJournalFixture(t)
		raw := f.evidence(t, 1, time.Hour, journalEmpty())
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := f.j.Enroll(ctx, raw); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if _, err := os.Stat(f.j.base); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("canceled initialization created directories", err)
		}
		invalidContexts := []context.Context{nil}
		if _, err := f.j.Status(invalidContexts[0]); !errors.Is(err, ErrNativeSessionUnavailable) {
			t.Fatal("nil context accepted", err)
		}
		ctx, cancel = context.WithCancel(context.Background())
		ops := f.j.ops
		f.j.ops.syncDir = func(path string) error {
			err := ops.syncDir(path)
			if _, e := os.Stat(filepath.Join(f.j.dir, nativeJournalState)); e == nil {
				cancel()
			}
			return err
		}
		if _, err := f.j.Enroll(ctx, raw); !errors.Is(err, context.Canceled) {
			t.Fatal("postcommit cancellation returned success", err)
		}
		f.j.ops = ops
		if status, err := f.j.Status(context.Background()); err != nil || status.Epoch != 1 {
			t.Fatal("conservative postcommit record missing", err)
		}
	})
	t.Run("held-record-replacement-is-terminal", func(t *testing.T) {
		f := newJournalFixture(t)
		ctx := context.Background()
		if _, err := f.j.Enroll(ctx, f.evidence(t, 1, time.Hour, journalEmpty())); err != nil {
			t.Fatal(err)
		}
		lease, err := f.j.acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(f.j.dir, nativeJournalState)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.Rename(path, path+".previous"); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err = lease.recheck(ctx, "sha256:"+strings.Repeat("1", 64)); !errors.Is(err, ErrNativeHistoryInvalid) {
			t.Fatal("held history replacement accepted", err)
		}
		if err = lease.recheck(ctx, "sha256:"+strings.Repeat("1", 64)); !errors.Is(err, ErrNativeSessionUnavailable) {
			t.Fatal("failed lease recovered implicitly", err)
		}
		if err = lease.Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("explicit-restart-reservation", func(t *testing.T) {
		f := newJournalFixture(t)
		ctx := context.Background()
		if _, err := f.j.Status(ctx); !errors.Is(err, ErrNativeHistoryRequired) {
			t.Fatal(err)
		}
		if _, err := f.j.Adopt(ctx, f.evidence(t, 1, time.Hour, journalEmpty())); !errors.Is(err, ErrNativeHistoryRequired) {
			t.Fatal(err)
		}
		if _, err := f.j.acquire(ctx); !errors.Is(err, ErrNativeHistoryRequired) {
			t.Fatal(err)
		}
		if _, err := os.Stat(f.j.base); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("read operations created state", err)
		}
		raw := f.evidence(t, 1, time.Hour, journalEmpty())
		status, err := f.j.Enroll(ctx, raw)
		if err != nil {
			t.Fatal(err)
		}
		frame, err := os.ReadFile(filepath.Join(f.j.dir, nativeJournalState))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(frame[:8], []byte("M3CNH01\n")) {
			t.Fatal("frame magic")
		}
		n := int(binary.BigEndian.Uint32(frame[8:12]))
		size := int(binary.BigEndian.Uint32(frame[12:16]))
		if len(frame) != 16+n+size || !bytes.Equal(frame[16+n:], raw) {
			t.Fatal("frame does not retain exact signed full set")
		}
		var header map[string]any
		if json.Unmarshal(frame[16:16+n], &header) != nil || header["epoch"] != float64(1) || header["history_authority_id"] != status.HistoryAuthorityID {
			t.Fatal("independent header oracle failed")
		}
		restarted, err := OpenNativeJournal(f.selection)
		if err != nil {
			t.Fatal(err)
		}
		observed, err := restarted.Status(ctx)
		if err != nil || observed != status {
			t.Fatal("restart changed history", err)
		}
		if _, err = f.j.Enroll(ctx, raw); !errors.Is(err, ErrNativeHistoryExists) {
			t.Fatal("reenrollment", err)
		}
		if err = os.Remove(filepath.Join(f.j.dir, nativeJournalState)); err != nil {
			t.Fatal(err)
		}
		if _, err = f.j.Status(ctx); !errors.Is(err, ErrNativeHistoryInvalid) {
			t.Fatal(err)
		}
		if _, err = f.j.Enroll(ctx, raw); !errors.Is(err, ErrNativeHistoryExists) {
			t.Fatal("missing record repaired", err)
		}
	})
	t.Run("strict-frame-and-evidence", func(t *testing.T) {
		for _, name := range []string{"magic", "oversized-header", "oversized-evidence", "trailing", "truncated", "duplicate-header", "wrong-epoch", "wrong-key"} {
			t.Run(name, func(t *testing.T) {
				f := newJournalFixture(t)
				ctx := context.Background()
				if _, err := f.j.Enroll(ctx, f.evidence(t, 1, time.Hour, journalEmpty())); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(f.j.dir, nativeJournalState)
				frame, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				n := int(binary.BigEndian.Uint32(frame[8:12]))
				header := append([]byte(nil), frame[16:16+n]...)
				evidence := append([]byte(nil), frame[16+n:]...)
				switch name {
				case "magic":
					frame[0] ^= 1
				case "oversized-header":
					binary.BigEndian.PutUint32(frame[8:12], nativeJournalHeaderMax+1)
				case "oversized-evidence":
					binary.BigEndian.PutUint32(frame[12:16], nativeJournalEvidenceMax+1)
				case "trailing":
					frame = append(frame, 'x')
				case "truncated":
					frame = frame[:len(frame)-1]
				case "duplicate-header":
					header = append([]byte(`{"schema":"m3c.native-mutation-history/v1",`), header[1:]...)
				case "wrong-epoch":
					header = bytes.Replace(header, []byte(`"epoch":1`), []byte(`"epoch":2`), 1)
				case "wrong-key":
					_, other, _ := nativeFixtureRoots(t)
					evidence = nativeEvidenceBytes(t, other, f.now.Add(-time.Hour), 1, journalEmpty(), nil)
					var h map[string]any
					if json.Unmarshal(header, &h) != nil {
						t.Fatal("header fixture")
					}
					h["evidence_sha256"] = agentDigest(evidence)[7:]
					h["evidence_length"] = len(evidence)
					header, err = json.Marshal(h)
					if err != nil {
						t.Fatal(err)
					}
				}
				if name == "duplicate-header" || name == "wrong-epoch" || name == "wrong-key" {
					frame = make([]byte, 16)
					copy(frame, nativeJournalMagic)
					binary.BigEndian.PutUint32(frame[8:12], uint32(len(header)))
					binary.BigEndian.PutUint32(frame[12:16], uint32(len(evidence)))
					frame = append(frame, header...)
					frame = append(frame, evidence...)
				}
				if err = os.WriteFile(path, frame, 0600); err != nil {
					t.Fatal(err)
				}
				if status, err := f.j.Status(ctx); !errors.Is(err, ErrNativeHistoryInvalid) || status.Epoch != 0 {
					t.Fatal("invalid frame granted status", err)
				}
			})
		}
	})
}
func TestNativeJournalEpochClockAndFullSet(t *testing.T) {
	ctx := context.Background()
	subject := "sha256:" + strings.Repeat("1", 64)
	t.Run("stale-old-explicit-refresh-and-emergency", func(t *testing.T) {
		f := newJournalFixture(t)
		raw := f.evidence(t, 7, time.Hour, []string{subject})
		if _, err := f.j.Enroll(ctx, raw); err != nil {
			t.Fatal(err)
		}
		f.now = f.now.Add(25 * time.Hour)
		if _, err := f.j.Status(ctx); err != nil {
			t.Fatal("authenticated old history must remain readable", err)
		}
		lease, err := f.j.acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = lease.recheck(ctx, subject); !errors.Is(err, ErrNativeHistoryStale) {
			t.Fatal(err)
		}
		if err = lease.Close(); err != nil {
			t.Fatal(err)
		}
		fresh := f.evidence(t, 7, time.Minute, []string{subject})
		if _, err = f.j.Adopt(ctx, fresh); err != nil {
			t.Fatal("explicit refresh of stale authentic history denied", err)
		}
		changed := nativeEvidenceBytes(t, f.key, f.now, 7, []string{subject}, func(h map[string]any) { h["emergency"] = []string{subject} })
		if _, err = f.j.Adopt(ctx, changed); !errors.Is(err, ErrNativeHistoryStale) {
			t.Fatal("same epoch emergency changed", err)
		}
		if _, err = f.j.Adopt(ctx, f.evidence(t, 7, time.Second, []string{"sha256:" + strings.Repeat("2", 64)})); !errors.Is(err, ErrNativeHistoryStale) {
			t.Fatal("same epoch set changed", err)
		}
		lease, err = f.j.acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = lease.recheck(ctx, subject); !errors.Is(err, ErrNativeSubjectRevoked) {
			t.Fatal(err)
		}
		if err = lease.Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("inclusive-nanosecond-edge-and-rollback", func(t *testing.T) {
		f := newJournalFixture(t)
		issued := f.now.Add(-24 * time.Hour)
		raw := nativeEvidenceBytes(t, f.key, issued, 1, journalEmpty(), nil)
		if _, err := f.j.Enroll(ctx, raw); err != nil {
			t.Fatal("24h boundary rejected", err)
		}
		f.now = f.now.Add(time.Nanosecond)
		lease, err := f.j.acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = lease.recheck(ctx, subject); !errors.Is(err, ErrNativeHistoryStale) {
			t.Fatal("24h+1ns accepted", err)
		}
		if err = lease.Close(); err != nil {
			t.Fatal(err)
		}
		status, err := f.j.Status(ctx)
		if err != nil || !status.LastSeen.Equal(f.now) {
			t.Fatal("stale observation not persisted", err)
		}
		f.now = f.now.Add(-time.Nanosecond)
		if _, err = f.j.Adopt(ctx, f.evidence(t, 2, time.Hour, journalEmpty())); !errors.Is(err, ErrNativeHistoryStale) {
			t.Fatal("clock rollback accepted", err)
		}
	})
	t.Run("epoch-issued-and-set-order", func(t *testing.T) {
		f := newJournalFixture(t)
		set := []string{subject, "sha256:" + strings.Repeat("2", 64)}
		if _, err := f.j.Enroll(ctx, f.evidence(t, 7, time.Hour, set)); err != nil {
			t.Fatal(err)
		}
		reversed := []string{set[1], set[0]}
		if _, err := f.j.Adopt(ctx, f.evidence(t, 7, time.Minute, reversed)); err != nil {
			t.Fatal("set order treated as authority change", err)
		}
		for _, raw := range [][]byte{f.evidence(t, 6, time.Second, set), f.evidence(t, 8, 2*time.Hour, set), f.evidence(t, 8, -time.Minute, set)} {
			if _, err := f.j.Adopt(ctx, raw); !errors.Is(err, ErrNativeHistoryStale) {
				t.Fatal("rollback/future accepted", err)
			}
		}
	})
}
func TestNativeJournalLockAndPersistence(t *testing.T) {
	if os.Getenv("M3C_NATIVE_JOURNAL_CHILD") == "1" {
		home := os.Getenv("HOME")
		raw, err := os.ReadFile(filepath.Join(home, "fixture-roots.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		roots, err := ParseNativeRootsSnapshot(raw)
		if err != nil {
			t.Fatal(err)
		}
		authority, err := NewNativeRevocationAuthority("self", nil, roots)
		if err != nil {
			t.Fatal(err)
		}
		selection, err := NewNativeInstallSelection(strings.Repeat("a", 64), strings.Repeat("b", 64), home, home, roots, authority, dependencies.Profile{Schema: dependencies.ProfileSchema, ProjectRoot: home, Tools: []dependencies.Tool{}})
		if err != nil {
			t.Fatal(err)
		}
		j, err := OpenNativeJournal(selection)
		if err != nil {
			t.Fatal(err)
		}
		budget := 5 * time.Second
		if os.Getenv("M3C_NATIVE_JOURNAL_EXPECT_BUSY") == "1" {
			budget = 100 * time.Millisecond
		}
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		_, err = j.Status(ctx)
		if os.Getenv("M3C_NATIVE_JOURNAL_EXPECT_INVALID") == "1" {
			if !errors.Is(err, ErrNativeHistoryInvalid) {
				t.Fatal("special record did not fail before open", err)
			}
		} else if os.Getenv("M3C_NATIVE_JOURNAL_EXPECT_BUSY") == "1" {
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("held OS lock did not block", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		return
	}

	t.Run("existing-special-record-before-open", func(t *testing.T) {
		for _, kind := range nativeJournalSpecialKinds() {
			t.Run(kind, func(t *testing.T) {
				f := newJournalFixture(t)
				ctx := context.Background()
				if _, err := f.j.Enroll(ctx, f.evidence(t, 1, time.Hour, journalEmpty())); err != nil {
					t.Fatal(err)
				}
				if _, err := f.j.Status(ctx); err != nil {
					t.Fatal("ordinary positive failed", err)
				}
				if err := os.WriteFile(filepath.Join(f.selection.home, "fixture-roots.yaml"), f.rootsRaw, 0600); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(f.j.dir, nativeJournalState)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				nativeJournalMakeSpecial(t, path, kind)
				exe, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				wait, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				cmd := exec.CommandContext(wait, exe, "-test.run=^TestNativeJournalLockAndPersistence$")
				cmd.WaitDelay = time.Second
				cmd.Env = append(os.Environ(), "HOME="+f.selection.home, "USERPROFILE="+f.selection.home, "M3C_NATIVE_JOURNAL_CHILD=1", "M3C_NATIVE_JOURNAL_EXPECT_INVALID=1")
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("bounded special-file child failed: %v %s", err, output)
				}
			})
		}
	})
	t.Run("real-process-lock", func(t *testing.T) {
		f := newJournalFixture(t)
		ctx := context.Background()
		if _, err := f.j.Enroll(ctx, f.evidence(t, 1, time.Hour, journalEmpty())); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.selection.home, "fixture-roots.yaml"), f.rootsRaw, 0600); err != nil {
			t.Fatal(err)
		}
		lease, err := f.j.acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		run := func(busy bool) {
			t.Helper()
			exe, e := os.Executable()
			if e != nil {
				t.Fatal(e)
			}
			wait, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(wait, exe, "-test.run=^TestNativeJournalLockAndPersistence$")
			cmd.WaitDelay = time.Second
			value := "0"
			if busy {
				value = "1"
			}
			cmd.Env = append(os.Environ(), "HOME="+f.selection.home, "USERPROFILE="+f.selection.home, "M3C_NATIVE_JOURNAL_CHILD=1", "M3C_NATIVE_JOURNAL_EXPECT_BUSY="+value)
			output, e := cmd.CombinedOutput()
			if e != nil {
				t.Fatalf("child lock control: %v %s", e, output)
			}
		}
		run(true)
		if err = lease.Close(); err != nil {
			t.Fatal(err)
		}
		run(false)
	})
	for _, phase := range []string{"enroll", "adopt", "recheck"} {
		for _, fault := range []string{"write", "short", "sync", "close", "replace", "dirsync"} {
			t.Run(phase+"/"+fault, func(t *testing.T) {
				f := newJournalFixture(t)
				ctx := context.Background()
				if phase != "enroll" {
					if _, err := f.j.Enroll(ctx, f.evidence(t, 1, time.Hour, journalEmpty())); err != nil {
						t.Fatal(err)
					}
				}
				var lease *nativeJournalLease
				var err error
				if phase == "recheck" {
					lease, err = f.j.acquire(ctx)
					if err != nil {
						t.Fatal(err)
					}
				}
				sentinel := errors.New("private-injected-io-marker")
				ops := f.j.ops
				switch fault {
				case "write":
					f.j.ops.write = func(*os.File, []byte) (int, error) { return 0, sentinel }
				case "short":
					f.j.ops.write = func(_ *os.File, b []byte) (int, error) { return len(b) - 1, nil }
				case "sync":
					f.j.ops.sync = func(file *os.File) error { return errors.Join(ops.sync(file), sentinel) }
				case "close":
					f.j.ops.close = func(file *os.File) error { return errors.Join(ops.close(file), sentinel) }
				case "replace":
					f.j.ops.replace = func(string, string) error { return sentinel }
				case "dirsync":
					f.j.ops.syncDir = func(path string) error { return errors.Join(ops.syncDir(path), sentinel) }
				}
				switch phase {
				case "enroll":
					_, err = f.j.Enroll(ctx, f.evidence(t, 1, time.Hour, journalEmpty()))
				case "adopt":
					_, err = f.j.Adopt(ctx, f.evidence(t, 2, time.Minute, journalEmpty()))
				case "recheck":
					err = lease.recheck(ctx, "sha256:"+strings.Repeat("1", 64))
				}
				if err == nil {
					t.Fatal("IO failure returned success")
				}
				if strings.Contains(err.Error(), "private-injected") {
					t.Fatal("raw cause leaked into public diagnostic")
				}
				if fault != "short" && !errors.Is(err, sentinel) {
					t.Fatal("typed IO cause lost", err)
				}
				if fault == "short" && !errors.Is(err, io.ErrShortWrite) {
					t.Fatal("short write cause lost", err)
				}
				f.j.ops = ops
				if lease != nil {
					if err = lease.recheck(ctx, "sha256:"+strings.Repeat("1", 64)); !errors.Is(err, ErrNativeSessionUnavailable) {
						t.Fatal("poisoned lease retried", err)
					}
					if err = lease.Close(); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}
