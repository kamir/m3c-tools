package registry

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

func nativeSkillAuthorBegin(t *testing.T, f *qaNativeSkillRegistryFixture) *NativeLiveSkillSession {
	t.Helper()
	s, err := NewNativeLiveSkillSession(context.Background(), f.base.journal, f.source, f.base.agent.staged.Digest)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNativeSkillConsentAndTargets(t *testing.T) {
	t.Run("canceled-entry-consumes-nonce", func(t *testing.T) {
		f := qaNativeSkillRegistryNew(t)
		s := nativeSkillAuthorBegin(t, f)
		p, err := s.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err = s.Confirm(ctx, p.Token); !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation cause lost", err)
		}
		if _, err = s.Confirm(context.Background(), p.Token); !errors.Is(err, ErrNativeConsentInvalid) {
			t.Fatal("canceled attempt left reusable token", err)
		}
		if _, err = os.Stat(f.target); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("canceled entry published", err)
		}
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("malformedDigestDeniedBeforeBusyJournal", func(t *testing.T) {
		f := qaNativeSkillRegistryNew(t)
		held := nativeSkillAuthorBegin(t, f)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if s, err := NewNativeLiveSkillSession(ctx, f.base.journal, f.source, "sha256:bad"); s != nil || !errors.Is(err, ErrNativeEvidenceInvalid) || errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("invalid digest reached journal/source", s, err)
		}
		if err := held.Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("physicalHomeReplacementBeforeFirstRename", func(t *testing.T) {
		f := qaNativeSkillRegistryNew(t)
		s := nativeSkillAuthorBegin(t, f)
		closed := false
		t.Cleanup(func() {
			if !closed {
				if err := s.Close(); err != nil {
					t.Errorf("checked emergency session cleanup: %v", err)
				}
			}
		})
		p, err := s.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		home := f.base.journal.selection.home
		moved := home + "-moved"
		changed, prevented := false, false
		s.phase = func(phase string) {
			if phase != "before-first-rename" {
				return
			}
			err := os.Rename(home, moved)
			if err != nil {
				// Windows can prevent the attempted mutation while the live
				// handles remain held. This branch proves OS prevention, not
				// detection of a replacement that actually occurred.
				if runtime.GOOS != "windows" || (!errors.Is(err, syscall.Errno(5)) && !errors.Is(err, syscall.Errno(32))) {
					t.Fatal("unexpected home rename failure", err)
				}
				path, e := os.Lstat(home)
				held, he := s.fs.home.Stat(".")
				if e != nil || he != nil || !os.SameFile(path, held) || !os.SameFile(path, f.base.journal.selection.homeInfo) || f.base.journal.selection.validate() != nil {
					t.Fatal("OS-prevention control lost unchanged home")
				}
				if _, e := os.Lstat(moved); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("OS prevention unexpectedly moved home", e)
				}
				if _, e := os.Lstat(f.target); !errors.Is(e, os.ErrNotExist) || s.published {
					t.Fatal("OS prevention control lost absent target", e)
				}
				prevented = true
				return
			}
			changed = true
			if err = os.Mkdir(home, 0700); err != nil {
				t.Fatal(err)
			}
		}
		installed, err := s.Confirm(context.Background(), p.Token)
		if changed {
			if err == nil || s.published {
				t.Fatal("replaced home reached publication", err)
			}
			if _, e := os.Lstat(f.target); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("published into replacement home", e)
			}
			if _, e := os.Lstat(filepath.Join(moved, ".claude", "skills", f.base.agent.name)); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("published into detached old home", e)
			}
			e := s.Close()
			closed = true
			if !errors.Is(e, ErrNativePersistence) {
				t.Fatal("detached workspace uncertainty lost", e)
			}
			if e := os.Remove(home); e != nil {
				t.Fatal(e)
			}
		} else {
			if !prevented || err != nil {
				t.Fatal("OS prevention control failed", prevented, err)
			}
			if len(installed) != 1 || installed[0] == nil || installed[0].SkillPath != f.target {
				t.Fatal("OS prevention control lost actual installed result")
			}
			archive, archiveErr := os.ReadFile(filepath.Join(f.target, s.prepared.bundle.Name+".skb"))
			contextRaw, contextErr := os.ReadFile(filepath.Join(f.target, AttestationStashName))
			if archiveErr != nil || contextErr != nil || !bytes.Equal(archive, s.prepared.archive) || !bytes.Equal(contextRaw, s.prepared.contextRaw) {
				t.Fatal("OS prevention control lost retained installed proof", archiveErr, contextErr)
			}
			e := s.Close()
			closed = true
			if e != nil {
				t.Fatal(e)
			}
			if e := os.Rename(home, moved); e != nil {
				t.Fatal("post-Close home rename remained blocked", e)
			}
		}
		if e := os.Rename(moved, home); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("strictNumericReleaseOrdering", func(t *testing.T) {
		for _, row := range []struct {
			new, old string
			older    bool
		}{{"1", "1.0.0.0", false}, {"1.0.0.1", "1", false}, {"1.9", "2", true}, {"18446744073709551615.0", "18446744073709551614.99", false}, {"0.0.0.0", "0.0.0.1", true}} {
			got, err := nativeSkillVersionOlder(row.new, row.old)
			if err != nil || got != row.older {
				t.Fatal("numeric ordering", row, got, err)
			}
		}
		for _, bad := range []string{"", "v1.0", "1.0.0-rc", "1.0+build", "01.0", "1..0", "+1", "1 ", "1.2.3.4.5", "18446744073709551616", "١.0", strings.Repeat("1", 84)} {
			if nativeSkillVersionValid(bad) {
				t.Fatalf("unsupported version accepted %q", bad)
			}
			if _, err := nativeSkillVersionOlder(bad, "1.0.0"); !errors.Is(err, ErrNativeEvidenceInvalid) {
				t.Fatal("invalid new version silently ordered", err)
			}
			if _, err := nativeSkillVersionOlder("1.0.0", bad); !errors.Is(err, ErrNativeEvidenceInvalid) {
				t.Fatal("invalid old version silently ordered", err)
			}
		}
	})
	t.Run("wrongTokenCheckedCloseAndFreshPlan", func(t *testing.T) {
		f := qaNativeSkillRegistryNew(t)
		s := nativeSkillAuthorBegin(t, f)
		p, err := s.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.Confirm(context.Background(), strings.Repeat("A", 43)); !errors.Is(err, ErrNativeConsentInvalid) {
			t.Fatalf("wrong nonce cause: %v", err)
		}
		if _, err = os.Stat(f.target); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("wrong nonce published", err)
		}
		marker := filepath.Join(f.base.journal.selection.home, ".claude", "skills", s.workspace.marker)
		if err = s.Close(); err != nil {
			t.Fatalf("healthy cancellation Close: %v", err)
		}
		if _, err = os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("owned pending reservation remains", err)
		}
		next := nativeSkillAuthorBegin(t, f)
		p2, err := next.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if p.Token == p2.Token {
			t.Fatal("fresh session reused nonce")
		}
		if err = next.Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("replanConsumesOldToken", func(t *testing.T) {
		f := qaNativeSkillRegistryNew(t)
		s := nativeSkillAuthorBegin(t, f)
		p, err := s.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		q, err := s.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if p.Token == q.Token {
			t.Fatal("replan reused nonce")
		}
		if _, err = s.Confirm(context.Background(), p.Token); !errors.Is(err, ErrNativeConsentInvalid) {
			t.Fatal(err)
		}
		if _, err = s.Confirm(context.Background(), q.Token); !errors.Is(err, ErrNativeConsentInvalid) {
			t.Fatal("attempt did not consume current plan", err)
		}
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("completeTreeRejectsPostPlanEmptyDirectory", func(t *testing.T) {
		f := qaNativeSkillRegistryNew(t)
		s := nativeSkillAuthorBegin(t, f)
		p, err := s.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.Confirm(context.Background(), p.Token); err != nil {
			t.Fatal(err)
		}
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
		next := nativeSkillAuthorBegin(t, f)
		p, err = next.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err = os.Mkdir(filepath.Join(f.target, "new-empty-directory"), 0700); err != nil {
			t.Fatal(err)
		}
		if _, err = next.Confirm(context.Background(), p.Token); !errors.Is(err, ErrPlanDrift) {
			t.Fatal("whole tree change accepted", err)
		}
		if next.published {
			t.Fatal("changed target reached first rename")
		}
		if err = next.Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("treeWorkCapAndHardlink", func(t *testing.T) {
		f := qaNativeSkillRegistryNew(t)
		s := nativeSkillAuthorBegin(t, f)
		if _, err := s.Plan(context.Background()); err != nil {
			t.Fatal(err)
		}
		before := s.workBytes
		s.workBytes = nativeLiveWorkMax - 1
		if _, err := s.fs.tree(context.Background(), s.workspace.stage, false, s.prepared.bundle.Name); !errors.Is(err, ErrNativeEvidenceInvalid) {
			t.Fatal("tree read escaped cumulative cap", err)
		}
		s.workBytes = before
		payload := filepath.Join(f.base.journal.selection.home, ".claude", "skills", s.workspace.stage, "SKILL.md")
		link := filepath.Join(f.base.journal.selection.home, ".claude", "skills", s.workspace.stage, "another.md")
		if err := os.Link(payload, link); err != nil {
			t.Fatal(err)
		}
		if _, err := s.fs.tree(context.Background(), s.workspace.stage, false, s.prepared.bundle.Name); !errors.Is(err, ErrNativeHistoryInvalid) {
			t.Fatal("hardlink accepted", err)
		}
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); !errors.Is(err, ErrNativePersistence) {
			t.Fatal("mutated stage cleanup must retain reservation", err)
		}
	})
}

func TestNativeSkillPublicationFailures(t *testing.T) {
	t.Run("createdTransactionParentSyncFailsBeforeRename", func(t *testing.T) {
		f := qaNativeSkillRegistryNew(t)
		s := nativeSkillAuthorBegin(t, f)
		ops := defaultNativeSkillFileOps()
		base := ops.syncParent
		fault := errors.New("synthetic transaction-parent sync failure")
		hit := false
		ops.syncParent = func(path string) error {
			if path == filepath.Join(f.base.journal.selection.home, ".claude", "skills", ".native-skill", "transactions") {
				hit = true
				return fault
			}
			return base(path)
		}
		s.skillOps = &ops
		if _, err := s.Plan(context.Background()); !hit || !errors.Is(err, fault) || !errors.Is(err, ErrNativePersistence) {
			t.Fatal("creation parent was not synced", hit, err)
		}
		if s.published {
			t.Fatal("creation sync failure reached rename")
		}
		if _, err := os.Lstat(f.target); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("creation sync failure published target", err)
		}
		if err := s.Close(); !errors.Is(err, fault) {
			t.Fatal("checked Close lost parent uncertainty", err)
		}
	})
	t.Run("PackScriptModeAppliedOnHeldFile", func(t *testing.T) {
		// This is a concrete I/O policy unit, not a publication grant. The real
		// SDK create/overwrite positives separately test held native authority.
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# modes\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(dir, "scripts"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "scripts", "run.sh"), []byte("#!/bin/sh\nexit 91\n"), 0755); err != nil {
			t.Fatal(err)
		}
		var raw bytes.Buffer
		if _, err := skillbundle.PackToWriter(dir, &raw, skillbundle.PackOptions{Manifest: skillbundle.BundleManifest{Name: "retained-skill", Version: "1.0.0", DependsOn: []skillbundle.Dependency{}}}); err != nil {
			t.Fatal(err)
		}
		signed := nativeSkillEvidenceFixture(t, raw.Bytes())
		p, err := prepareNativeSkillEvidence(signed.staged, raw.Bytes(), signed.opts())
		if err != nil {
			t.Fatal(err)
		}
		selected := nativeSessionQANew(t, nil).journal.selection
		work := int64(0)
		fs, err := openNativeSkillFS(selected, &work, defaultNativeSkillFileOps())
		if err != nil {
			t.Fatal(err)
		}
		root, done, err := fs.dir("io-mode-fixture/scripts", true)
		if err != nil {
			t.Fatal(err)
		}
		_ = root
		if err = done(); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, entry := range p.entries {
			if entry.Rel == "scripts/run.sh" {
				found = true
				if entry.Mode.Perm() != 0755 {
					t.Fatal("unpack lost canonical script mode")
				}
				if _, err = fs.writeMode("io-mode-fixture/scripts/run.sh", entry.Content, entry.Mode); err != nil {
					t.Fatal(err)
				}
			}
		}
		if !found {
			t.Fatal("signed real Pack script missing")
		}
		info, err := os.Stat(filepath.Join(selected.home, ".claude", "skills", "io-mode-fixture", "scripts", "run.sh"))
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0755 {
			t.Fatal("held writer dropped script executable policy", info.Mode())
		}
		if err = fs.Close(); err != nil {
			t.Fatal(err)
		}
	})
	for _, which := range []string{"file", "root"} {
		t.Run("cleanup-empty-EOF-plus-"+which+"-close", func(t *testing.T) {
			f := qaNativeSkillRegistryNew(t)
			s := nativeSkillAuthorBegin(t, f)
			if _, err := s.Plan(context.Background()); err != nil {
				t.Fatal(err)
			}
			fault := errors.New("synthetic final empty transaction Close failure")
			armed, injected := false, false
			tx := filepath.Join(f.base.journal.selection.home, ".claude", "skills", s.workspace.transaction)
			s.phase = func(phase string) {
				if phase == "cleanup-empty-check" {
					armed = true
				}
			}
			baseFile, baseRoot := s.fs.ops.closeFile, s.fs.ops.closeRoot
			s.fs.ops.closeFile = func(file *os.File) error {
				err := baseFile(file)
				if which == "file" && armed && !injected && filepath.Clean(file.Name()) == tx {
					injected = true
					return errors.Join(err, fault)
				}
				return err
			}
			s.fs.ops.closeRoot = func(root *os.Root) error {
				err := baseRoot(root)
				if which == "root" && armed && !injected && filepath.Clean(root.Name()) == tx {
					injected = true
					return errors.Join(err, fault)
				}
				return err
			}
			if err := s.Close(); !injected || !errors.Is(err, fault) || !errors.Is(err, ErrNativePersistence) {
				t.Fatal("EOF swallowed checked Close", injected, err)
			}
			if _, err := os.Stat(filepath.Join(f.base.journal.selection.home, ".claude", "skills", s.workspace.marker)); err != nil {
				t.Fatal("uncertain cancellation lost marker", err)
			}
		})
	}
	t.Run("replan-close-is-sticky-before-further-IO", func(t *testing.T) {
		f := qaNativeSkillRegistryNew(t)
		s := nativeSkillAuthorBegin(t, f)
		p, err := s.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.Confirm(context.Background(), p.Token); err != nil {
			t.Fatal(err)
		}
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
		next := nativeSkillAuthorBegin(t, f)
		if _, err = next.Plan(context.Background()); err != nil {
			t.Fatal(err)
		}
		fault := errors.New("synthetic unclosed target file")
		base := next.fs.ops.closeFile
		injected := false
		calls := 0
		next.fs.ops.closeFile = func(file *os.File) error {
			calls++
			if !injected && filepath.Base(file.Name()) == "bundle.json" {
				injected = true
				return fault
			}
			return base(file)
		}
		if _, err = next.Plan(context.Background()); !injected || !errors.Is(err, fault) {
			t.Fatal("replan Close fault not reached", err)
		}
		before := calls
		if _, err = next.Plan(context.Background()); !errors.Is(err, ErrNativeSessionUnavailable) || !errors.Is(err, ErrNativePersistence) {
			t.Fatal("uncertain FS was reusable", err)
		}
		if calls != before {
			t.Fatal("poisoned plan performed further file IO")
		}
		if err = next.Close(); !errors.Is(err, fault) {
			t.Fatal("shutdown lost uncertain Close", err)
		}
	})
	t.Run("closed-publication-lock-cannot-publish", func(t *testing.T) {
		f := qaNativeSkillRegistryNew(t)
		s := nativeSkillAuthorBegin(t, f)
		p, err := s.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err = s.workspace.lock.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err = s.Confirm(context.Background(), p.Token); !errors.Is(err, ErrNativePersistence) {
			t.Fatal("closed lock was treated as held", err)
		}
		if s.published {
			t.Fatal("first rename reached without live publication lock")
		}
		if _, err = os.Stat(f.target); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("target appeared", err)
		}
		if err = s.Close(); !errors.Is(err, ErrNativePersistence) {
			t.Fatal("closed descriptor outcome lost", err)
		}
	})
	t.Run("canonical-payload-modes-and-private-proof", func(t *testing.T) {
		f := qaNativeSkillRegistryNew(t)
		s := nativeSkillAuthorBegin(t, f)
		p, err := s.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.Confirm(context.Background(), p.Token); err != nil {
			t.Fatal(err)
		}
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
		for _, row := range []struct {
			path string
			mode os.FileMode
		}{{"SKILL.md", 0644}, {"references", 0755}, {"references/inert.txt", 0644}, {".skillctl-attest.json", 0600}, {".m3c-provenance.json", 0600}, {f.base.agent.name + ".skb", 0600}} {
			info, err := os.Stat(filepath.Join(f.target, filepath.FromSlash(row.path)))
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm() != row.mode {
				t.Fatalf("canonical mode %s got%o want%o", row.path, info.Mode().Perm(), row.mode)
			}
		}
	})
	t.Run("firstRenameFailurePreservesMarkerAndOldBody", func(t *testing.T) {
		f := qaNativeSkillRegistryNew(t)
		s := nativeSkillAuthorBegin(t, f)
		p, err := s.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.Confirm(context.Background(), p.Token); err != nil {
			t.Fatal(err)
		}
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
		old := qaNativeSkillRegistryTree(t, f.target)
		next := nativeSkillAuthorBegin(t, f)
		p, err = next.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		fault := errors.New("synthetic first rename failure")
		next.fs.ops.rename = func(*os.Root, string, string) error { return fault }
		if _, err = next.Confirm(context.Background(), p.Token); !errors.Is(err, fault) || !errors.Is(err, ErrAgentPublicationIncomplete) {
			t.Fatal("possible-change cause lost", err)
		}
		if _, err = next.Plan(context.Background()); !errors.Is(err, ErrNativeSessionUnavailable) || !errors.Is(err, fault) {
			t.Fatal("post-rename failure session resumed", err)
		}
		if now := qaNativeSkillRegistryTree(t, f.target); len(now) != len(old) || now["SKILL.md"] != old["SKILL.md"] {
			t.Fatal("failed first rename changed old tree")
		}
		marker := filepath.Join(f.base.journal.selection.home, ".claude", "skills", next.workspace.marker)
		if _, err = os.Stat(marker); err != nil {
			t.Fatal("reservation not retained", err)
		}
		if err = next.Close(); err != nil {
			t.Fatal(err)
		}
		third := nativeSkillAuthorBegin(t, f)
		if _, err = third.Plan(context.Background()); !errors.Is(err, ErrNativeHistoryExists) {
			t.Fatal("pending state adopted", err)
		}
		if err = third.Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("checkedRootCloseAfterPublicationIsUncertain", func(t *testing.T) {
		f := qaNativeSkillRegistryNew(t)
		s := nativeSkillAuthorBegin(t, f)
		p, err := s.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.Confirm(context.Background(), p.Token); err != nil {
			t.Fatal(err)
		}
		fault := errors.New("synthetic root close failure")
		base := s.fs.ops.closeRoot
		s.fs.ops.closeRoot = func(r *os.Root) error { return errors.Join(base(r), fault) }
		if err = s.Close(); !errors.Is(err, fault) || !errors.Is(err, ErrAgentPublicationIncomplete) || !errors.Is(err, ErrNativePersistence) {
			t.Fatal("Close uncertainty lost", err)
		}
		if err = s.Close(); !errors.Is(err, fault) {
			t.Fatal("repeat Close lost outcome", err)
		}
	})
}
