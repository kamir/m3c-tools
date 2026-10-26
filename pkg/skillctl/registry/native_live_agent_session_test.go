package registry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func nativeLiveSessionFixture(t *testing.T, fields map[string]any) (*NativeLiveAgentSession, *nativeSessionQAFixture) {
	t.Helper()
	f := nativeSessionQANew(t, fields)
	inner, err := f.journal.BeginOfflineInstall(context.Background(), f.agent.staged.Digest)
	if err != nil {
		t.Fatal(err)
	}
	bundle, _, err := inner.snapshotInput([]*StagedBundle{f.agent.staged})
	if err != nil {
		t.Fatal(err)
	}
	bundle.StagedSkbPath, bundle.ProvenancePath = "", ""
	live := &NativeLiveAgentSession{session: inner, candidate: &NativeLiveAgentCandidate{Archive: append([]byte(nil), f.agent.blob...), Bundle: bundle}}
	inner.liveWork = &live.workBytes
	t.Cleanup(func() {
		if e := live.Close(); e != nil {
			t.Errorf("checked live close: %v", e)
		}
	})
	return live, f
}

func TestNativeLiveSessionRetainedConsent(t *testing.T) {
	t.Run("small-existing-target-overwrite", func(t *testing.T) {
		live, f := nativeLiveSessionFixture(t, nil)
		first, err := live.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = live.Confirm(context.Background(), first.Token); err != nil {
			t.Fatal(err)
		}
		if err = live.Close(); err != nil {
			t.Fatal(err)
		}
		inner, err := f.journal.BeginOfflineInstall(context.Background(), f.agent.staged.Digest)
		if err != nil {
			t.Fatal(err)
		}
		again := &NativeLiveAgentSession{session: inner, candidate: live.candidate}
		inner.liveWork = &again.workBytes
		defer func() {
			if e := again.Close(); e != nil {
				t.Error(e)
			}
		}()
		plan, err := again.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if plan.Rows[0].Operation != "overwrite" || plan.Rows[0].OldDigest == "" {
			t.Fatal("overwrite omitted current target")
		}
		if _, err = again.Confirm(context.Background(), plan.Token); err != nil {
			t.Fatal("small overwrite failed", err)
		}
	})

	t.Run("actual-source-metadata-enters-consent", func(t *testing.T) {
		live, _ := nativeLiveSessionFixture(t, nil)
		live.session.liveSourceBinding = strings.Repeat("a", 64)
		if _, err := live.Plan(context.Background()); err != nil {
			t.Fatal(err)
		}
		first := live.session.plan.planHash
		live.session.liveSourceBinding = strings.Repeat("b", 64)
		if _, err := live.Plan(context.Background()); err != nil {
			t.Fatal(err)
		}
		if first == live.session.plan.planHash {
			t.Fatal("actual source metadata absent from consent")
		}
	})

	t.Run("signed-retained-bytes-no-staged-reopen", func(t *testing.T) {
		live, f := nativeLiveSessionFixture(t, nil)
		plan, err := live.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.Rows) != 1 || plan.Rows[0].Operation != "create" || len(plan.Token) != 43 {
			t.Fatal("missing actual native consent")
		}
		if err = os.Remove(f.agent.staged.StagedSkbPath); err != nil {
			t.Fatal(err)
		}
		for i := range f.agent.blob {
			f.agent.blob[i] = 0
		}
		target := plan.Rows[0].Target
		if _, err = os.Stat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("Plan published active bytes", err)
		}
		results, err := live.Confirm(context.Background(), plan.Token)
		if err != nil || len(results) != 1 {
			t.Fatal("retained signed confirmation failed", err)
		}
		body, err := os.ReadFile(target)
		if err != nil || !strings.Contains(string(body), "Signed native session fixture.") {
			t.Fatal("wrong active retained body", err)
		}
		record := filepath.Join(filepath.Dir(target), ".skillctl-evidence", f.agent.name+".record")
		if info, err := os.Stat(record); err != nil || info.Size() == 0 {
			t.Fatal("retained proof missing", err)
		}
		if _, err = live.Confirm(context.Background(), plan.Token); !errors.Is(err, ErrNativeSessionUnavailable) {
			t.Fatal("consent replay was not denied", err)
		}
	})
	t.Run("replan-invalidates-and-attempt-consumes", func(t *testing.T) {
		live, _ := nativeLiveSessionFixture(t, nil)
		first, err := live.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		second, err := live.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if first.Token == second.Token {
			t.Fatal("replan reused nonce")
		}
		if _, err = live.Confirm(context.Background(), first.Token); !errors.Is(err, ErrNativeConsentInvalid) {
			t.Fatal("old token accepted", err)
		}
		if _, err = live.Confirm(context.Background(), second.Token); !errors.Is(err, ErrNativeConsentInvalid) {
			t.Fatal("attempt failed to consume current plan", err)
		}
		if _, err = os.Stat(second.Rows[0].Target); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("failed consent changed target", err)
		}
	})
}

func TestNativeLiveSessionFailClosed(t *testing.T) {
	t.Run("target-growth-between-final-observations", func(t *testing.T) {
		live, f := nativeLiveSessionFixture(t, nil)
		dir := filepath.Join(f.journal.selection.home, ".claude", "agents")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(dir, f.agent.name+".md")
		if err := os.WriteFile(target, []byte("existing target"), 0600); err != nil {
			t.Fatal(err)
		}
		plan, err := live.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		reached := false
		live.session.phase = func(stage string) {
			if stage != "before-agent-lock" {
				return
			}
			reached = true
			if e := os.WriteFile(target, []byte("externally grown target "+strings.Repeat("x", 1<<20)), 0600); e != nil {
				t.Fatal(e)
			}
		}
		if _, err = live.Confirm(context.Background(), plan.Token); !errors.Is(err, ErrPlanDrift) {
			t.Fatal("changed target escaped final observation", err)
		}
		if !reached {
			t.Fatal("did not reach actual final phase")
		}
		body, err := os.ReadFile(target)
		if err != nil || !strings.HasPrefix(string(body), "externally grown target ") {
			t.Fatal("denied confirmation published over changed target", err)
		}
		if _, err = os.Stat(filepath.Join(dir, ".skillctl-evidence", f.agent.name+".record")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("denied growth wrote retained proof", err)
		}
	})

	t.Run("existing-target-read-and-directory-batch-budget", func(t *testing.T) {
		live, f := nativeLiveSessionFixture(t, nil)
		home := f.journal.selection.home
		dir := filepath.Join(home, ".claude", "agents")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(dir, f.agent.name+".md")
		if err := os.WriteFile(target, []byte(strings.Repeat("x", 1<<20)), 0600); err != nil {
			t.Fatal(err)
		}
		positive, err := nativeObserveTargetsWork(f.journal.selection, f.agent.name, nil)
		if err != nil || !positive[0].Exists || positive[0].Bytes != 1<<20 {
			t.Fatal("uncapped ordinary target control", err)
		}
		used := int64(nativeLiveWorkMax - 1024)
		if _, err = nativeObserveTargetsWork(f.journal.selection, f.agent.name, &used); !errors.Is(err, ErrNativeEvidenceInvalid) {
			t.Fatal("large target read exceeded cumulative work", err)
		}
		if err = os.WriteFile(target, []byte("small"), 0600); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 200; i++ {
			name := filepath.Join(dir, fmt.Sprintf("ordinary-%03d", i))
			if err = os.WriteFile(name, []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		used = 0
		if _, err = nativeObserveTargetsWork(f.journal.selection, f.agent.name, &used); err != nil {
			t.Fatal("bounded batch positive", err)
		}
		used = nativeLiveWorkMax - 700000
		if _, err = nativeObserveTargetsWork(f.journal.selection, f.agent.name, &used); !errors.Is(err, ErrNativeEvidenceInvalid) {
			t.Fatal("second directory batch was not charged", err)
		}
		if live.session.plan != nil {
			t.Fatal("observer changed consent")
		}
	})

	t.Run("cumulative-budget-terminal-before-unpack", func(t *testing.T) {
		live, _ := nativeLiveSessionFixture(t, nil)
		live.workBytes = nativeLiveWorkMax
		if _, err := live.Plan(context.Background()); !errors.Is(err, ErrNativeEvidenceInvalid) {
			t.Fatal("exhausted source work was refunded", err)
		}
		if !live.session.terminal || live.session.plan != nil {
			t.Fatal("work failure did not make live session terminal")
		}
		if _, err := live.Plan(context.Background()); !errors.Is(err, ErrNativeSessionUnavailable) {
			t.Fatal("terminal source session retried", err)
		}
	})

	t.Run("signed-nonempty-dependencies", func(t *testing.T) {
		live, _ := nativeLiveSessionFixture(t, map[string]any{"depends_on": []any{map[string]any{"kind": "skill", "name": "missing", "constraint": "*"}}})
		if _, err := live.Plan(context.Background()); !errors.Is(err, ErrNativeDependenciesUnavailable) {
			t.Fatal("signed dependencies accepted", err)
		}
	})
	t.Run("closed-and-nil-context", func(t *testing.T) {
		live, _ := nativeLiveSessionFixture(t, nil)
		var nilContext context.Context
		if _, err := live.Plan(nilContext); !errors.Is(err, ErrNativeSessionUnavailable) {
			t.Fatal("nil context accepted", err)
		}
		if err := live.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := live.Plan(context.Background()); !errors.Is(err, ErrNativeSessionUnavailable) {
			t.Fatal("closed session planned", err)
		}
	})
	t.Run("zero-facade", func(t *testing.T) {
		var live NativeLiveAgentSession
		if _, err := live.Plan(context.Background()); !errors.Is(err, ErrNativeSessionUnavailable) {
			t.Fatal(err)
		}
		if _, err := live.Confirm(context.Background(), strings.Repeat("A", 43)); !errors.Is(err, ErrNativeSessionUnavailable) {
			t.Fatal(err)
		}
	})
}
