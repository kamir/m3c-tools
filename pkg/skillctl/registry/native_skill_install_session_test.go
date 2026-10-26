package registry

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

type qaNativeSkillRegistryFixture struct {
	base    *nativeSessionQAFixture
	source  *NativeLiveSkillSource
	archive []byte
	target  string
}

func qaNativeSkillRegistryNew(t *testing.T) *qaNativeSkillRegistryFixture {
	t.Helper()
	f := nativeSessionQANew(t, nil)
	a := f.agent
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: native-session-agent\n---\n\nActual signed native SKILL, inert payload.\n"), 0600); err != nil {
		t.Fatal(qaNativeSkillRegistryCauses(err))
	}
	if err := os.Mkdir(filepath.Join(dir, "references"), 0700); err != nil {
		t.Fatal(qaNativeSkillRegistryCauses(err))
	}
	if err := os.WriteFile(filepath.Join(dir, "references", "inert.txt"), []byte("exact nested payload\n"), 0600); err != nil {
		t.Fatal(qaNativeSkillRegistryCauses(err))
	}
	var raw bytes.Buffer
	if _, err := skillbundle.PackToWriter(dir, &raw, skillbundle.PackOptions{Manifest: skillbundle.BundleManifest{Name: a.name, Version: "1.0.0", DependsOn: []skillbundle.Dependency{}}}); err != nil {
		t.Fatal(qaNativeSkillRegistryCauses(err))
	}
	a.blob = raw.Bytes()
	item, digest := mintAdmitItem(t, a.registryKey, a.name, "1.0.0", string(a.blob))
	event, err := extractEvent(itemBody(item))
	if err != nil {
		t.Fatal(qaNativeSkillRegistryCauses(err))
	}
	a.staged.Kind = "skill"
	a.staged.Digest = digest
	a.staged.Attestation = &AttestationContext{AdmitEvent: event}
	for i, key := range a.signerKeys {
		e := signedAttest(t, key, a.roots.Signers[i].ReviewerID, digest, "green", a.now.Add(-time.Minute).Format(time.RFC3339), nil)
		a.staged.Attestation.GovernanceAttestations = append(a.staged.Attestation.GovernanceAttestations, e)
	}
	a.staged.Attestation.GovernanceAttestation = a.staged.Attestation.GovernanceAttestations[0]
	events := append([]map[string]any{event}, a.staged.Attestation.GovernanceAttestations...)
	items := []map[string]any{}
	for i, e := range events {
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(qaNativeSkillRegistryCauses(err))
		}
		body := "```json\n" + string(b) + "\n```\n"
		if i == 0 {
			body += "```skb-base64\n" + base64.StdEncoding.EncodeToString(a.blob) + "\n```\n"
		}
		items = append(items, map[string]any{"doc_id": fmt.Sprintf("skill-%d", i), "transcript": body})
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Header.Get("Authorization") != "" || r.Header.Get("X-API-Key") != "" {
			t.Error("skill source used wrong method/credential")
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"items": items}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	source, err := NewNativeLiveSkillSource(NativeLiveSkillSourceOptions{BaseURL: server.URL, ContextID: "synthetic___skills", AuthMode: "none", TLSMode: "pinned-pem", CAPEM: ca})
	if err != nil {
		t.Fatal(qaNativeSkillRegistryCauses(err))
	}
	return &qaNativeSkillRegistryFixture{base: f, source: source, archive: append([]byte(nil), a.blob...), target: filepath.Join(f.journal.selection.home, ".claude", "skills", a.name)}
}
func (f *qaNativeSkillRegistryFixture) begin(t *testing.T) *NativeLiveSkillSession {
	t.Helper()
	s, err := NewNativeLiveSkillSession(context.Background(), f.base.journal, f.source, f.base.agent.staged.Digest)
	if err != nil {
		t.Fatal(qaNativeSkillRegistryCauses(err))
	}
	t.Cleanup(func() {
		t.Logf("skill work beforeCleanup=%d", s.workBytes)
		if e := s.Close(); e != nil {
			t.Error("checked skill cleanup", e)
		}
	})
	return s
}
func qaNativeSkillRegistryTree(t *testing.T, path string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(path, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(path, p)
		if e != nil {
			return e
		}
		if d.IsDir() {
			out[rel] = "directory"
			return nil
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		out[rel] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(qaNativeSkillRegistryCauses(err))
	}
	return out
}
func TestNativeSkillSessionPublicationBoundary(t *testing.T) {
	t.Run("canonical-Pack-retained-create-and-overwrite", func(t *testing.T) {
		f := qaNativeSkillRegistryNew(t)
		s := f.begin(t)
		p, err := qaNativeSkillRegistryPlan(t, s)
		if err != nil {
			t.Fatal(qaNativeSkillRegistryCauses(err))
		}
		if len(p.Rows) != 1 || p.Rows[0].Kind != "skill" || p.Rows[0].Operation != "create" || p.Rows[0].BackupPath != "" {
			t.Fatal("create consent row wrong")
		}
		if _, err = os.Stat(f.target); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("Plan published skill", err)
		}
		if _, err = qaNativeSkillRegistryConfirm(t, s, p.Token); err != nil {
			t.Fatal(qaNativeSkillRegistryCauses(err))
		}
		if err = s.Close(); err != nil {
			t.Fatal(qaNativeSkillRegistryCauses(err))
		}
		raw, err := os.ReadFile(filepath.Join(f.target, f.base.agent.name+".skb"))
		if err != nil || !bytes.Equal(raw, f.archive) {
			t.Fatal("selected signed outer archive not retained", err)
		}
		ctx, err := ReadAttestationStash(f.target)
		if err != nil || !reflect.DeepEqual(ctx, f.base.agent.staged.Attestation) {
			t.Fatal("complete signed proof changed", err)
		}
		old := qaNativeSkillRegistryTree(t, f.target)
		s2 := f.begin(t)
		p2, err := qaNativeSkillRegistryPlan(t, s2)
		if err != nil {
			t.Fatal(qaNativeSkillRegistryCauses(err))
		}
		if p2.Rows[0].Operation != "overwrite" || p2.Rows[0].OldDigest != f.base.agent.staged.Digest || p2.Rows[0].BackupPath == "" {
			t.Fatal("overwrite consent omitted prior digest/backup")
		}
		if _, err = qaNativeSkillRegistryConfirm(t, s2, p2.Token); err != nil {
			t.Fatal(qaNativeSkillRegistryCauses(err))
		}
		if got := qaNativeSkillRegistryTree(t, p2.Rows[0].BackupPath); !reflect.DeepEqual(got, old) {
			t.Fatal("planned backup lost exact old tree")
		}
	})
	t.Run("tree-changed-after-consent-no-rename", func(t *testing.T) {
		f := qaNativeSkillRegistryNew(t)
		s := f.begin(t)
		p, err := qaNativeSkillRegistryPlan(t, s)
		if err != nil {
			t.Fatal(qaNativeSkillRegistryCauses(err))
		}
		if _, err = qaNativeSkillRegistryConfirm(t, s, p.Token); err != nil {
			t.Fatal(qaNativeSkillRegistryCauses(err))
		}
		if err = s.Close(); err != nil {
			t.Fatal(qaNativeSkillRegistryCauses(err))
		}
		s2 := f.begin(t)
		p2, err := qaNativeSkillRegistryPlan(t, s2)
		if err != nil {
			t.Fatal(qaNativeSkillRegistryCauses(err))
		}
		changed := filepath.Join(f.target, "references", "inert.txt")
		if err = os.WriteFile(changed, []byte("external edited bytes\n"), 0600); err != nil {
			t.Fatal(qaNativeSkillRegistryCauses(err))
		}
		before := qaNativeSkillRegistryTree(t, f.target)
		if _, err = qaNativeSkillRegistryConfirm(t, s2, p2.Token); !errors.Is(err, ErrPlanDrift) {
			t.Fatal("target-tree change escaped consent binding", err)
		}
		if !reflect.DeepEqual(before, qaNativeSkillRegistryTree(t, f.target)) {
			t.Fatal("refused target change still modified old tree")
		}
	})
	t.Run("second-rename-fails-restores-exact-old-and-reports-uncertainty", func(t *testing.T) {
		f := qaNativeSkillRegistryNew(t)
		s := f.begin(t)
		p, err := qaNativeSkillRegistryPlan(t, s)
		if err != nil {
			t.Fatal(qaNativeSkillRegistryCauses(err))
		}
		if _, err = qaNativeSkillRegistryConfirm(t, s, p.Token); err != nil {
			t.Fatal(qaNativeSkillRegistryCauses(err))
		}
		if err = s.Close(); err != nil {
			t.Fatal(qaNativeSkillRegistryCauses(err))
		}
		old := qaNativeSkillRegistryTree(t, f.target)
		s2 := f.begin(t)
		p2, err := qaNativeSkillRegistryPlan(t, s2)
		if err != nil {
			t.Fatal(qaNativeSkillRegistryCauses(err))
		}
		ops := defaultNativeSkillFileOps()
		realRename := ops.rename
		calls := 0
		injected := errors.New("synthetic second rename failure")
		ops.rename = func(root *os.Root, a, b string) error {
			calls++
			if calls == 2 {
				return injected
			}
			return realRename(root, a, b)
		}
		s2.skillOps = &ops
		if _, err = qaNativeSkillRegistryConfirm(t, s2, p2.Token); !errors.Is(err, injected) || !errors.Is(err, ErrAgentPublicationIncomplete) || !errors.Is(err, ErrNativePersistence) || !strings.Contains(err.Error(), "files may already have changed") {
			t.Fatal("actual injected rename cause lost", err)
		}
		if calls < 3 {
			t.Fatal("failed publication did not attempt checked restoration")
		}
		if !reflect.DeepEqual(old, qaNativeSkillRegistryTree(t, f.target)) {
			t.Fatal("restore did not preserve exact old target")
		}
	})
	t.Run("late-tree-change-before-first-destructive-rename", func(t *testing.T) {
		f := qaNativeSkillRegistryNew(t)
		s := f.begin(t)
		plan, err := qaNativeSkillRegistryPlan(t, s)
		if err != nil {
			t.Fatal(qaNativeSkillRegistryCauses(err))
		}
		if _, err = qaNativeSkillRegistryConfirm(t, s, plan.Token); err != nil {
			t.Fatal(qaNativeSkillRegistryCauses(err))
		}
		if err = s.Close(); err != nil {
			t.Fatal(qaNativeSkillRegistryCauses(err))
		}
		s2 := f.begin(t)
		plan2, err := qaNativeSkillRegistryPlan(t, s2)
		if err != nil {
			t.Fatal(qaNativeSkillRegistryCauses(err))
		}
		changed := false
		var before map[string]string
		s2.phase = func(stage string) {
			if stage != "before-first-rename" {
				return
			}
			if err := os.WriteFile(filepath.Join(f.target, "references", "inert.txt"), []byte("late external tree edit\n"), 0600); err != nil {
				t.Fatal(err)
			}
			before = qaNativeSkillRegistryTree(t, f.target)
			changed = true
		}
		if _, err = qaNativeSkillRegistryConfirm(t, s2, plan2.Token); !errors.Is(err, ErrPlanDrift) || !changed {
			t.Fatal("late tree drift was not checked before first rename", qaNativeSkillRegistryCauses(err))
		}
		if !reflect.DeepEqual(before, qaNativeSkillRegistryTree(t, f.target)) {
			t.Fatal("late drift refusal changed original target")
		}
	})
	t.Run("expiry-during-before-first-rename", func(t *testing.T) {
		f := qaNativeSkillRegistryNew(t)
		s := f.begin(t)
		plan, err := qaNativeSkillRegistryPlan(t, s)
		if err != nil {
			t.Fatal(qaNativeSkillRegistryCauses(err))
		}
		reached := false
		s.phase = func(stage string) {
			if stage == "before-first-rename" {
				f.base.now = f.base.now.Add(TokenTTL + time.Second)
				reached = true
			}
		}
		if _, err = qaNativeSkillRegistryConfirm(t, s, plan.Token); !errors.Is(err, ErrNativeConsentInvalid) || !reached {
			t.Fatal("late consent expiry escaped final guard", qaNativeSkillRegistryCauses(err))
		}
		if _, err = os.Stat(f.target); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("expired skill created active target", err)
		}
	})

}

func qaNativeSkillRegistryCauses(err error) string {
	if err == nil {
		return "<nil>"
	}
	s := fmt.Sprintf("%T:%s", err, err.Error())
	if x, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range x.Unwrap() {
			s += "; " + qaNativeSkillRegistryCauses(e)
		}
	} else if e := errors.Unwrap(err); e != nil {
		s += "; " + qaNativeSkillRegistryCauses(e)
	}
	return s
}

func qaNativeSkillRegistryPlan(t *testing.T, s *NativeLiveSkillSession) (*NativeSkillInstallPlan, error) {
	t.Helper()
	t.Logf("skill work beforePlan=%d", s.workBytes)
	p, e := s.Plan(context.Background())
	t.Logf("skill work afterPlan=%d", s.workBytes)
	return p, e
}
func qaNativeSkillRegistryConfirm(t *testing.T, s *NativeLiveSkillSession, token string) ([]*InstallResult, error) {
	t.Helper()
	t.Logf("skill work beforeConfirm=%d", s.workBytes)
	out, e := s.Confirm(context.Background(), token)
	t.Logf("skill work afterConfirm=%d", s.workBytes)
	return out, e
}
