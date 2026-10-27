package registry

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pjbgf/sha1cd"
)

// The fixture builds actual Git binary tree payloads independently of the
// production codec. The server exposes only documented REST response shapes.
type nativeGitSessionTree struct {
	files map[string][]byte
	dirs  map[string]*nativeGitSessionTree
}
type nativeGitSessionAPI struct {
	source *NativeGitSource
	calls  atomic.Int64
}

func nativeGitSessionOID(t *testing.T, kind string, data []byte) string {
	t.Helper()
	framed := append([]byte(fmt.Sprintf("%s %d\x00", kind, len(data))), data...)
	sum, collision := sha1cd.Sum(framed)
	if collision {
		t.Fatal("ordinary Git fixture unexpectedly flagged")
	}
	return hex.EncodeToString(sum[:])
}

func nativeGitSessionSource(t *testing.T, provider string, f *nativeSessionQAFixture) *nativeGitSessionAPI {
	t.Helper()
	root := &nativeGitSessionTree{files: map[string][]byte{}, dirs: map[string]*nativeGitSessionTree{}}
	add := func(path string, data []byte) {
		parts := strings.Split(path, "/")
		node := root
		for _, name := range parts[:len(parts)-1] {
			if node.dirs[name] == nil {
				node.dirs[name] = &nativeGitSessionTree{files: map[string][]byte{}, dirs: map[string]*nativeGitSessionTree{}}
			}
			node = node.dirs[name]
		}
		node.files[parts[len(parts)-1]] = append([]byte(nil), data...)
	}
	b := f.agent.staged
	add("skills/"+b.Name+"/"+b.Version+"/bundle.skb", f.agent.blob)
	events := append([]map[string]any{b.Attestation.AdmitEvent}, b.Attestation.GovernanceAttestations...)
	for i, event := range events {
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		add(fmt.Sprintf("events/%s/%06d.json", strings.TrimPrefix(b.Digest, "sha256:"), i+1), raw)
	}
	trees := map[string][]map[string]any{}
	pathTrees := map[string]string{}
	blobs := map[string][]byte{}
	var encode func(*nativeGitSessionTree, string) string
	encode = func(node *nativeGitSessionTree, path string) string {
		keys := make([]string, 0, len(node.files)+len(node.dirs))
		for name := range node.files {
			keys = append(keys, name)
		}
		for name := range node.dirs {
			keys = append(keys, name)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := keys[i], keys[j]
			if node.dirs[a] != nil {
				a += "/"
			}
			if node.dirs[b] != nil {
				b += "/"
			}
			return a < b
		})
		var payload bytes.Buffer
		rows := []map[string]any{}
		for _, name := range keys {
			mode, typ := "100644", "blob"
			var oid string
			if child := node.dirs[name]; child != nil {
				mode, typ = "040000", "tree"
				oid = encode(child, strings.TrimPrefix(path+"/"+name, "/"))
			} else {
				oid = nativeGitSessionOID(t, "blob", node.files[name])
				blobs[oid] = node.files[name]
			}
			binaryOID, err := hex.DecodeString(oid)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&payload, "%s %s\x00", strings.TrimLeft(mode, "0"), name)
			payload.Write(binaryOID)
			row := map[string]any{"path": name, "mode": mode, "type": typ, "sha": oid}
			if typ == "blob" {
				row["size"] = len(node.files[name])
			}
			rows = append(rows, row)
		}
		oid := nativeGitSessionOID(t, "tree", payload.Bytes())
		trees[oid] = rows
		pathTrees[path] = oid
		return oid
	}
	rootOID := encode(root, "")
	commitOID := strings.Repeat("c", 40)
	fixture := &nativeGitSessionAPI{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.calls.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" || r.Header.Get("PRIVATE-TOKEN") != "" {
			t.Error("native Git session unexpected method or credential")
		}
		w.Header().Set("Content-Type", "application/json")
		parts := strings.Split(r.URL.Path, "/")
		last := parts[len(parts)-1]
		switch {
		case strings.Contains(r.URL.Path, "/commits/"):
			if last != commitOID {
				http.Error(w, "unexpected commit", 404)
				return
			}
			if provider == "github" {
				_ = json.NewEncoder(w).Encode(map[string]any{"sha": commitOID, "tree": map[string]any{"sha": rootOID}})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]any{"id": commitOID})
			}
		case strings.Contains(r.URL.Path, "/git/trees/"):
			rows, ok := trees[last]
			if !ok || r.URL.Query().Has("recursive") {
				http.Error(w, "unexpected tree", 404)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": last, "truncated": false, "tree": rows})
		case strings.HasSuffix(r.URL.Path, "/repository/tree"):
			if r.URL.Query().Get("ref") != commitOID {
				t.Error("GitLab omitted full commit ref")
			}
			oid, ok := pathTrees[r.URL.Query().Get("path")]
			if !ok {
				http.Error(w, "unexpected tree path", 404)
				return
			}
			rows := []map[string]any{}
			for _, old := range trees[oid] {
				name := old["path"].(string)
				path := strings.TrimPrefix(r.URL.Query().Get("path")+"/"+name, "/")
				rows = append(rows, map[string]any{"id": old["sha"], "name": name, "path": path, "type": old["type"], "mode": old["mode"]})
			}
			_ = json.NewEncoder(w).Encode(rows)
		case strings.Contains(r.URL.Path, "/blobs/"):
			if last == "raw" {
				last = parts[len(parts)-2]
			}
			blob, ok := blobs[last]
			if !ok {
				http.Error(w, "unexpected blob", 404)
				return
			}
			if provider == "github" {
				_ = json.NewEncoder(w).Encode(map[string]any{"sha": last, "encoding": "base64", "size": len(blob), "content": base64.StdEncoding.EncodeToString(blob)})
			} else {
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write(blob)
			}
		default:
			http.Error(w, "unexpected API path", 404)
		}
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	var err error
	fixture.source, err = NewNativeGitSource(NativeGitSourceOptions{Provider: provider, APIBase: server.URL, Repository: "owner/repo", CommitOID: commitOID, RootTreeOID: rootOID, ObjectFormat: "sha1", AuthMode: "none", TLSMode: "pinned-pem", CAPEM: ca})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestNativeGitSessionConsentAndPublication(t *testing.T) {

	t.Run("carried-source-work-cannot-reset-before-retain", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		inner := f.begin(t)
		b := *f.agent.staged
		b.StagedSkbPath = ""
		b.ProvenancePath = ""
		inner.mu.Lock()
		live, err := retainNativeAgentCandidateLocked(inner, &NativeLiveAgentCandidate{Archive: f.agent.blob, Bundle: &b, workBytes: nativeLiveWorkMax}, strings.Repeat("e", 64))
		inner.mu.Unlock()
		if live != nil || !errors.Is(err, ErrNativeEvidenceInvalid) {
			t.Fatalf("agent source work reset: %v", err)
		}
		// The SKILL retention helper rejects exhausted carried source work before
		// cloning or attempting any archive/manifest preparation.
		sf := qaNativeSkillRegistryNew(t)
		sb := *sf.base.agent.staged
		sb.StagedSkbPath, sb.ProvenancePath = "", ""
		skill := &NativeLiveSkillSession{rootDigest: sb.Digest}
		skill.mu.Lock()
		err = skill.retainCandidateLocked(&NativeLiveSkillCandidate{Archive: sf.archive, Bundle: &sb, workBytes: nativeLiveWorkMax}, strings.Repeat("e", 64))
		skill.mu.Unlock()
		if !errors.Is(err, ErrNativeEvidenceInvalid) || skill.candidate != nil {
			t.Fatalf("skill source work reset: %v", err)
		}
		bounded := &NativeLiveSkillSession{rootDigest: sb.Digest}
		bounded.mu.Lock()
		err = bounded.retainCandidateLocked(&NativeLiveSkillCandidate{Archive: sf.archive, Bundle: &sb}, strings.Repeat("e", 64))
		bounded.mu.Unlock()
		if err != nil || bounded.candidate == nil {
			t.Fatalf("same valid SKILL should retain under available budget: %v", err)
		}
	})
	t.Run("invalid-intent-grants-nothing", func(t *testing.T) {
		var nilContext context.Context
		if got, err := NewNativeGitAgentSession(nilContext, nil, nil, "invalid"); got != nil || !errors.Is(err, ErrNativeSessionUnavailable) {
			t.Fatalf("zero agent constructor: %v", err)
		}
		if got, err := NewNativeGitSkillSession(nilContext, nil, nil, "invalid"); got != nil || !errors.Is(err, ErrNativeSessionUnavailable) {
			t.Fatalf("zero skill constructor: %v", err)
		}
	})
	t.Run("fresh-history-before-source-and-checked-release", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		api := nativeGitSessionSource(t, "github", f)
		for _, kind := range []string{"agent", "skill"} {
			if kind == "agent" {
				if got, e := NewNativeGitAgentSession(context.Background(), f.journal, api.source, "invalid"); got != nil || !errors.Is(e, ErrNativeEvidenceInvalid) {
					t.Fatalf("agent invalid digest: %v", e)
				}
			} else {
				if got, e := NewNativeGitSkillSession(context.Background(), f.journal, api.source, "invalid"); got != nil || !errors.Is(e, ErrNativeEvidenceInvalid) {
					t.Fatalf("skill invalid digest: %v", e)
				}
			}
		}
		f.now = f.now.Add(25 * time.Hour)
		if got, e := NewNativeGitAgentSession(context.Background(), f.journal, api.source, f.agent.staged.Digest); got != nil || !errors.Is(e, ErrNativeHistoryStale) {
			t.Fatalf("agent stale: %v", e)
		}
		if got, e := NewNativeGitSkillSession(context.Background(), f.journal, api.source, f.agent.staged.Digest); got != nil || !errors.Is(e, ErrNativeHistoryStale) {
			t.Fatalf("skill stale: %v", e)
		}
		if api.calls.Load() != 0 {
			t.Fatal("stale/invalid intent contacted source")
		}
	})
	t.Run("source-error-releases-kind-lease", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		api := nativeGitSessionSource(t, "github", f)
		api.source.commit = strings.Repeat("d", 40)
		if got, e := NewNativeGitAgentSession(context.Background(), f.journal, api.source, f.agent.staged.Digest); got != nil || !errors.Is(e, ErrNativeGitSourceIO) {
			t.Fatalf("failed agent acquisition: %v", e)
		}
		if got, e := NewNativeGitSkillSession(context.Background(), f.journal, api.source, f.agent.staged.Digest); got != nil || !errors.Is(e, ErrNativeGitSourceIO) {
			t.Fatalf("failed skill acquisition: %v", e)
		}
		if _, e := f.journal.Status(context.Background()); e != nil {
			t.Fatal("failed acquisition retained lease", e)
		}
	})
	for _, provider := range []string{"github", "gitlab"} {
		for _, kind := range []string{"agent", "skill"} {
			t.Run(provider+"-"+kind, func(t *testing.T) {
				var f *nativeSessionQAFixture
				if kind == "skill" {
					f = qaNativeSkillRegistryNew(t).base
				} else {
					f = nativeSessionQANew(t, nil)
				}
				api := nativeGitSessionSource(t, provider, f)
				ctx := context.Background()
				if kind == "agent" {
					s, err := NewNativeGitAgentSession(ctx, f.journal, api.source, f.agent.staged.Digest)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if e := s.Close(); e != nil {
							t.Error(e)
						}
					})
					if !nativeSHA(s.session.liveSourceBinding) || s.session.liveSourceBinding == api.source.configID || s.workBytes == 0 {
						t.Fatal("missing actual source proof or carried work")
					}
					plan, err := s.Plan(ctx)
					if err != nil {
						t.Fatal(err)
					}
					calls := api.calls.Load()
					if _, err = s.Confirm(ctx, strings.Repeat("A", 43)); !errors.Is(err, ErrNativeConsentInvalid) {
						t.Fatalf("wrong consent: %v", err)
					}
					if _, err = os.Stat(plan.Rows[0].Target); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("wrong consent published target")
					}
					plan, err = s.Plan(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if _, err = s.Confirm(ctx, plan.Token); err != nil {
						t.Fatal(err)
					}
					if _, err = os.Stat(plan.Rows[0].Target); err != nil {
						t.Fatal(err)
					}
					if api.calls.Load() != calls {
						t.Fatal("consent refetched source")
					}
					if err = s.Close(); err != nil {
						t.Fatal(err)
					}
				} else {
					s, err := NewNativeGitSkillSession(ctx, f.journal, api.source, f.agent.staged.Digest)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if e := s.Close(); e != nil {
							t.Error(e)
						}
					})
					if !nativeSHA(s.sourceBinding) || s.sourceBinding == api.source.configID || s.workBytes == 0 {
						t.Fatal("missing skill snapshot binding or budget")
					}
					plan, err := s.Plan(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if _, err = s.Confirm(ctx, plan.Token); err != nil {
						t.Fatal(err)
					}
					if _, err = os.Stat(filepath.Join(plan.Rows[0].Target, "SKILL.md")); err != nil {
						t.Fatal(err)
					}
					if err = s.Close(); err != nil {
						t.Fatal(err)
					}
					second, err := NewNativeGitSkillSession(ctx, f.journal, api.source, f.agent.staged.Digest)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if e := second.Close(); e != nil {
							t.Error(e)
						}
					})
					plan, err = second.Plan(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if plan.Rows[0].Operation != "overwrite" || plan.Rows[0].BackupPath == "" {
						t.Fatal("old complete tree or backup missing from consent")
					}
					if _, err = second.Confirm(ctx, plan.Token); err != nil {
						t.Fatal(err)
					}
					if _, err = os.Stat(filepath.Join(plan.Rows[0].BackupPath, "SKILL.md")); err != nil {
						t.Fatal("healthy overwrite lost backup", err)
					}
					if err = second.Close(); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}
