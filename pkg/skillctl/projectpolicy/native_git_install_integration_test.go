package projectpolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/pjbgf/sha1cd"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// qaNativeGitObjects independently serializes Git trees; API labels never form
// the oracle. Commit IDs below are provenance labels, deliberately not raw commits.
type qaNativeGitEntry struct{ name, mode, kind, oid string }
type qaNativeGitObjects struct {
	blobs        map[string][]byte
	trees        map[string][]qaNativeGitEntry
	paths        map[string]string
	root, commit string
	mu           sync.Mutex
	requests     int
	tamperBlob   bool
	truncateTree bool
}

func qaNativeGitOID(kind string, raw []byte) string {
	framed := append([]byte(fmt.Sprintf("%s %d\x00", kind, len(raw))), raw...)
	sum, collision := sha1cd.Sum(framed)
	if collision {
		panic("ordinary fixture unexpectedly collided")
	}
	return hex.EncodeToString(sum[:])
}
func qaNativeGitGraph(t *testing.T, files map[string][]byte) *qaNativeGitObjects {
	t.Helper()
	if qaNativeGitOID("tree", nil) != "4b825dc642cb6eb9a060e54bf8d69288fbee4904" || qaNativeGitOID("blob", []byte("hello\n")) != "ce013625030ba8dba906f756967f9e9ca394464a" {
		t.Fatal("independent Git encoding golden changed")
	}
	g := &qaNativeGitObjects{blobs: map[string][]byte{}, trees: map[string][]qaNativeGitEntry{}, paths: map[string]string{}, commit: strings.Repeat("a", 40)}
	type node struct {
		files map[string][]byte
		dirs  map[string]*node
	}
	root := &node{map[string][]byte{}, map[string]*node{}}
	for p, b := range files {
		parts := strings.Split(p, "/")
		n := root
		for _, part := range parts[:len(parts)-1] {
			if n.dirs[part] == nil {
				n.dirs[part] = &node{map[string][]byte{}, map[string]*node{}}
			}
			n = n.dirs[part]
		}
		n.files[parts[len(parts)-1]] = append([]byte(nil), b...)
	}
	var encode func(*node, string) string
	encode = func(n *node, p string) string {
		entries := []qaNativeGitEntry{}
		for name, b := range n.files {
			oid := qaNativeGitOID("blob", b)
			g.blobs[oid] = b
			entries = append(entries, qaNativeGitEntry{name, "100644", "blob", oid})
		}
		for name, child := range n.dirs {
			entries = append(entries, qaNativeGitEntry{name, "040000", "tree", encode(child, path.Join(p, name))})
		}
		sort.Slice(entries, func(i, j int) bool {
			a, b := entries[i].name, entries[j].name
			if entries[i].kind == "tree" {
				a += "/"
			}
			if entries[j].kind == "tree" {
				b += "/"
			}
			return bytes.Compare([]byte(a), []byte(b)) < 0
		})
		var raw bytes.Buffer
		for _, e := range entries {
			mode := e.mode
			if e.kind == "tree" {
				mode = "40000"
			}
			fmt.Fprintf(&raw, "%s %s%c", mode, e.name, byte(0))
			oid, err := hex.DecodeString(e.oid)
			if err != nil {
				t.Fatal(err)
			}
			raw.Write(oid)
		}
		oid := qaNativeGitOID("tree", raw.Bytes())
		g.trees[oid] = entries
		g.paths[p] = oid
		return oid
	}
	g.root = encode(root, "")
	return g
}
func (g *qaNativeGitObjects) serve(t *testing.T, provider string, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requests++
	if r.Method != "GET" || r.ProtoMajor != 1 || r.Header.Get("Authorization") != "" || r.Header.Get("PRIVATE-TOKEN") != "" || r.Header.Get("Cookie") != "" {
		t.Error("public Git fixture saw ambient credentials or changed method/protocol")
	}
	w.Header().Set("Content-Type", "application/json")
	route := r.URL.Path
	if provider == "github" {
		prefix := "/api/repos/owner/repository/git/"
		if !strings.HasPrefix(route, prefix) {
			http.NotFound(w, r)
			return
		}
		tail := strings.TrimPrefix(route, prefix)
		switch {
		case tail == "commits/"+g.commit:
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": g.commit, "tree": map[string]any{"sha": g.root}})
		case strings.HasPrefix(tail, "trees/"):
			oid := strings.TrimPrefix(tail, "trees/")
			entries, ok := g.trees[oid]
			if !ok {
				http.NotFound(w, r)
				return
			}
			rows := []map[string]any{}
			for _, e := range entries {
				rows = append(rows, map[string]any{"path": e.name, "mode": e.mode, "type": e.kind, "sha": e.oid})
			}
			if g.truncateTree && oid == g.root {
				filtered := rows[:0]
				for _, row := range rows {
					if row["path"] != "foo.bar" {
						filtered = append(filtered, row)
					}
				}
				rows = filtered
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": oid, "truncated": false, "tree": rows})
		case strings.HasPrefix(tail, "blobs/"):
			oid := strings.TrimPrefix(tail, "blobs/")
			b, ok := g.blobs[oid]
			if !ok {
				http.NotFound(w, r)
				return
			}
			if g.tamperBlob {
				b = append(append([]byte(nil), b...), byte('!'))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": oid, "encoding": "base64", "size": len(b), "content": base64.StdEncoding.EncodeToString(b)})
		default:
			http.NotFound(w, r)
		}
		return
	}
	prefix := "/api/projects/owner/repository/repository/"
	// URL.Path is decoded by net/http, including GitLab's encoded project slash.
	if !strings.HasPrefix(route, prefix) {
		http.NotFound(w, r)
		return
	}
	tail := strings.TrimPrefix(route, prefix)
	switch {
	case tail == "commits/"+g.commit:
		_ = json.NewEncoder(w).Encode(map[string]any{"id": g.commit})
	case tail == "tree":
		if r.URL.Query().Get("ref") != g.commit || r.URL.Query().Get("recursive") != "false" || r.URL.Query().Get("per_page") != "100" {
			t.Error("GitLab request lost full commit/nonrecursive bound")
		}
		oid, ok := g.paths[r.URL.Query().Get("path")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		rows := []map[string]any{}
		if r.URL.Query().Get("page") != "1" {
			t.Error("small fixture unexpectedly paginated")
		}
		for _, e := range g.trees[oid] {
			rows = append(rows, map[string]any{"id": e.oid, "name": e.name, "type": e.kind, "path": path.Join(r.URL.Query().Get("path"), e.name), "mode": e.mode})
		}
		if g.truncateTree && oid == g.root {
			filtered := rows[:0]
			for _, row := range rows {
				if row["name"] != "foo.bar" {
					filtered = append(filtered, row)
				}
			}
			rows = filtered
		}
		_ = json.NewEncoder(w).Encode(rows)
	case strings.HasPrefix(tail, "blobs/") && strings.HasSuffix(tail, "/raw"):
		oid := strings.TrimSuffix(strings.TrimPrefix(tail, "blobs/"), "/raw")
		b, ok := g.blobs[oid]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if g.tamperBlob {
			b = append(append([]byte(nil), b...), byte('!'))
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(b)
	default:
		http.NotFound(w, r)
	}
}
func (g *qaNativeGitObjects) count() int { g.mu.Lock(); defer g.mu.Unlock(); return g.requests }

func qaNativeGitFiles(t *testing.T, archive []byte, admit map[string]any, attest []map[string]any, extra map[string][]byte) map[string][]byte {
	t.Helper()
	name, ok := admit["name"].(string)
	if !ok {
		t.Fatal("signed admit name missing")
	}
	version, ok := admit["version"].(string)
	if !ok {
		t.Fatal("signed admit version missing")
	}
	files := map[string][]byte{path.Join("skills", name, version, "bundle.skb"): archive, "foo.bar": []byte("first sibling\n"), "foo/inert": []byte("directory sorting oracle\n"), "foo0": []byte{0xff, 0, 0xfe}}
	for i, event := range append([]map[string]any{admit}, attest...) {
		b, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		files[fmt.Sprintf("events/misleading-label/%04d.json", i)] = b
	}
	for p, b := range extra {
		files[p] = b
	}
	return files
}

func TestNativeGitPolicySessionIntegration(t *testing.T) {
	for _, provider := range []string{"github", "gitlab"} {
		for _, kind := range []string{"agent", "skill"} {
			for _, mode := range []string{"signed-positive", "wrong-root-pin", "raw-blob-substitution", "omitted-tree-entry", "hidden-revoke", "malformed-event"} {
				t.Run(provider+"/"+kind+"/"+mode, func(t *testing.T) {
					var base *qaEvidenceFixture
					var archive []byte
					var admit map[string]any
					var attest []map[string]any
					var agent *c33LiveFixture
					var skill *qaNativeSkillLiveFixture
					if kind == "agent" {
						agent = c33LiveNew(t, nil)
						base, archive, admit, attest = agent.base, agent.archive, agent.admit, agent.attest
					} else {
						skill = qaNativeSkillLiveNew(t, nil)
						base, archive, admit, attest = skill.base, skill.archive, skill.admit, skill.attest
					}
					extra := map[string][]byte{}
					if mode == "hidden-revoke" {
						event, e := registry.BuildBundleRevokedEvent(registry.RevokedEventInput{BundleDigest: admit["bundle_digest"].(string), RevokedBy: "source-revoker", ReasonCode: "red", Rationale: "selected adverse event hidden under unrelated digest directory", OccurredAt: time.Now().UTC().Add(-time.Minute)})
						if e != nil {
							t.Fatal(e)
						}
						if _, e = registry.SignEnvelopeSignature(base.artifact, event); e != nil {
							t.Fatal(e)
						}
						raw, e := json.Marshal(event)
						if e != nil {
							t.Fatal(e)
						}
						extra["events/another-digest/deeper/0009-revoked.json"] = raw
					}
					if mode == "malformed-event" {
						extra["events/unrelated/ignored.json"] = []byte("{malformed")
					}
					graph := qaNativeGitGraph(t, qaNativeGitFiles(t, archive, admit, attest, extra))
					server, ca := qaEvidenceTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { graph.serve(t, provider, w, r) }))
					caPath := filepath.Join(base.project, "git-ca.pem")
					if e := os.WriteFile(caPath, ca, 0600); e != nil {
						t.Fatal(e)
					}
					sum := sha256.Sum256(ca)
					pin := graph.root
					if mode == "wrong-root-pin" {
						pin = strings.Repeat("0", 40)
					}
					base.doc["schema"] = "m3c.enterprise-project-profile/v5"
					base.doc["native"].(map[string]any)["carrier"] = map[string]any{"kind": "git", "provider": provider, "api_base": server.URL + "/api", "repository": "owner/repository", "object_format": "sha1", "commit_oid": graph.commit, "root_tree_oid": pin, "auth": map[string]any{"mode": "none"}, "tls": map[string]any{"mode": "pinned-pem", "ca": map[string]string{"path": caPath, "sha256": hex.EncodeToString(sum[:])}}}
					p := base.load(t)
					if kind == "agent" {
						agent.enroll(t, p)
					} else {
						skill.enroll(t, p)
					}
					before := qaEvidenceInventory(t, base.home, true)
					digest := admit["bundle_digest"].(string)
					graph.tamperBlob = mode == "raw-blob-substitution"
					graph.truncateTree = mode == "omitted-tree-entry"
					if kind == "agent" {
						s, e := p.BeginGitAgentInstall(context.Background(), digest)
						if s != nil {
							t.Cleanup(func() {
								if closeErr := s.Close(); closeErr != nil {
									t.Error("Git session checked cleanup", closeErr)
								}
							})
						}

						if mode != "signed-positive" {
							if !errors.Is(e, registry.ErrNativeEvidenceInvalid) || s != nil {
								t.Fatalf("selected Git failure must deny12 during acquisition with nil session: %v", e)
							}
							if !reflect.DeepEqual(before, qaEvidenceInventory(t, base.home, true)) {
								t.Fatal("denied Git acquisition changed artifact inventory")
							}
							return
						}
						if e != nil {
							t.Fatal("fresh signed Git Begin", e)
						}
						plan, e := s.Plan(context.Background())

						if e != nil || plan == nil || len(plan.Rows) != 1 || len(plan.Token) != 43 {
							t.Fatal("signed Git agent plan", e)
						}
						if !reflect.DeepEqual(before, qaEvidenceInventory(t, base.home, true)) {
							t.Fatal("Plan published before consent")
						}
						if _, e = s.Confirm(context.Background(), plan.Token); e != nil {
							t.Fatal("signed Git confirm", e)
						}
						if e = s.Close(); e != nil {
							t.Fatal(e)
						}
						c33LiveFrame(t, agent)
					} else {
						s, e := p.BeginGitSkillInstall(context.Background(), digest)
						if s != nil {
							t.Cleanup(func() {
								if closeErr := s.Close(); closeErr != nil {
									t.Error("Git session checked cleanup", closeErr)
								}
							})
						}

						if mode != "signed-positive" {
							if !errors.Is(e, registry.ErrNativeEvidenceInvalid) || s != nil {
								t.Fatalf("selected Git failure must deny12 during acquisition with nil session: %v", e)
							}
							if !reflect.DeepEqual(before, qaEvidenceInventory(t, base.home, true)) {
								t.Fatal("denied Git acquisition changed artifact inventory")
							}
							return
						}
						if e != nil {
							t.Fatal("fresh signed Git Begin", e)
						}
						plan, e := s.Plan(context.Background())

						if e != nil || plan == nil || len(plan.Rows) != 1 || len(plan.Token) != 43 {
							t.Fatal("signed Git skill plan", e)
						}
						if _, e = s.Confirm(context.Background(), plan.Token); e != nil {
							t.Fatal("signed Git confirm", e)
						}
						if e = s.Close(); e != nil {
							t.Fatal(e)
						}
						qaNativeSkillLiveProof(t, skill, filepath.Join(base.home, ".claude", "skills", "live-skill"))
					}
					if graph.count() == 0 {
						t.Fatal("Git positive made no actual TLS requests")
					}
				})
			}
		}
	}
}
