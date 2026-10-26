package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pjbgf/sha1cd"
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
			if g.truncateTree && oid == g.root && len(rows) > 0 {
				rows = rows[1:]
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
		if g.truncateTree && oid == g.root && len(rows) > 0 {
			rows = rows[1:]
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

type qaNativeGitCLI struct {
	source       *qaNativeSourceCLI
	digest, kind string
	graph        *qaNativeGitObjects
	agent        *c33CLILive
	skill        *qaNativeSkillCLILive
}

func qaNativeGitCLINew(t *testing.T, provider, kind string) *qaNativeGitCLI {
	t.Helper()
	f := &qaNativeGitCLI{kind: kind}
	var archive []byte
	var admit map[string]any
	var attest []map[string]any
	if kind == "agent" {
		f.agent = c33CLINew(t)
		f.source = f.agent.source
		f.digest = f.agent.digest
		archive, admit, attest = f.agent.archive, f.agent.admit, f.agent.attest
	} else {
		f.skill = qaNativeSkillCLINew(t)
		f.source = f.skill.source
		f.digest = f.skill.digest
		archive, admit, attest = f.skill.archive, f.skill.admit, f.skill.attest
	}
	f.graph = qaNativeGitGraph(t, qaNativeGitFiles(t, archive, admit, attest, nil))
	server, ca := qaNativeSourceCLITLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.graph.serve(t, provider, w, r) }))
	caPath := filepath.Join(f.source.base.project, "git-api-ca.pem")
	if e := os.WriteFile(caPath, ca, 0600); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(ca)
	f.source.doc["schema"] = "m3c.enterprise-project-profile/v5"
	f.source.doc["native"].(map[string]any)["carrier"] = map[string]any{"kind": "git", "provider": provider, "api_base": server.URL + "/api", "repository": "owner/repository", "object_format": "sha1", "commit_oid": f.graph.commit, "root_tree_oid": f.graph.root, "auth": map[string]any{"mode": "none"}, "tls": map[string]any{"mode": "pinned-pem", "ca": map[string]any{"path": caPath, "sha256": hex.EncodeToString(sum[:])}}}
	f.source.save(t)
	return f
}
func (f *qaNativeGitCLI) args() []string {
	return []string{"pull", "--enterprise-profile", f.source.base.path, "--enterprise-profile-sha256", f.source.base.pin, "--home", f.source.base.home, "--kind", f.kind, "--digest", f.digest, "--install", "--trust-mode", "--native-session"}
}
func (f *qaNativeGitCLI) enroll(t *testing.T, binary, flags string) {
	t.Helper()
	p, _ := c33EnrollEvidence(t, f.source)
	if code, out := qaNativeSourceRun(t, binary, flags, f.source, c33EnrollArgs(f.source, p)); code != 0 {
		t.Fatalf("Git enrollment prerequisite %d %s", code, out)
	}
}
func (f *qaNativeGitCLI) proof(t *testing.T) {
	t.Helper()
	if f.kind == "agent" {
		c33CLIFrame(t, f.agent)
	} else {
		qaNativeSkillCLIFrame(t, f.skill)
	}
}

// The SKILL plan reserves its private pending transaction before consent. Only
// journal and that exact private staging prefix are excluded; active artifacts
// and every other newly created path remain part of the no-publication oracle.
func (f *qaNativeGitCLI) inventory(t *testing.T) map[string]string {
	t.Helper()
	if f.kind == "skill" {
		return qaNativeSkillCLIInventory(t, f.source.base.home)
	}
	return qaNativeSourceArtifactInventory(t, f.source.base.home)
}

func TestNativeGitInstallActualCLI(t *testing.T) {
	binary, flags, _ := qaNativeSourceBinary(t)
	for _, provider := range []string{"github", "gitlab"} {
		for _, kind := range []string{"agent", "skill"} {
			for _, mode := range []string{"confirm", "crlf", "wrong-token", "close"} {
				t.Run(provider+"/"+kind+"/"+mode, func(t *testing.T) {
					f := qaNativeGitCLINew(t, provider, kind)
					f.enroll(t, binary, flags)
					before := f.inventory(t)
					ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, binary, f.args()...)
					cmd.WaitDelay = time.Second
					cmd.Dir = f.source.base.project
					cmd.Env = qaNativeSourceEnv(nativeCLIQAEnv(f.source.base.home), "GOFLAGS", flags)
					in, e := cmd.StdinPipe()
					if e != nil {
						t.Fatal(e)
					}
					defer in.Close()
					out, e := cmd.StdoutPipe()
					if e != nil {
						t.Fatal(e)
					}
					var diag bytes.Buffer
					cmd.Stderr = &diag
					if e = cmd.Start(); e != nil {
						t.Fatal(e)
					}
					defer func() {
						if cmd.ProcessState == nil {
							_ = cmd.Process.Kill()
							_ = cmd.Wait()
						}
					}()
					scanner := bufio.NewScanner(out)
					scanner.Buffer(make([]byte, 4096), 1<<20)
					if !scanner.Scan() {
						t.Fatal("Git CLI did not produce checked plan", diag.String())
					}
					var plan struct {
						Type  string                                  `json:"type"`
						Rows  []struct{ Kind, Digest, Target string } `json:"rows"`
						Token string                                  `json:"token"`
					}
					if e = json.Unmarshal(scanner.Bytes(), &plan); e != nil {
						t.Fatal(e)
					}
					if plan.Type != "native-"+kind+"-plan" || len(plan.Rows) != 1 || plan.Rows[0].Kind != kind || plan.Rows[0].Digest != f.digest || len(plan.Token) != 43 {
						t.Fatal("Git CLI lost exact typed plan")
					}
					if !reflect.DeepEqual(before, f.inventory(t)) {
						t.Fatal("Git plan published before consent")
					}
					busy, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
					_, e = f.source.journal(t).Status(busy)
					stop()
					if !errors.Is(e, context.DeadlineExceeded) {
						t.Fatal("Git CLI did not hold actual journal", e)
					}
					token := plan.Token
					if mode == "wrong-token" {
						token = strings.Repeat("A", 43)
						if token == plan.Token {
							token = strings.Repeat("B", 42) + "A"
						}
					}
					if mode != "close" {
						ending := "\n"
						if mode == "crlf" {
							ending = "\r\n"
						}
						if _, e = in.Write([]byte(token + ending)); e != nil {
							t.Fatal(e)
						}
					}
					_ = in.Close()
					installed := false
					for scanner.Scan() {
						var row map[string]any
						if e = json.Unmarshal(scanner.Bytes(), &row); e != nil {
							t.Fatal(e)
						}
						if row["type"] == "native-"+kind+"-installed" {
							installed = true
						}
					}
					if e = scanner.Err(); e != nil {
						t.Fatal(e)
					}
					e = cmd.Wait()
					if mode == "confirm" || mode == "crlf" {
						if e != nil || !installed {
							t.Fatal("actual signed Git publication failed", e, diag.String())
						}
						f.proof(t)
					} else {
						var exit *exec.ExitError
						if !errors.As(e, &exit) || exit.ExitCode() != 12 || installed {
							t.Fatal("canonical rejected Git consent wrong exit", e, diag.String())
						}
						if !reflect.DeepEqual(before, f.inventory(t)) {
							t.Fatal("unconfirmed Git CLI published")
						}
					}
					released, stop := context.WithTimeout(context.Background(), 5*time.Second)
					defer stop()
					if _, e = f.source.journal(t).Status(released); e != nil {
						t.Fatal("Git CLI leaked lease", e)
					}
					f.graph.mu.Lock()
					requests := f.graph.requests
					f.graph.mu.Unlock()
					if requests == 0 || f.source.requests.Load() != 0 || f.source.base.requests.Load() != 0 {
						t.Fatal("Git CLI used unselected source or no Git source")
					}
				})
			}
		}
	}
}
