package registry

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/pjbgf/sha1cd"
)

type securityGitEntry struct{ name, mode, kind, oid string }
type securityGitFixture struct {
	base     *nativeSessionQAFixture
	source   *NativeGitSource
	blobs    map[string][]byte
	trees    map[string][]securityGitEntry
	paths    map[string]string
	commit   string
	calls    atomic.Int32
	alter    func(string, any) any
	response func(http.ResponseWriter, *http.Request) bool
}

func securityGitOID(kind string, raw []byte) string {
	framed := append([]byte(fmt.Sprintf("%s %d\x00", kind, len(raw))), raw...)
	sum, collision := sha1cd.Sum(framed)
	if collision {
		panic("unexpected fixture collision")
	}
	return hex.EncodeToString(sum[:])
}
func (f *securityGitFixture) tree(path string, entries []securityGitEntry) string {
	// Independent fixture encoder: sort a copied API projection, manually build
	// canonical raw tree bytes, not the consumer codec or its verification helper.
	sorted := append([]securityGitEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i].name, sorted[j].name
		if sorted[i].kind == "tree" {
			a += "/"
		}
		if sorted[j].kind == "tree" {
			b += "/"
		}
		return a < b
	})
	var body bytes.Buffer
	for _, e := range sorted {
		mode := e.mode
		if mode == "040000" {
			mode = "40000"
		}
		body.WriteString(mode)
		body.WriteByte(' ')
		body.WriteString(e.name)
		body.WriteByte(0)
		raw, _ := hex.DecodeString(e.oid)
		body.Write(raw)
	}
	oid := securityGitOID("tree", body.Bytes())
	f.trees[oid] = entries
	f.paths[path] = oid
	return oid
}
func (f *securityGitFixture) blob(raw []byte) string {
	oid := securityGitOID("blob", raw)
	f.blobs[oid] = raw
	return oid
}
func securityGitNew(t *testing.T, provider string, extra []map[string]any) *securityGitFixture {
	t.Helper()
	return securityGitNewKind(t, provider, extra, skillbundle.KindAgent)
}
func securityGitNewKind(t *testing.T, provider string, extra []map[string]any, kind string) *securityGitFixture {
	t.Helper()
	base := nativeSessionQANew(t, nil)
	if kind == skillbundle.KindSkill {
		a := base.agent
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: native-session-agent\n---\n\nInert signed SKILL.\n"), 0600); err != nil {
			t.Fatal(err)
		}
		var raw bytes.Buffer
		if _, err := skillbundle.PackToWriter(dir, &raw, skillbundle.PackOptions{Manifest: skillbundle.BundleManifest{Name: a.name, Version: "1.0.0", DependsOn: []skillbundle.Dependency{}}}); err != nil {
			t.Fatal(err)
		}
		a.blob = raw.Bytes()
		item, digest := mintAdmitItem(t, a.registryKey, a.name, "1.0.0", string(a.blob))
		event, err := extractEvent(itemBody(item))
		if err != nil {
			t.Fatal(err)
		}
		a.staged.Kind = kind
		a.staged.Digest = digest
		a.staged.Attestation = &AttestationContext{AdmitEvent: event}
		for i, key := range a.signerKeys {
			a.staged.Attestation.GovernanceAttestations = append(a.staged.Attestation.GovernanceAttestations, signedAttest(t, key, a.roots.Signers[i].ReviewerID, digest, "green", a.now.Add(-time.Minute).Format(time.RFC3339), nil))
		}
		a.staged.Attestation.GovernanceAttestation = a.staged.Attestation.GovernanceAttestations[0]
	}
	f := &securityGitFixture{base: base, blobs: map[string][]byte{}, trees: map[string][]securityGitEntry{}, paths: map[string]string{}, commit: strings.Repeat("c", 40)}
	events := append([]map[string]any{base.agent.staged.Attestation.AdmitEvent}, base.agent.staged.Attestation.GovernanceAttestations...)
	events = append(events, extra...)
	var eventEntries []securityGitEntry
	for i, event := range events {
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		eventEntries = append(eventEntries, securityGitEntry{fmt.Sprintf("%03d.json", i), "100644", "blob", f.blob(raw)})
	}
	eventsOID := f.tree("events", eventEntries)
	leaf := f.tree("skills/"+base.agent.name+"/1.0.0", []securityGitEntry{{"bundle.skb", "100644", "blob", f.blob(base.agent.blob)}})
	version := f.tree("skills/"+base.agent.name, []securityGitEntry{{"1.0.0", "040000", "tree", leaf}})
	skills := f.tree("skills", []securityGitEntry{{base.agent.name, "040000", "tree", version}})
	root := f.tree("", []securityGitEntry{{"events", "040000", "tree", eventsOID}, {"skills", "040000", "tree", skills}})
	caRaw, ca, key := nativeSourceTestCA(t, 1031)
	server := nativeSourceTestServer(t, ca, key, http.HandlerFunc(f.serve), nil)
	source, err := NewNativeGitSource(NativeGitSourceOptions{Provider: provider, APIBase: server.URL, Repository: "owner/repo", CommitOID: f.commit, RootTreeOID: root, ObjectFormat: "sha1", AuthMode: "none", TLSMode: "pinned-pem", CAPEM: caRaw})
	if err != nil {
		t.Fatal(err)
	}
	f.source = source
	return f
}
func (f *securityGitFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	if f.response != nil && f.response(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	escaped := r.URL.EscapedPath()
	provider := f.source.provider
	prefix := "/repos/owner/repo"
	if provider == "gitlab" {
		prefix = "/projects/owner%2Frepo/repository"
	}
	if !strings.HasPrefix(escaped, prefix) || r.Method != http.MethodGet {
		w.WriteHeader(404)
		return
	}
	suffix := strings.TrimPrefix(escaped, prefix)
	var value any
	switch {
	case suffix == "/git/commits/"+f.commit:
		value = map[string]any{"sha": f.commit, "tree": map[string]any{"sha": f.source.tree}}
	case suffix == "/commits/"+f.commit:
		value = map[string]any{"id": f.commit}
	case strings.HasPrefix(suffix, "/git/trees/") || suffix == "/tree":
		oid := strings.TrimPrefix(suffix, "/git/trees/")
		path := ""
		if provider == "gitlab" {
			if r.URL.Query().Get("ref") != f.commit || r.URL.Query().Get("recursive") != "false" {
				w.WriteHeader(400)
				return
			}
			path = r.URL.Query().Get("path")
			oid = f.paths[path]
		} else if _, exists := r.URL.Query()["recursive"]; exists {
			w.WriteHeader(400)
			return
		}
		entries, exists := f.trees[oid]
		if !exists {
			w.WriteHeader(404)
			return
		}
		rows := []any{}
		for _, e := range entries {
			if provider == "github" {
				rows = append(rows, map[string]any{"path": e.name, "mode": e.mode, "type": e.kind, "sha": e.oid})
			} else {
				full := e.name
				if path != "" {
					full = path + "/" + e.name
				}
				rows = append(rows, map[string]any{"path": full, "name": e.name, "mode": e.mode, "type": e.kind, "id": e.oid})
			}
		}
		if provider == "github" {
			value = map[string]any{"sha": oid, "truncated": false, "tree": rows}
		} else {
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			start := (page - 1) * 100
			if start < 0 {
				w.WriteHeader(400)
				return
			}
			if start > len(rows) {
				start = len(rows)
			}
			end := start + 100
			if end > len(rows) {
				end = len(rows)
			}
			value = rows[start:end]
			w.Header().Set("X-Page", strconv.Itoa(page))
			if end < len(rows) {
				w.Header().Set("X-Next-Page", strconv.Itoa(page+1))
			}
		}
	case strings.HasPrefix(suffix, "/git/blobs/"):
		oid := strings.TrimPrefix(suffix, "/git/blobs/")
		raw, ok := f.blobs[oid]
		if !ok {
			w.WriteHeader(404)
			return
		}
		value = map[string]any{"sha": oid, "size": len(raw), "encoding": "base64", "content": base64.StdEncoding.EncodeToString(raw)}
	case strings.HasPrefix(suffix, "/blobs/") && strings.HasSuffix(suffix, "/raw"):
		oid := strings.TrimSuffix(strings.TrimPrefix(suffix, "/blobs/"), "/raw")
		raw, ok := f.blobs[oid]
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(raw)
		return
	default:
		w.WriteHeader(404)
		return
	}
	if f.alter != nil {
		value = f.alter(suffix, value)
	}
	_ = json.NewEncoder(w).Encode(value)
}
func (f *securityGitFixture) fetch(t *testing.T) (*nativeGitCandidate, error) {
	t.Helper()
	lease, err := f.base.journal.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	}()
	return f.source.fetchCandidate(context.Background(), f.base.journal, lease, f.base.agent.staged.Digest, f.base.agent.staged.Kind)
}
func TestNativeGitSourceSnapshot(t *testing.T) {
	for _, provider := range []string{"github", "gitlab"} {
		t.Run(provider, func(t *testing.T) {
			f := securityGitNew(t, provider, nil)
			c, err := f.fetch(t)
			if err != nil || c == nil {
				t.Fatalf("real signed TLS source: %v", err)
			}
			if !bytes.Equal(c.Archive, f.base.agent.blob) || len(c.Bundle.Attestation.GovernanceAttestations) != 2 || len(c.bindingID) != 64 || c.workBytes <= 0 {
				t.Fatal("lost exact archive/full quorum/proof work")
			}
			if verifyAgentContext(f.base.journal.selection.artifactRoots, c.Bundle.Attestation, c.Bundle.Digest, c.Bundle.Name, c.Bundle.Version, f.base.now) != nil {
				t.Fatal("real selected context invalid")
			}
			if f.calls.Load() < 7 {
				t.Fatal("did not perform actual API traversal")
			}
		})
	}
	for _, provider := range []string{"github", "gitlab"} {
		t.Run(provider+"-skill", func(t *testing.T) {
			f := securityGitNewKind(t, provider, nil, skillbundle.KindSkill)
			c, err := f.fetch(t)
			if err != nil || c == nil || c.Bundle.Kind != skillbundle.KindSkill || !bytes.Equal(c.Archive, f.base.agent.blob) || len(c.Bundle.Attestation.GovernanceAttestations) != 2 {
				t.Fatalf("genuine signed SKILL source: %v", err)
			}
		})
	}

	t.Run("independentCanonicalObjects", func(t *testing.T) {
		work := &nativeLiveWork{}
		if nativeGitVerifyObject("tree", nil, "4b825dc642cb6eb9a060e54bf8d69288fbee4904", work) != nil {
			t.Fatal("known empty Git tree")
		}
		if nativeGitVerifyObject("blob", []byte("test content\n"), "d670460b4b4aece5915caf5c68d12f560a9fe3e4", work) != nil {
			t.Fatal("known Git blob")
		}
		if nativeGitVerifyObject("blob", []byte("tampered"), "d670460b4b4aece5915caf5c68d12f560a9fe3e4", work) == nil {
			t.Fatal("API label granted wrong bytes")
		}
	})
	t.Run("knownCollisionFlagAndRefusal", func(t *testing.T) {
		// Unmodified first320 bytes of upstream sha1cdv0.7.0
		// test/testdata/files/shattered-1.pdf (upstream fuzz_seed_test vector).
		// This tests the dependency's flag, NOT a colliding Git-framed object.
		raw, e := hex.DecodeString("255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474682032203020522f4865696768742033203020522f547970652034203020522f537562747970652035203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e6774682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe017346dc9166b67e118f029ab621b2560ff9ca67cca8c7f85ba84c79030c2b3de218f86db3a90901d5df45c14f26fedfb3dc38e96ac22fe7bd728f0e45bce046d23c570feb141398bb552ef5a0a82be331fea48037b8b5d71f0e332edf93ac3500eb4ddc0decc1a864790c782c76215660dd309791d06bd0af3f98cda4bc4629b1")
		if e != nil {
			t.Fatal(e)
		}
		sum, collision := sha1cd.Sum(raw)
		if !collision {
			t.Fatal("known upstream collision flag lost")
		}
		if !errors.Is(nativeGitCompareHash(sum[:], collision, hex.EncodeToString(sum[:])), ErrNativeEvidenceInvalid) {
			t.Fatal("collision flag allowed matching digest")
		}
		if e = nativeGitCompareHash(sum[:], false, hex.EncodeToString(sum[:])); e != nil {
			t.Fatal("ordinary flagfalse hash comparison failed")
		}
	})
	t.Run("rawNameOrdering", func(t *testing.T) {
		f := &securityGitFixture{trees: map[string][]securityGitEntry{}, paths: map[string]string{}}
		entries := []securityGitEntry{{"foo", "040000", "tree", strings.Repeat("1", 40)}, {"foo.bar", "100644", "blob", strings.Repeat("2", 40)}, {"Foo", "100755", "blob", strings.Repeat("3", 40)}, {"é", "100644", "blob", strings.Repeat("4", 40)}}
		want := f.tree("", entries)
		consumer := []nativeGitEntry{}
		for _, e := range entries {
			consumer = append(consumer, nativeGitEntry{e.name, e.mode, e.kind, e.oid})
		}
		work := &nativeLiveWork{}
		raw, e := nativeGitTreeBytes(consumer, work)
		if e != nil || nativeGitVerifyObject("tree", raw, want, work) != nil {
			t.Fatal("Git directory sorting/case/raw UTF8 mismatch")
		}
	})
}
func TestNativeGitSourceTransport(t *testing.T) {
	if os.Getenv("M3C_NATIVE_GIT_PROXY_CHILD") == "1" {
		securityGitProxyChild(t)
		return
	}
	t.Run("freshChildNoAmbientProxy", func(t *testing.T) {
		exe, e := os.Executable()
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		child := exec.CommandContext(ctx, exe, "-test.run=^TestNativeGitSourceTransport$")
		child.WaitDelay = time.Second
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "M3C_NATIVE_GIT_PROXY_CHILD=") {
				child.Env = append(child.Env, entry)
			}
		}
		child.Env = append(child.Env, "M3C_NATIVE_GIT_PROXY_CHILD=1")
		if out, e := child.CombinedOutput(); e != nil || ctx.Err() != nil {
			t.Fatalf("proxy child failed: %v %s", e, out)
		}
	})
	t.Run("physicalResponseCapAndHeaders", func(t *testing.T) {
		f := securityGitNew(t, "github", nil)
		f.response = func(w http.ResponseWriter, _ *http.Request) bool {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("[]"))
			return true
		}
		fetch := newNativeGitFetch(context.Background(), f.source, f.base.journal, "")
		defer fetch.transport.CloseIdleConnections()
		if raw, _, e := fetch.get(f.source.base+"/cap", 2, true); e != nil || string(raw) != "[]" {
			t.Fatal("exact physical response cap failed", e)
		}
		if raw, _, e := fetch.get(f.source.base+"/cap", 1, true); raw != nil || !errors.Is(e, ErrNativeEvidenceInvalid) {
			t.Fatal("cap+1 source response accepted")
		}
		f.response = func(w http.ResponseWriter, _ *http.Request) bool {
			w.Header().Add("Content-Type", "application/json")
			w.Header().Add("Content-Type", "application/json")
			_, _ = w.Write([]byte("[]"))
			return true
		}
		if raw, _, e := fetch.get(f.source.base+"/cap", 2, true); raw != nil || !errors.Is(e, ErrNativeEvidenceInvalid) {
			t.Fatal("duplicate media header accepted")
		}
	})

	t.Run("leaseBeforeSelectedCredential", func(t *testing.T) {
		f := securityGitNew(t, "github", nil)
		var env int
		f.source.authMode = "external-env"
		f.source.readEnv = func(string) (string, bool) { env++; return "synthetic-selected-token", true }
		lease, err := f.base.journal.acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err = lease.Close(); err != nil {
			t.Fatal(err)
		}
		c, err := f.source.fetchCandidate(context.Background(), f.base.journal, lease, f.base.agent.staged.Digest, skillbundle.KindAgent)
		if c != nil || !errors.Is(err, ErrNativeSessionUnavailable) || env != 0 || f.calls.Load() != 0 {
			t.Fatal("closed lease reached credential/network")
		}
	})
	for _, provider := range []string{"github", "gitlab"} {
		t.Run("selectedToken-"+provider, func(t *testing.T) {
			f := securityGitNew(t, provider, nil)
			f.source.authMode = "external-env"
			env := 0
			f.source.readEnv = func(name string) (string, bool) {
				env++
				expected := "M3C_GITHUB_RO_TOKEN"
				if provider == "gitlab" {
					expected = "M3C_GITLAB_RO_TOKEN"
				}
				if name != expected {
					t.Error("wrong credential family")
				}
				return "synthetic-selected-token", true
			}
			headers := 0
			f.response = func(_ http.ResponseWriter, r *http.Request) bool {
				if provider == "github" {
					if r.Header.Get("Authorization") != "Bearer synthetic-selected-token" || r.Header.Get("PRIVATE-TOKEN") != "" {
						t.Error("wrong auth header")
					}
				} else if r.Header.Get("PRIVATE-TOKEN") != "synthetic-selected-token" || r.Header.Get("Authorization") != "" {
					t.Error("wrong auth header")
				}
				headers++
				return false
			}
			if c, e := f.fetch(t); e != nil || c == nil || env != 1 || headers < 7 {
				t.Fatal("selected token acquisition failed", e)
			}
		})
	}
	t.Run("missingTokenNoFallback", func(t *testing.T) {
		f := securityGitNew(t, "github", nil)
		f.source.authMode = "external-env"
		f.source.readEnv = func(string) (string, bool) { return "", false }
		c, e := f.fetch(t)
		if c != nil || !errors.Is(e, ErrNativeGitSourceIO) || f.calls.Load() != 0 {
			t.Fatal("missing token fell back")
		}
	})
	t.Run("redirectNoFollow", func(t *testing.T) {
		f := securityGitNew(t, "github", nil)
		f.response = func(w http.ResponseWriter, _ *http.Request) bool {
			w.Header().Set("Location", "https://unselected.invalid/")
			w.WriteHeader(302)
			return true
		}
		c, e := f.fetch(t)
		if c != nil || !errors.Is(e, ErrNativeGitSourceIO) || f.calls.Load() != 1 {
			t.Fatal("redirect followed or granted", e)
		}
	})
	t.Run("checkedCloseConstantDiagnostic", func(t *testing.T) {
		f := securityGitNew(t, "gitlab", nil)
		cause := errors.New("synthetic-sensitive-close-detail")
		f.source.closeBody = func(body io.ReadCloser) error { return errors.Join(body.Close(), cause) }
		c, e := f.fetch(t)
		if c != nil || !errors.Is(e, cause) || !errors.Is(e, ErrNativeGitSourceIO) || strings.Contains(e.Error(), cause.Error()) {
			t.Fatal("Close uncertainty lost or diagnostic leaked", e)
		}
	})
	t.Run("constructorBoundsAndRootAPI", func(t *testing.T) {
		f := securityGitNew(t, "github", nil)
		u, _ := url.Parse(f.source.base)
		if u.Path != "" {
			t.Fatal("fixture should exercise empty base path")
		}
		for _, o := range []NativeGitSourceOptions{{Provider: "github", APIBase: strings.Repeat("x", 8193)}, {Provider: "github", APIBase: f.source.base, Repository: "owner/repo", CommitOID: f.commit, RootTreeOID: f.source.tree, ObjectFormat: "sha1", TLSMode: "system", AuthMode: "external-env", AuthFamily: "github-read-token", AuthOrigin: "https://foreign.invalid"}} {
			if _, e := NewNativeGitSource(o); !errors.Is(e, ErrNativeEvidenceInvalid) {
				t.Fatal("invalid constructor granted")
			}
		}
	})
}
func TestNativeGitSourceCompletenessAndBounds(t *testing.T) {
	for _, provider := range []string{"github", "gitlab"} {
		t.Run("omittedEntry-"+provider, func(t *testing.T) {
			f := securityGitNew(t, provider, nil)
			f.alter = func(path string, value any) any {
				if strings.Contains(path, "trees/") {
					m := value.(map[string]any)
					rows := m["tree"].([]any)
					if len(rows) > 0 {
						m["tree"] = rows[1:]
					}
				} else if path == "/tree" {
					rows := value.([]any)
					if len(rows) > 0 {
						return rows[1:]
					}
				}
				return value
			}
			c, e := f.fetch(t)
			if c != nil || !errors.Is(e, ErrNativeEvidenceInvalid) {
				t.Fatal("omitted tree member accepted", e)
			}
		})
	}
	t.Run("unpairedSurrogateDuplicateAndAliases", func(t *testing.T) {
		for _, raw := range []string{`{"sha":"a","sha":"b"}`, `{"name":"\ud800"}`, `{"bundle_Digest":"x"}`} {
			if _, err := nativeGitJSON([]byte(raw), 1024, "", &nativeLiveWork{}); !errors.Is(err, ErrNativeEvidenceInvalid) {
				t.Fatal("strict decoder accepted ambiguous JSON")
			}
		}
		value, err := nativeGitJSON([]byte(`{"sha":"a"}`), 1024, "", &nativeLiveWork{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = nativeGitMap(value, []string{"sha"}); err != nil {
			t.Fatal("genuine API map rejected")
		}
		value, err = nativeGitJSON([]byte(`{"SHA":"a"}`), 1024, "", &nativeLiveWork{})
		if err != nil {
			t.Fatal("fixture should reach required API-key validation")
		}
		if _, err = nativeGitMap(value, []string{"sha"}); !errors.Is(err, ErrNativeEvidenceInvalid) {
			t.Fatal("API alias granted")
		}
	})
	t.Run("capsPreallocation", func(t *testing.T) {
		f := &nativeGitFetch{work: nativeLiveWork{bytes: nativeLiveWorkMax - 1}, seenObjects: map[string]bool{}}
		if !errors.Is(f.object(strings.Repeat("a", 40)), ErrNativeEvidenceInvalid) || len(f.seenObjects) != 0 {
			t.Fatal("object reserved after allocation")
		}
		f = &nativeGitFetch{work: nativeLiveWork{}, source: &NativeGitSource{provider: "github"}, treeEntries: 4096}
		if _, e := f.decodeEntries([]any{map[string]any{}}, ""); !errors.Is(e, ErrNativeEvidenceInvalid) {
			t.Fatal("tree cap not cumulative")
		}
		if nativeGitPage(http.Header{"X-Next-Page": []string{"4"}}, 1, 100) == nil {
			t.Fatal("unbounded pagination accepted")
		}
		f = &nativeGitFetch{pathBytes: 4 << 20}
		if f.reserveEntryPath("", "a") == nil {
			t.Fatal("path cap lost")
		}
	})
	t.Run("allReconstructedPathsBeforeAllocation", func(t *testing.T) {
		f := &nativeGitFetch{source: &NativeGitSource{provider: "github"}, pathBytes: 4<<20 - 4}
		entry := map[string]any{"path": "abc", "mode": "100644", "type": "blob", "sha": strings.Repeat("a", 40)}
		if _, err := f.decodeEntries([]any{entry}, ""); err != nil || f.pathBytes != 4<<20-1 {
			t.Fatal("exact path reservation", err)
		}
		before := f.work.bytes
		if _, err := f.decodeEntries([]any{entry}, "unrelated"); !errors.Is(err, ErrNativeEvidenceInvalid) || f.pathBytes != 4<<20-1 || f.work.bytes != before+256 {
			t.Fatal("ancestor/unrelated path not rejected before path allocation")
		}
		oid := strings.Repeat("b", 40)
		f = &nativeGitFetch{source: &NativeGitSource{provider: "github"}, trees: map[string][]nativeGitEntry{oid: {{name: "abc", mode: "100644", kind: "blob", oid: strings.Repeat("a", 40)}}}, verifiedPaths: map[string]string{}}
		if _, err := f.treeAt("one", oid); err != nil || f.pathBytes != 7 {
			t.Fatal("cached object new path uncharged", err)
		}
		if _, err := f.treeAt("one", oid); err != nil || f.pathBytes != 7 {
			t.Fatal("same verified path charged twice", err)
		}
		if _, err := f.treeAt("two", oid); err != nil || f.pathBytes != 14 {
			t.Fatal("same object second namespace path uncharged", err)
		}
	})

	t.Run("realGitLabFullPageThenTerminator", func(t *testing.T) {
		f := securityGitNew(t, "gitlab", nil)
		entries := make([]securityGitEntry, 100)
		oid := f.blob([]byte("inert unrelated entry"))
		for i := range entries {
			entries[i] = securityGitEntry{fmt.Sprintf("entry-%03d", i), "100644", "blob", oid}
		}
		tree := f.tree("paged", entries)
		fetch := newNativeGitFetch(context.Background(), f.source, f.base.journal, "")
		defer fetch.transport.CloseIdleConnections()
		before := f.calls.Load()
		got, err := fetch.treeAt("paged", tree)
		if err != nil || len(got) != 100 || f.calls.Load()-before != 2 {
			t.Fatalf("complete exact-page traversal: %v", err)
		}
	})
	for _, provider := range []string{"github", "gitlab"} {
		t.Run(provider+"-malformedOtherEventCannotSkip", func(t *testing.T) {
			f := securityGitNew(t, provider, []map[string]any{{"schema_version": "1.0.0", "digest": strings.Repeat("e", 64), "unknown_event": "inert"}})
			c, err := f.fetch(t)
			if c != nil || !errors.Is(err, ErrNativeEvidenceInvalid) {
				t.Fatal("complete namespace skipped malformed unrelated event", err)
			}
		})
	}

	t.Run("auditNonAuthorityAndProofBinding", func(t *testing.T) {
		f := securityGitNew(t, "github", nil)
		audit, e := BuildBundleInstalledEvent(InstalledEventInput{BundleDigest: f.base.agent.staged.Digest, Name: f.base.agent.name, Version: "1.0.0", InstalledOnHost: "synthetic", InstalledAt: f.base.now, Registry: "self"})
		if e != nil {
			t.Fatal(e)
		}
		audit["envelope_signature"] = base64.StdEncoding.EncodeToString(make([]byte, 64))
		kind, e := nativeGitEventShape(audit)
		if e != nil || kind != "audit" {
			t.Fatal("syntactic local audit subset rejected")
		}
		fetch := newNativeGitFetch(context.Background(), f.source, f.base.journal, "")
		defer fetch.transport.CloseIdleConnections()
		raw, _ := json.Marshal(audit)
		fetch.records = []nativeGitRecord{{path: "events/a.json", mode: "100644", oid: securityGitOID("blob", raw), raw: raw, event: audit, kind: kind}}
		if _, e = fetch.selectBundle(f.base.agent.staged.Digest, skillbundle.KindAgent); !errors.Is(e, ErrNativeEvidenceInvalid) {
			t.Fatal("audit-only granted")
		}
		first, e := fetch.proofDigest()
		if e != nil {
			t.Fatal(e)
		}
		fetch.records[0].raw = append([]byte(" "), raw...)
		second, e := fetch.proofDigest()
		if e != nil || first == second {
			t.Fatal("raw audit bytes omitted from proof")
		}
		audit["revoked_by"] = "foreign"
		if _, e = nativeGitEventShape(audit); !errors.Is(e, ErrNativeEvidenceInvalid) {
			t.Fatal("mixed audit/revoke accepted")
		}
	})
	t.Run("selectedRevokeAlways12", func(t *testing.T) {
		f := securityGitNew(t, "github", nil)
		rev, e := BuildBundleRevokedEvent(RevokedEventInput{BundleDigest: f.base.agent.staged.Digest, ReasonCode: "synthetic", RevokedBy: "untrusted-local", OccurredAt: f.base.now})
		if e != nil {
			t.Fatal(e)
		}
		rev["envelope_signature"] = base64.StdEncoding.EncodeToString(make([]byte, 64))
		fetch := newNativeGitFetch(context.Background(), f.source, f.base.journal, "")
		defer fetch.transport.CloseIdleConnections()
		fetch.records = []nativeGitRecord{{event: rev, kind: "revoke"}}
		if _, e = fetch.selectBundle(f.base.agent.staged.Digest, skillbundle.KindAgent); !errors.Is(e, ErrNativeEvidenceInvalid) || errors.Is(e, ErrNativeSubjectRevoked) {
			t.Fatal("raw revoke granted role or wrong exit", e)
		}
	})
	t.Run("precryptoWorkReservation", func(t *testing.T) {
		f := securityGitNew(t, "github", nil)
		makeFetch := func(att *AttestationContext) *nativeGitFetch {
			fetch := newNativeGitFetch(context.Background(), f.source, f.base.journal, "")
			t.Cleanup(fetch.transport.CloseIdleConnections)
			for _, event := range append([]map[string]any{att.AdmitEvent}, att.GovernanceAttestations...) {
				kind, e := nativeGitEventShape(event)
				if e != nil {
					t.Fatal(e)
				}
				fetch.records = append(fetch.records, nativeGitRecord{kind: kind, event: event})
			}
			return fetch
		}
		genuine := f.base.agent.staged.Attestation
		positive := makeFetch(genuine)
		if b, e := positive.selectBundle(f.base.agent.staged.Digest, skillbundle.KindAgent); e != nil || b == nil || positive.work.verificationCalls != 1 {
			t.Fatal("genuine source context failed", e)
		}
		invalid, _, e := snapshotAgentContext(genuine)
		if e != nil {
			t.Fatal(e)
		}
		invalid.AdmitEvent["envelope_signature"] = base64.StdEncoding.EncodeToString(make([]byte, 64))
		_, raw, e := snapshotAgentContext(invalid)
		if e != nil {
			t.Fatal(e)
		}
		reserve := 4 * int64(len(raw)) * int64(len(f.base.journal.selection.artifactRoots.Signers)+1)
		low := makeFetch(invalid)
		low.work.bytes = nativeLiveWorkMax - 8*maxAgentContext - reserve + 1
		if _, e = low.selectBundle(f.base.agent.staged.Digest, skillbundle.KindAgent); !errors.Is(e, ErrNativeEvidenceInvalid) || low.work.verificationCalls != 0 {
			t.Fatalf("signer budget denial must precede crypto: calls=%d err=%v", low.work.verificationCalls, e)
		}
		exact := makeFetch(invalid)
		exact.work.bytes = nativeLiveWorkMax - 8*maxAgentContext - reserve
		if _, e = exact.selectBundle(f.base.agent.staged.Digest, skillbundle.KindAgent); !errors.Is(e, ErrNativeEvidenceInvalid) || exact.work.verificationCalls != 1 || exact.work.bytes != nativeLiveWorkMax {
			t.Fatal("exact budget must reach signature denial")
		}
	})
	t.Run("contextCancellationBeforeIO", func(t *testing.T) {
		f := securityGitNew(t, "github", nil)
		lease, e := f.base.journal.acquire(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		defer func() {
			if e := lease.Close(); e != nil {
				t.Error(e)
			}
		}()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if c, e := f.source.fetchCandidate(ctx, f.base.journal, lease, f.base.agent.staged.Digest, skillbundle.KindAgent); c != nil || !errors.Is(e, context.Canceled) || f.calls.Load() != 0 {
			t.Fatal("canceled source reached IO")
		}
	})
}

func securityGitProxyChild(t *testing.T) {
	var calls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(502) }))
	defer proxy.Close()
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(key, proxy.URL)
	}
	for _, key := range []string{"NO_PROXY", "no_proxy"} {
		t.Setenv(key, "")
	}
	f := securityGitNew(t, "github", nil)
	original, _ := url.Parse(f.source.base)
	selected := net.JoinHostPort("evidence.synthetic.invalid", original.Port())
	f.source.base = "https://" + selected
	f.source.readEnv = func(string) (string, bool) { t.Error("authnone read credential"); return "", false }
	dial := &net.Dialer{Timeout: time.Second}
	f.source.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != selected {
			return nil, errors.New("unselected synthetic dial")
		}
		return dial.DialContext(ctx, network, original.Host)
	}
	c, e := f.fetch(t)
	if e != nil || c == nil || calls.Load() != 0 || f.calls.Load() < 7 {
		t.Fatalf("no-proxy actual nonloopback TLS failed: %v proxy=%d source=%d", e, calls.Load(), f.calls.Load())
	}
}
