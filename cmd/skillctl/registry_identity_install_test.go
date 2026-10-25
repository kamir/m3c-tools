package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/install"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
	"gopkg.in/yaml.v3"
)

func TestInstallRegistryIdentityActualCLI(t *testing.T) {
	binary := skillctlBin(t)
	for _, mode := range []string{"valid", "foreign-dependency-id", "foreign-root-id", "redirect", "root-final-key", "root-final-revoked", "unbound-env"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("M3C_REGISTRY_RO_TOKEN", "")
			t.Setenv("M3C_REGISTRY_TOKEN", "")
			t.Setenv("M3C_REGISTRY_TOKEN_ORIGIN", "")
			proof := installedCLIProofFixture(t)
			leaf, leafMeta := installedCLIBundle(t, proof, "required", "")
			root, meta := installedCLIBundle(t, proof, "fetch-contract", `,"depends_on":[{"kind":"skill","name":"required"}]`)
			var foreign, requests, wrongAuth atomic.Int32
			decoy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { foreign.Add(1) }))
			defer decoy.Close()
			var mu sync.Mutex
			calls := map[string]int{}
			rawRoot, e := os.ReadFile(root.skbPath)
			if e != nil {
				t.Fatal(e)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if mode == "valid" && r.Header.Get("Authorization") != "Bearer synthetic-registry-token" {
					wrongAuth.Add(1)
				}
				if strings.Contains(r.URL.Path, "/identities/") {
					id := strings.TrimPrefix(r.URL.Path, "/api/skills/identities/")
					mu.Lock()
					calls[id]++
					nth := calls[id]
					mu.Unlock()
					if mode == "redirect" {
						w.Header().Set("Location", decoy.URL+"/identity")
						w.WriteHeader(302)
						return
					}
					out := map[string]any{"id": id, "pubkey_b64": root.authorPubB64, "auth_source": "manual"}
					if mode == "foreign-dependency-id" && id == "id:dependency@m3c" || mode == "foreign-root-id" && id == root.authorID {
						out["id"] = "id:foreign@m3c"
					}
					if id == root.authorID && nth >= 2 {
						if mode == "root-final-key" {
							out["pubkey_b64"] = base64.StdEncoding.EncodeToString(make([]byte, 32))
						}
						if mode == "root-final-revoked" {
							out["revoked_at"] = "2026-01-01T00:00:00Z"
						}
					}
					_ = json.NewEncoder(w).Encode(out)
					return
				}
				if strings.Contains(r.URL.Path, "/by-name/") {
					_ = json.NewEncoder(w).Encode(map[string]any{"versions": []registry.BundleVersion{{Version: "1.0.0", Digest: root.digest, Status: "admitted"}}})
					return
				}
				if strings.Contains(r.URL.Path, "/bundles/") {
					if r.URL.Query().Get("meta") == "1" {
						_ = json.NewEncoder(w).Encode(meta)
					} else {
						_, _ = w.Write(rawRoot)
					}
					return
				}
				http.NotFound(w, r)
			}))
			defer srv.Close()
			root.regURL = srv.URL + "/api/skills"
			if mode == "valid" {
				t.Setenv("M3C_REGISTRY_TOKEN", "synthetic-registry-token")
				t.Setenv("M3C_REGISTRY_TOKEN_ORIGIN", srv.URL)
			}
			if mode == "unbound-env" {
				t.Setenv("M3C_REGISTRY_TOKEN", "synthetic-selected-invalid")
				t.Setenv("M3C_REGISTRY_TOKEN_ORIGIN", decoy.URL)
			}
			root.home = t.TempDir()
			roots, e := verify.Load(root.trPath)
			if e != nil {
				t.Fatal(e)
			}
			roots.Roots[0].RegistryURL = root.regURL
			roots.Roots[0].IdentityKeysAuthorized = "from-registry"
			roots.Roots[0].Authors = nil
			body, e := yaml.Marshal(roots)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(root.trPath, body, 0600); e != nil {
				t.Fatal(e)
			}
			dir := filepath.Join(root.home, ".claude", "skills", "required")
			if e = os.MkdirAll(dir, 0700); e != nil {
				t.Fatal(e)
			}
			leafRaw, e := os.ReadFile(leaf.skbPath)
			if e != nil {
				t.Fatal(e)
			}
			entries, e := skillbundle.Unpack(leafRaw, skillbundle.UnpackOptions{StripWrapper: true})
			if e != nil {
				t.Fatal(e)
			}
			for _, entry := range entries {
				if entry.Rel == "." {
					continue
				}
				path := filepath.Join(dir, filepath.FromSlash(entry.Rel))
				if entry.IsDir {
					e = os.MkdirAll(path, 0700)
				} else {
					if e = os.MkdirAll(filepath.Dir(path), 0700); e == nil {
						e = os.WriteFile(path, entry.Content, 0600)
					}
				}
				if e != nil {
					t.Fatal(e)
				}
			}
			if e = os.WriteFile(filepath.Join(dir, "retained.skb"), leafRaw, 0600); e != nil {
				t.Fatal(e)
			}
			leafMeta.Signatures[0].IdentityID = "id:dependency@m3c"
			stash := install.OfflineMeta{BundleMeta: leafMeta, Identities: map[string]*registry.Identity{"id:dependency@m3c": {ID: "id:forged@m3c", PubkeyB64: base64.StdEncoding.EncodeToString(make([]byte, 32)), AuthSource: "forged"}}, StashedAt: time.Now().UTC().Format(time.RFC3339Nano)}
			body, e = json.Marshal(stash)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(dir, ".skillctl-offline.json"), body, 0600); e != nil {
				t.Fatal(e)
			}
			enrollStateCLI(t, binary, root, mutationCLIList(t, root, "initial", 1, time.Now().Add(-time.Hour)))
			target := filepath.Join(root.home, ".claude", "skills", "fetch-contract", "SKILL.md")
			if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(target, []byte("old target"), 0600); e != nil {
				t.Fatal(e)
			}
			want := 0
			switch mode {
			case "foreign-dependency-id":
				want = 14
			case "foreign-root-id", "redirect", "root-final-key":
				want = 11
			case "root-final-revoked":
				want = 17
			case "unbound-env":
				want = 12
			}
			registryMutationInstall(t, binary, root, want)
			if mode == "unbound-env" && requests.Load() != 0 {
				t.Fatalf("invalid selected origin contacted registry: %d", requests.Load())
			}
			if mode == "valid" && wrongAuth.Load() != 0 {
				t.Fatalf("selected token missing or changed: %d", wrongAuth.Load())
			}
			got, e := os.ReadFile(target)
			if e != nil {
				t.Fatal(e)
			}
			if want != 0 && string(got) != "old target" {
				t.Fatal("identity denial changed old installation")
			}
			if want == 0 && string(got) != "# fetch-contract\n" {
				t.Fatalf("live identity install body: %q", got)
			}
			if foreign.Load() != 0 {
				t.Fatal("identity redirect contacted foreign endpoint")
			}
			mu.Lock()
			depCalls, rootCalls := calls["id:dependency@m3c"], calls[root.authorID]
			mu.Unlock()
			if mode == "valid" && (depCalls != 2 || rootCalls != 2) {
				t.Fatalf("fresh phase identities not observed: root=%d dep=%d", rootCalls, depCalls)
			}
			if strings.HasPrefix(mode, "root-final") && rootCalls != 2 {
				t.Fatalf("final root lookup not observed: %d", rootCalls)
			}
		})
	}
}
