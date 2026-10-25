package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/install"
	"github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
	"gopkg.in/yaml.v3"
)

const managedCLITransportKey = "synthetic-cli-managed-key"

func TestInstallManagedTransportActualCLI(t *testing.T) {
	binary := skillctlBin(t)
	for _, pinned := range []bool{true, false} {
		author := "registry"
		if pinned {
			author = "pinned"
		}
		for _, mode := range []string{"relative", "absolute", "dot-relative", "relative-escape", "other-port", "foreign-prefix", "lookalike", "malformed-location", "metadata-reflection", "bad-env-pin", "bad-prefix", "ignore"} {
			t.Run(author+"/"+mode, func(t *testing.T) {
				proof := installedCLIProofFixture(t)
				leaf, leafMeta := installedCLIBundle(t, proof, "required", "")
				root, meta := installedCLIBundle(t, proof, "fetch-contract", `,"depends_on":[{"kind":"skill","name":"required"}]`)
				root.home = t.TempDir()
				var foreign, requests, audits, badAuth, redirects atomic.Int32
				decoy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { foreign.Add(1); w.WriteHeader(500) }))
				defer decoy.Close()
				rawRoot, err := os.ReadFile(root.skbPath)
				if err != nil {
					t.Fatal(err)
				}
				var serverURL string
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if r.Header.Get("Authorization") != "Bearer "+managedCLITransportKey {
						badAuth.Add(1)
					}
					if strings.Contains(r.URL.Path, "/audit") {
						audits.Add(1)
						w.WriteHeader(201)
						return
					}
					if !strings.HasPrefix(r.URL.Path, "/api/skills/") {
						foreign.Add(1)
						w.WriteHeader(500)
						return
					}
					if strings.Contains(r.URL.Path, "/identities/") {
						id := strings.TrimPrefix(r.URL.Path, "/api/skills/identities/")
						_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "pubkey_b64": root.authorPubB64, "auth_source": "manual"})
						return
					}
					if strings.HasPrefix(r.URL.Path, "/api/skills/by-name/") && r.URL.Path != "/api/skills/by-name/retained-redirected" {
						redirects.Add(1)
						location := "/api/skills/allowed/name"
						switch mode {
						case "relative":
							location = "retained-redirected"
						case "absolute":
							location = serverURL + location
						case "dot-relative":
							location = "../allowed/name"
						case "relative-escape":
							location = "../../outside"
						case "other-port":
							location = decoy.URL + location
						case "foreign-prefix":
							location = "/other/escape"
						case "lookalike":
							location = "/api/skills-foreign/name"
						case "malformed-location":
							location = serverURL + "/api/skills/" + managedCLITransportKey + "%zz"
						default:
							_ = json.NewEncoder(w).Encode(map[string]any{"versions": []registry.BundleVersion{{Version: "1.0.0", Digest: root.digest, Status: "admitted"}}})
							return
						}
						w.Header().Set("Location", location)
						w.WriteHeader(302)
						return
					}
					if r.URL.Path == "/api/skills/allowed/name" || r.URL.Path == "/api/skills/by-name/retained-redirected" {
						_ = json.NewEncoder(w).Encode(map[string]any{"versions": []registry.BundleVersion{{Version: "1.0.0", Digest: root.digest, Status: "admitted"}}})
						return
					}
					if strings.Contains(r.URL.Path, "/bundles/") {
						if r.URL.Query().Get("meta") == "1" {
							if mode == "metadata-reflection" {
								m := *meta
								m.Bundle = map[string]any{"bundle_digest": managedCLITransportKey, "status": "admitted"}
								_ = json.NewEncoder(w).Encode(m)
							} else {
								_ = json.NewEncoder(w).Encode(meta)
							}
						} else {
							_, _ = w.Write(rawRoot)
						}
						return
					}
					foreign.Add(1)
					w.WriteHeader(500)
				}))
				defer srv.Close()
				serverURL = srv.URL
				root.regURL = srv.URL + "/api/skills"
				if mode == "bad-prefix" {
					root.regURL += "/%252e"
				}
				roots, err := verify.Load(root.trPath)
				if err != nil {
					t.Fatal(err)
				}
				roots.Roots[0].RegistryURL = root.regURL
				if pinned {
					roots.Roots[0].Authors = append(roots.Roots[0].Authors, verify.AuthorKey{ID: "id:dependency@m3c", PubkeyB64: root.authorPubB64})
				} else {
					roots.Roots[0].IdentityKeysAuthorized = "from-registry"
					roots.Roots[0].Authors = nil
				}
				body, err := yaml.Marshal(roots)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(root.trPath, body, 0600); err != nil {
					t.Fatal(err)
				}
				dir := filepath.Join(root.home, ".claude", "skills", "required")
				if err = os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				leafRaw, err := os.ReadFile(leaf.skbPath)
				if err != nil {
					t.Fatal(err)
				}
				entries, err := skillbundle.Unpack(leafRaw, skillbundle.UnpackOptions{StripWrapper: true})
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if entry.Rel == "." {
						continue
					}
					path := filepath.Join(dir, filepath.FromSlash(entry.Rel))
					if entry.IsDir {
						err = os.MkdirAll(path, 0700)
					} else {
						if err = os.MkdirAll(filepath.Dir(path), 0700); err == nil {
							err = os.WriteFile(path, entry.Content, 0600)
						}
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				if err = os.WriteFile(filepath.Join(dir, "retained.skb"), leafRaw, 0600); err != nil {
					t.Fatal(err)
				}
				leafMeta.Signatures[0].IdentityID = "id:dependency@m3c"
				body, err = json.Marshal(install.OfflineMeta{BundleMeta: leafMeta, StashedAt: time.Now().UTC().Format(time.RFC3339Nano)})
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, ".skillctl-offline.json"), body, 0600); err != nil {
					t.Fatal(err)
				}
				enrollStateCLI(t, binary, root, mutationCLIList(t, root, "initial", 1, time.Now().Add(-time.Hour)))
				target := filepath.Join(root.home, ".claude", "skills", "fetch-contract", "SKILL.md")
				if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(target, []byte("old target"), 0600); err != nil {
					t.Fatal(err)
				}
				args := append([]string{"install", "--json"}, enterpriseInstallFixtureArgs(t, root)...)
				if mode == "bad-prefix" {
					cwd, e := os.Getwd()
					if e != nil {
						t.Fatal(e)
					}
					if _, e = projectpolicy.Load(args[3], cwd, root.home); e != nil {
						t.Fatalf("fixture rejected before strict transport boundary: %v", e)
					}
				}
				args = append(args, "--registry", root.regURL)
				if mode == "ignore" {
					args = append(args, "--ignore-deps")
				}
				args = append(args, "fetch-contract")
				origin := srv.URL
				if mode == "bad-env-pin" {
					origin = decoy.URL
				}
				cmd := exec.Command(binary, args...)
				cmd.Env = append(os.Environ(), "HOME="+root.home, "USERPROFILE="+root.home, "M3C_TOKEN_STORE=file", "M3C_TEST_KEYCHAIN=0", "M3C_ER1_KEYCHAIN=off", "M3C_REGISTRY_RO_TOKEN=", "M3C_REGISTRY_TOKEN="+managedCLITransportKey, "M3C_REGISTRY_TOKEN_ORIGIN="+origin)
				var stdout, stderr bytes.Buffer
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr
				runErr := cmd.Run()
				code := 0
				if runErr != nil {
					var exit *exec.ExitError
					if !errors.As(runErr, &exit) {
						t.Fatal(runErr)
					}
					code = exit.ExitCode()
				}
				want := 1
				switch mode {
				case "relative", "absolute", "dot-relative":
					want = 0
				case "metadata-reflection":
					want = 10
				case "bad-env-pin", "bad-prefix":
					want = 12
				case "ignore":
					want = 2
				}
				if code != want {
					t.Fatalf("actual managed transport exit=%d want=%d output=%s stderr=%s", code, want, stdout.String(), stderr.String())
				}
				if strings.Contains(stdout.String()+stderr.String(), managedCLITransportKey) {
					t.Fatal("selected credential reflected in actual CLI diagnostics")
				}
				if foreign.Load() != 0 {
					t.Fatalf("forbidden target received request: %d", foreign.Load())
				}
				if audits.Load() != 0 {
					t.Fatal("managed install invoked audit override")
				}
				if (mode == "bad-env-pin" || mode == "bad-prefix" || mode == "ignore") && requests.Load() != 0 {
					t.Fatal("early refusal contacted registry")
				}
				if requests.Load() > 0 && badAuth.Load() != 0 {
					t.Fatal("selected managed token changed")
				}
				got, err := os.ReadFile(target)
				if err != nil {
					t.Fatal(err)
				}
				if want != 0 && string(got) != "old target" {
					t.Fatal("transport refusal changed old installation")
				}
				if want == 0 && string(got) != "# fetch-contract\n" {
					t.Fatal("allowed transport did not install signed body")
				}
				audit, err := os.ReadFile(lifecycleAuditPath(root.home))
				if (mode == "malformed-location" || mode == "metadata-reflection") && (err != nil || len(audit) == 0) {
					t.Fatalf("error lifecycle record not observed: %v", err)
				}
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
				if bytes.Contains(audit, []byte(managedCLITransportKey)) {
					t.Fatal("selected credential persisted in lifecycle diagnostics")
				}
			})
		}
	}
}
