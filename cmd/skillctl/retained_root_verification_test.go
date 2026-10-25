package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestInstallRetainedRootSnapshotActualCLI(t *testing.T) {
	binary := skillctlBin(t)
	for _, mode := range []string{"remove", "replace", "wrong-retained"} {
		t.Run(mode, func(t *testing.T) {
			fx := newFixture(t)
			home := t.TempDir()
			mux := fx.happyMux(t, map[string]any{"depends_on": []any{}}, "green", nil)
			var mu sync.Mutex
			var mutationErr error
			changed := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/bundles/") && r.URL.Query().Get("meta") == "1" {
					count := 0
					err := filepath.WalkDir(filepath.Join(home, ".claude", "skills", ".tmp"), func(path string, d os.DirEntry, e error) error {
						if e != nil {
							return e
						}
						if d.IsDir() || !strings.HasSuffix(path, ".skb") {
							return nil
						}
						count++
						if mode == "remove" {
							return os.Remove(path)
						}
						replacement := fx.blob
						if mode == "replace" {
							replacement = []byte("different staged bytes")
						}
						return os.WriteFile(path, replacement, 0600)
					})
					if err == nil && count != 1 {
						err = fmt.Errorf("staged archive count=%d", count)
					}
					mu.Lock()
					changed += count
					mutationErr = err
					mu.Unlock()
				} else if mode == "wrong-retained" && strings.Contains(r.URL.Path, "/bundles/") {
					_, _ = w.Write([]byte("unsigned download"))
					return
				}
				mux.ServeHTTP(w, r)
			}))
			defer srv.Close()
			fx.pinTrust(t, home, srv.URL, "")
			defaultPath := filepath.Join(home, ".claude", "skill-trust-roots.yaml")
			raw, err := os.ReadFile(defaultPath)
			if err != nil {
				t.Fatal(err)
			}
			raw = append(raw, []byte("    offline_policy:\n      enterprise: true\n")...)
			roots := filepath.Join(t.TempDir(), "roots.yaml")
			if err := os.WriteFile(roots, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(defaultPath); err != nil {
				t.Fatal(err)
			}
			f := installableFixture{home: home, dir: t.TempDir(), trPath: roots, regURL: srv.URL + "/api/skills", regPriv: fx.regPriv, regPubB64: base64.StdEncoding.EncodeToString(fx.regPub), digest: fx.digestStr}
			enrollStateCLI(t, binary, f, mutationCLIList(t, f, "initial", 1, time.Now().Add(-time.Hour)))
			want := 0
			if mode == "wrong-retained" {
				want = 10
			}
			registryMutationInstall(t, binary, f, want)
			mu.Lock()
			count, changeErr := changed, mutationErr
			mu.Unlock()
			if count != 1 || changeErr != nil {
				t.Fatalf("metadata handler did not mutate exactly one staged archive: %d %v", count, changeErr)
			}
			target := filepath.Join(home, ".claude", "skills", "fetch-contract")
			if want != 0 {
				if _, err := os.Stat(target); !os.IsNotExist(err) {
					t.Fatal("unsigned retained bytes published target")
				}
				return
			}
			paths, err := filepath.Glob(filepath.Join(target, "*.skb"))
			if err != nil || len(paths) != 1 {
				t.Fatalf("stash count: %v %v", paths, err)
			}
			got, err := os.ReadFile(paths[0])
			if err != nil || !bytes.Equal(got, fx.blob) {
				t.Fatalf("actual CLI stash differs from signed retained download: %v", err)
			}
		})
	}
}
