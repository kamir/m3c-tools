//go:build darwin

package main

import (
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/kamir/m3c-tools/pkg/plaud"
)

// BUG-0617: `plaud dev sync` and the menubar sync decide what to skip from the
// sync check. When the server check fails, nothing may be uploaded: the local
// ledger alone does not know what other machines synced.
func TestDevSyncUploadsNothingWhenTheServerCheckFails(t *testing.T) {
	var others atomic.Int32
	srv := plaudSyncTestServer(t, http.StatusInternalServerError, "boom", &others)
	plaudSyncTestEnv(t, srv)

	tokenFile := filepath.Join(t.TempDir(), "tokens-mcp.json")
	if err := os.WriteFile(tokenFile, []byte(`{"access_token":"plaud-test-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := plaud.NewDevClientFromFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	id := "of_aaaa1111bbbb2222cccc3333dddd4444"
	recs := map[string]plaud.DevRecording{id: {ID: id, Name: "synced elsewhere", Duration: 60000}}
	var phases []string
	prog := func(id, name, phase, disp, docID string, err error) { phases = append(phases, phase) }

	tot, err := runDevSyncByIDs(client, recs, []string{id}, "", false, false, prog)

	if err == nil {
		t.Fatal("a failed server check must stop the sync")
	}
	if tot != (devSyncTotals{}) || len(phases) != 0 {
		t.Fatalf("nothing may be attempted, got totals %+v and phases %v", tot, phases)
	}
	if n := others.Load(); n != 0 {
		t.Fatalf("%d request(s) besides the check reached ER1", n)
	}
}
