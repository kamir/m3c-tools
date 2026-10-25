package mutationstate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// Reexec uses this test binary and only public signed fixtures. It does not
// build a product CLI, inspect a credential store or invoke an external backend.
func TestStateRealProcessLock(t *testing.T) {
	if mode := os.Getenv("M3C_MUTATION_STATE_CHILD"); mode != "" {
		rootBytes, err := os.ReadFile(os.Getenv("M3C_MUTATION_STATE_ROOT"))
		if err != nil {
			t.Fatal(err)
		}
		var root verify.TrustRoot
		if err := json.Unmarshal(rootBytes, &root); err != nil {
			t.Fatal(err)
		}
		store, err := New(os.Getenv("M3C_MUTATION_STATE_DIR"), &root)
		if err != nil {
			t.Fatal(err)
		}
		now, err := time.Parse(time.RFC3339Nano, os.Getenv("M3C_MUTATION_STATE_NOW"))
		if err != nil {
			t.Fatal(err)
		}
		store.now = func() time.Time { return now }
		list, err := os.ReadFile(os.Getenv("M3C_MUTATION_STATE_LIST"))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		status, err := store.Adopt(ctx, list)
		switch mode {
		case "blocked":
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("cross-process lock bypassed: %v", err)
			}
		case "released":
			if err != nil || status.Epoch != 8 {
				t.Fatalf("released lock did not permit advance: %+v %v", status, err)
			}
		default:
			t.Fatal("unknown child mode")
		}
		return
	}
	f := newStateFixture(t)
	enrollFixture(t, f, 7)
	rootBytes, err := json.Marshal(f.root)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.json")
	listPath := filepath.Join(dir, "list.json")
	if err := os.WriteFile(rootPath, rootBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(listPath, f.list(t, 8, f.clock.now()), 0600); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	run := func(mode string) {
		t.Helper()
		cmd := exec.Command(binary, "-test.run=^TestStateRealProcessLock$", "-test.count=1")
		cmd.Env = append(os.Environ(), "M3C_MUTATION_STATE_CHILD="+mode, "M3C_MUTATION_STATE_ROOT="+rootPath, "M3C_MUTATION_STATE_LIST="+listPath, "M3C_MUTATION_STATE_DIR="+f.dir, "M3C_MUTATION_STATE_NOW="+f.clock.now().Format(time.RFC3339Nano))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child %s failed: %v\n%s", mode, err, out)
		}
	}
	active, err := f.store.Begin(context.Background(), verify.MutationInstall, f.digest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = active.Close() }()
	run("blocked")
	if err := active.Close(); err != nil {
		t.Fatal(err)
	}
	run("released")
	status, err := f.reopen(t).Status(context.Background())
	if err != nil || status.Epoch != 8 {
		t.Fatalf("child did not durably advance: %+v %v", status, err)
	}
}
