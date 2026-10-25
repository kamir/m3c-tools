package dependencies

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func observationFixture(t *testing.T) string {
	t.Helper()
	root := isolated(t)
	if err := os.WriteFile(filepath.Join(root, "a.py"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "empty"), 0700); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestRuntimeTreeObservationGolden(t *testing.T) {
	root := observationFixture(t)
	observed, err := FingerprintTree(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	// Fixed independent digest of the documented three-entry byte protocol.
	if observed.Algorithm != "m3c.python-site-tree/v1" || observed.Digest != "140cac5e910981aa05f4b2fce61b5627a02af214120c8cd5d0d303bcd9407ddd" || observed.Path != canonical || !observed.Complete || observed.Approved {
		t.Fatalf("unexpected observation: %+v", observed)
	}
	if observed.Limits != (TreeObservationLimits{100000, 4 << 20, 4096, 128, 256 << 20}) {
		t.Fatalf("changed public limits: %+v", observed.Limits)
	}
	raw, err := json.Marshal(observed)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if json.Unmarshal(raw, &decoded) != nil || decoded["approved"] != false || decoded["complete"] != true || decoded["algorithm"] != "m3c.python-site-tree/v1" {
		t.Fatal("observation wire contract")
	}
	// The existing limited reader must preserve the same hash and deny every
	// independent exhausted budget, rather than silently produce a partial tree.
	exact := treeLimits{3, 10, 5, 1, 9}
	if _, hash, err := siteFingerprintBounded(context.Background(), root, exact); err != nil || hash != observed.Digest {
		t.Fatalf("exact limits: %v", err)
	}
	for _, limit := range []treeLimits{{2, 10, 5, 1, 9}, {3, 9, 5, 1, 9}, {3, 10, 4, 1, 9}, {3, 10, 5, 0, 9}, {3, 10, 5, 1, 8}} {
		if _, _, err := siteFingerprintBounded(context.Background(), root, limit); !errors.Is(err, ErrUnresolved) {
			t.Fatalf("exhausted budget accepted: %+v %v", limit, err)
		}
	}
}

func TestRuntimeTreeObservationReadOnly(t *testing.T) {
	root := observationFixture(t)
	profile := filepath.Join(root, "profile.json")
	original := []byte("{\"operator_approved\":false}\n")
	if err := os.WriteFile(profile, original, 0600); err != nil {
		t.Fatal(err)
	}
	first, err := FingerprintTree(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := FingerprintTree(context.Background(), root)
	if err != nil || first.Digest != second.Digest || first.Approved || second.Approved {
		t.Fatalf("read changed tree or approval: %v", err)
	}
	after, err := os.ReadFile(profile)
	if err != nil || string(after) != string(original) {
		t.Fatal("profile changed")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 3 {
		t.Fatal("observation created files")
	}
	if err := os.WriteFile(filepath.Join(root, "a.py"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := FingerprintTree(context.Background(), root)
	if err != nil || changed.Digest == first.Digest || changed.Approved {
		t.Fatalf("change not observed: %v", err)
	}

}

func TestRuntimeTreeObservationInvalid(t *testing.T) {
	root := observationFixture(t)
	for _, path := range []string{"", "relative", strings.Repeat("x", 4097), root + "\x00", root + "\xff"} {
		if out, err := FingerprintTree(context.Background(), path); out != nil || !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid path accepted: %v", err)
		}
	}
	missingContext := struct{ context.Context }{}
	if out, err := FingerprintTree(missingContext.Context, root); out != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err := FingerprintTree(ctx, filepath.Join(root, "missing")); out != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
	for _, path := range []string{filepath.Join(root, "missing"), filepath.Join(root, "a.py")} {
		if out, err := FingerprintTree(context.Background(), path); out != nil || err == nil {
			t.Fatal("missing/non-directory succeeded")
		}
	}
	if err := os.Symlink(filepath.Join(root, "a.py"), filepath.Join(root, "link")); err != nil {
		// Windows policy may prohibit creating links; this prerequisite is separate
		// from the mandatory common path validation exercised above.
		t.Logf("link creation unavailable: %v", err)
	} else if out, err := FingerprintTree(context.Background(), root); out != nil || !errors.Is(err, ErrUnresolved) {
		t.Fatal("interior link accepted")
	}
}
