package capture

import (
	"bytes"
	"context"
	"errors"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// milestoneTerm matches a delivery milestone name (PR-1, PR 2, T-01). Such a
// name must not enter runtime data: the profile bytes are digested into every
// capture and would pin a planning term forever.
var milestoneTerm = regexp.MustCompile(`\bPR[- ]?[0-9]+\b|\bT-[0-9]{2}\b`)

// O-7: no built-in profile carries a milestone term, in a description or a
// comment (the digest covers the raw bytes).
func TestBuiltinProfilesCarryNoMilestoneTerm(t *testing.T) {
	for _, planted := range []string{"the one profile PR-1 can complete", "arrives with T-02", "PR 3"} {
		if !milestoneTerm.MatchString(planted) {
			t.Fatalf("the scan misses the planted %q", planted)
		}
	}
	ids := BuiltinProfileIDs()
	if len(ids) < 5 {
		t.Fatalf("only %d built-in profiles", len(ids))
	}
	for _, id := range ids {
		raw, err := builtinProfiles.ReadFile("profiles/" + id + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		if m := milestoneTerm.FindString(string(raw)); m != "" {
			t.Errorf("profile %s carries the milestone term %q", id, m)
		}
	}
}

// O-3, SPEC-0470 section 4.2: the capture actor follows the identifier
// charset of reviewer and change ids (ASCII letters, digits and ._-@+:, at
// most 128 characters); capture refuses any other actor before it writes.
func TestCaptureRefusesUnsafeActor(t *testing.T) {
	for _, actor := range []string{"Alice Smith", "corp/alice", "b\u00f8b", strings.Repeat("a", 129), "alice;x"} {
		t.Run(actor, func(t *testing.T) {
			opts := baseOptions(t, profile(t, []string{"common.identity"}, nil), registry(t), identityRunner())
			opts.Actor = actor
			if _, err := Run(context.Background(), opts); !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("Run with actor %q: err = %v, want ErrInvalidOptions", actor, err)
			}
			if _, err := os.Stat(opts.Output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("output written for a refused actor: %v", err)
			}
		})
	}
	for _, actor := range []string{"", "alice", "id:alice@example", "Az09._-@+:" + strings.Repeat("x", 118)} {
		opts := baseOptions(t, profile(t, []string{"common.identity"}, nil), registry(t), identityRunner())
		opts.Actor = actor
		mustRun(t, opts)
	}
}

// stepClock advances by step on every reading, so a capture's start and
// finish differ.
type stepClock struct {
	mu   sync.Mutex
	t    time.Time
	step time.Duration
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(c.step)
	return c.t
}

// O-1, SPEC-0470 section 4.4: the engine writes exactly the manifest that
// trustfreeze.DeriveCaptureManifest rebuilds from the capture's files and
// capture.json, so verify can recompute a baseline's capture digest from the
// baseline alone.
func TestEngineManifestFollowsTheDerivation(t *testing.T) {
	for _, actor := range []string{"", "id:alice@example"} {
		opts := baseOptions(t, profile(t, []string{"common.identity"}, []string{"common.missing"}), registry(t), identityRunner())
		opts.Actor = actor
		opts.Host.Clock = &stepClock{t: testTime, step: 250 * time.Millisecond}
		res := mustRun(t, opts)
		if res.Capture.Capture.StartedAt == res.Capture.Capture.FinishedAt {
			t.Fatal("fixture error: start and finish must differ")
		}
		cm, err := trustfreeze.DeriveCaptureManifest(res.Manifest, res.Capture)
		if err != nil {
			t.Fatal(err)
		}
		want, got := mustCanonical(t, res.Manifest), mustCanonical(t, cm)
		if !bytes.Equal(want, got) {
			t.Fatalf("derived manifest differs from the written one:\n%s\n---\n%s", got, want)
		}
	}
	// A baseline adds approval.json; the derivation drops it again.
	opts := baseOptions(t, profile(t, []string{"common.identity"}, nil), registry(t), identityRunner())
	res := mustRun(t, opts)
	withApproval := res.Manifest
	withApproval.Kind = trustfreeze.KindBaseline
	withApproval.Files = append(append([]trustfreeze.FileEntry(nil), res.Manifest.Files...), trustfreeze.FileEntry{Path: trustfreeze.ApprovalFile, Size: 2, SHA256: strings.Repeat("0", 64)})
	cm, err := trustfreeze.DeriveCaptureManifest(withApproval, res.Capture)
	if err != nil || cm.ContentDigest != res.Manifest.ContentDigest {
		t.Fatalf("derivation from a baseline manifest: %v, %s want %s", err, cm.ContentDigest, res.Manifest.ContentDigest)
	}
}

func mustCanonical(t *testing.T, v any) []byte {
	t.Helper()
	b, err := trustfreeze.MarshalCanonical(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
