package git

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
)

// TestGitWireFormatFrozen is the SPEC-0356 §6a FREEZE guard. Once real skills
// land in a git registry the on-disk layout is a permanent, externally-pinned
// contract; this test pins that contract byte-for-byte so any accidental drift
// (a renamed path, a dropped attribute, a reserialized event) goes red in CI.
// If this test needs updating, the wire format changed — bump WireFormatVersion
// and write a migration, do not "fix" the assertions.
func TestGitWireFormatFrozen(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	ctx := context.Background()
	bare := bareRepo(t)
	b := newGitBackend(bare, "gitlab")
	defer b.Close()

	const name, ver = "freeze-canary", "1.0.0"
	d := fdig('a')
	admit := admitEvent(name, ver, d)
	if _, err := b.Publish(ctx, admit); err != nil {
		t.Fatalf("Publish admit: %v", err)
	}

	// Materialize the pushed tree into a working checkout we can inspect.
	work := filepath.Join(t.TempDir(), "wc")
	mustGit(t, "", "clone", "--quiet", bare, work)
	read := func(rel string) []byte {
		data, err := os.ReadFile(filepath.Join(work, rel))
		if err != nil {
			t.Fatalf("frozen file %s missing/unreadable: %v", rel, err)
		}
		return data
	}

	// 1) The write-once version anchor — dedicated marker at a HARDCODED literal
	//    path (not the markerPath const, so a rename is caught), schema_version
	//    asserted as a literal 1 (not against WireFormatVersion — which would make
	//    a version bump self-follow).
	var m formatMarker
	if err := json.Unmarshal(read(".skillctl/registry.json"), &m); err != nil {
		t.Fatalf(".skillctl/registry.json not valid JSON: %v", err)
	}
	if m.SchemaVersion != 1 {
		t.Errorf("frozen schema_version = %d, want 1", m.SchemaVersion)
	}

	// 2) Byte-safety attribute at its literal path — without this a Windows
	//    checkout corrupts the .skb digest. It MUST be in the frozen layout.
	if attrs := string(read(".gitattributes")); !strings.Contains(attrs, "*.skb binary -text") {
		t.Errorf(".gitattributes missing `*.skb binary -text`; got:\n%s", attrs)
	}

	// 3) The blob path + EXACT bytes (sha256 of these bytes is the pinned digest).
	if got := read("skills/freeze-canary/1.0.0/bundle.skb"); string(got) != string(admit.Blob) {
		t.Errorf("bundle.skb bytes drifted: got %q want %q", got, admit.Blob)
	}

	// 4) The review handle carries the (advisory) digest at the frozen path.
	var bj bundleJSON
	if err := json.Unmarshal(read("skills/freeze-canary/1.0.0/bundle.json"), &bj); err != nil {
		t.Fatalf("bundle.json invalid: %v", err)
	}
	if bj.Digest != d || bj.Name != name || bj.Version != ver {
		t.Errorf("bundle.json = %+v, want name/version/digest %s/%s/%s", bj, name, ver, d)
	}

	// 5) The event path (events/<digesthex>/0001-admitted.json) + the frozen
	//    serialization, pinned to a HAND-WRITTEN golden literal (2-space indent,
	//    sorted keys) — NOT marshalEvent(admit.Event), which would move both sides
	//    together and hide a serializer drift. External SPEC-0190 consumers read
	//    these bytes; a reindent is a wire change, so it must redden here.
	evRel := "events/" + strings.Repeat("a", 64) + "/0001-admitted.json"
	wantEv := "{\n" +
		"  \"bundle_digest\": \"" + d + "\",\n" +
		"  \"kind\": \"admitted\",\n" +
		"  \"schema_version\": \"1.0.0\",\n" +
		"  \"skill\": \"freeze-canary\",\n" +
		"  \"version\": \"1.0.0\"\n" +
		"}"
	// Git may smudge a text file to CRLF on checkout (Windows). EOL is presentational
	// for the event JSON — the verifier re-canonicalizes from the parsed map
	// (WIRE-FORMAT.md §4) — so the freeze pins indent + key order + content, with EOL
	// normalized. A reindent (2-space -> tab) still fails here; a line-ending does not.
	gotEv := strings.ReplaceAll(string(read(evRel)), "\r\n", "\n")
	if gotEv != wantEv {
		t.Errorf("event file %s serialization drifted:\n got: %q\nwant: %q", evRel, gotEv, wantEv)
	}

	// 6) The publish unit is the tag <name>/v<version>.
	if out := gitOut(t, work, "tag", "--list", "freeze-canary/v1.0.0"); strings.TrimSpace(out) != "freeze-canary/v1.0.0" {
		t.Errorf("frozen tag missing: git tag --list => %q", out)
	}
}

// TestGitWireFormatWriteOnce proves the version marker is written ONCE and never
// rewritten by a later publish. It drives ensureFormatFiles directly with TWO
// DIFFERENT clocks (no git, no wall-clock dependency): a re-stamp regression is
// caught deterministically because it would flip changed→true AND drift
// created_at to T2 — unlike a byte-compare of two same-second live publishes,
// which the challenge gate proved is a false-negative 11/20 runs.
func TestGitWireFormatWriteOnce(t *testing.T) {
	dir := t.TempDir()
	t1 := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 8, 31, 12, 30, 0, 0, time.UTC) // deliberately a different second

	changed, err := ensureFormatFiles(dir, "skillctl", t1)
	if err != nil || !changed {
		t.Fatalf("first ensureFormatFiles: changed=%v err=%v, want true/nil", changed, err)
	}
	first, err := os.ReadFile(filepath.Join(dir, markerPath))
	if err != nil {
		t.Fatal(err)
	}

	// Second call, different clock + author: MUST be a no-op (write-once).
	changed2, err := ensureFormatFiles(dir, "someone-else", t2)
	if err != nil {
		t.Fatal(err)
	}
	if changed2 {
		t.Error("second ensureFormatFiles reported a change; the marker must be write-once")
	}
	second, err := os.ReadFile(filepath.Join(dir, markerPath))
	if err != nil {
		t.Fatal(err)
	}
	if string(second) != string(first) {
		t.Errorf("marker rewritten by a later call (not write-once):\n first: %s\nsecond: %s", first, second)
	}
	// The retained created_at is T1's, proving the FIRST stamp survived (not T2).
	var m formatMarker
	if err := json.Unmarshal(second, &m); err != nil {
		t.Fatal(err)
	}
	if want := t1.UTC().Format(time.RFC3339); m.CreatedAt != want {
		t.Errorf("created_at = %q, want the first stamp %q (a re-stamp would show T2)", m.CreatedAt, want)
	}
}

// TestGitWireFormatFailsClosed proves a repo marked with a NEWER wire-format
// version is refused for both reads and writes (fail closed), rather than
// silently misread by an older client.
func TestGitWireFormatFailsClosed(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	ctx := context.Background()
	bare := bareRepo(t)
	b := newGitBackend(bare, "gitlab")
	defer b.Close()

	if _, err := b.Publish(ctx, admitEvent("fc", "1.0.0", fdig('c'))); err != nil {
		t.Fatalf("seed admit: %v", err)
	}

	// Simulate a newer client bumping the repo to a version we don't support.
	work := filepath.Join(t.TempDir(), "bump")
	mustGit(t, "", "clone", "--quiet", bare, work)
	future, _ := json.MarshalIndent(formatMarker{SchemaVersion: WireFormatVersion + 5, CreatedBy: "future"}, "", "  ")
	if err := os.WriteFile(filepath.Join(work, markerPath), future, 0o644); err != nil {
		t.Fatal(err)
	}
	mustGit(t, work, "add", "-A")
	mustGit(t, work, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "bump to future format")
	mustGit(t, work, "push", "--quiet", "origin", "HEAD")

	// Reads refuse.
	if _, err := b.List(ctx, artifact.ListFilter{}, artifact.Page{}); err == nil ||
		!strings.Contains(err.Error(), "newer than this build") {
		t.Errorf("List on a future-version repo should fail closed; got err=%v", err)
	}
	// Writes refuse too.
	if _, err := b.Publish(ctx, admitEvent("fc2", "1.0.0", fdig('d'))); err == nil ||
		!strings.Contains(err.Error(), "newer than this build") {
		t.Errorf("Publish into a future-version repo should fail closed; got err=%v", err)
	}
}

// fdig builds a valid canonical digest (64 lowercase-hex chars) from a hex byte.
func fdig(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

// TestGitWireFormatSymlinkRefused is the regression for the challenge-gate HIGH:
// a hostile repo commits the version marker as a symlink escaping the clone; the
// backend must FAIL CLOSED on both read and write paths and must NOT follow the
// link to create/overwrite a file outside the repo.
func TestGitWireFormatSymlinkRefused(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	ctx := context.Background()
	bare := bareRepo(t)
	b := newGitBackend(bare, "gitlab")
	defer b.Close()

	// Seed a real v1 registry (establishes the branch + a legit marker).
	if _, err := b.Publish(ctx, admitEvent("seed", "1.0.0", fdig('f'))); err != nil {
		t.Fatalf("seed admit: %v", err)
	}

	// Attacker replaces .skillctl/registry.json with a symlink to an outside path.
	outside := filepath.Join(t.TempDir(), "PWNED")
	atk := filepath.Join(t.TempDir(), "atk")
	mustGit(t, "", "clone", "--quiet", bare, atk)
	marker := filepath.Join(atk, ".skillctl", "registry.json")
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, marker); err != nil {
		// Windows needs privilege to create symlinks; there git also defaults to
		// core.symlinks=false, so a committed symlink is never materialized — the
		// attack vector this test covers is a *nix concern. Skip where unsupported.
		t.Skipf("symlink creation unsupported here (%v); defense is core.symlinks=false, OS-independent", err)
	}
	mustGit(t, atk, "add", "-A")
	mustGit(t, atk, "-c", "user.email=a@a", "-c", "user.name=a", "commit", "-m", "evil marker symlink")
	mustGit(t, atk, "push", "--quiet", "origin", "HEAD")

	// A read path must refuse, not follow the link.
	if _, err := b.List(ctx, artifact.ListFilter{}, artifact.Page{}); err == nil {
		t.Error("List against a symlinked-marker repo should fail closed")
	}
	// A write path must refuse AND must not create the escaped target.
	if _, err := b.Publish(ctx, admitEvent("evil", "1.0.0", fdig('e'))); err == nil {
		t.Error("Publish into a symlinked-marker repo should fail closed")
	}
	if _, err := os.Stat(outside); err == nil {
		t.Fatalf("SECURITY: symlinked marker escaped the clone and wrote %s", outside)
	}
}

func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}
