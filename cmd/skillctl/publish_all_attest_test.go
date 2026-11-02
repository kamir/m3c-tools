package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
)

// BUG-0244: `publish --all` admitted every entry but handed neither the bundle
// path nor the digest to the attest half. With no version in the manifest the
// attest half rebuilt `./<name>@.skb`, found nothing, and failed; the batch
// report then said `ok=0 fail=N` and hid that every admit had gone through.
//
// The ER1 POSTs are replaced through the batchAdmit / batchAttest seams. The
// admit fake packs a real bundle with the real ensureBundle, exactly as the
// real admit does. The attest fake runs the REAL runPublishAttest in dry-run
// mode with a real key, so digest and kind resolution are the production code.

func batchFixture(t *testing.T, names ...string) (manifest, keyPath string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	var lines []string
	for _, n := range names {
		dir := filepath.Join(home, ".claude", "skills", n)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		body := "---\nname: " + n + "\ndescription: batch probe\n---\n\n# " + n + "\n\nSays hello.\n"
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		// No version column: the entry gets the auto version, the BUG-0244 case.
		lines = append(lines, n+"  yellow  batch probe rationale")
	}
	keys := t.TempDir()
	base := filepath.Join(keys, "self")
	if err := signing.Generate(base); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	keyPath = base + ".priv"
	work := t.TempDir()
	t.Chdir(work)
	manifest = filepath.Join(work, "publish-manifest.txt")
	if err := os.WriteFile(manifest, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return manifest, keyPath
}

// fakeAdmit packs like the real admit and reports what it packed, without POST.
func fakeAdmit(t *testing.T) func(io.Writer, io.Writer, publishAdmitArgs) int {
	return func(stdout, stderr io.Writer, a publishAdmitArgs) int {
		path, ver, err := ensureBundle(a, stderr)
		if err != nil {
			t.Errorf("admit fake: %v", err)
			return 1
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("admit fake: %v", err)
			return 1
		}
		d, _ := sha256Hex(raw)
		if a.result != nil {
			*a.result = admitResult{bundlePath: path, version: ver, digest: "sha256:" + d}
		}
		return 0
	}
}

func withBatchSeams(t *testing.T, admit func(io.Writer, io.Writer, publishAdmitArgs) int, attest func(io.Writer, io.Writer, publishAttestArgs) int) {
	t.Helper()
	oldA, oldT := batchAdmit, batchAttest
	batchAdmit, batchAttest = admit, attest
	t.Cleanup(func() { batchAdmit, batchAttest = oldA, oldT })
}

func TestPublishAllAttestGetsTheAdmittedBundle(t *testing.T) {
	manifest, key := batchFixture(t, "batch-one", "batch-two")
	var seen []publishAttestArgs
	withBatchSeams(t, fakeAdmit(t), func(stdout, stderr io.Writer, a publishAttestArgs) int {
		seen = append(seen, a)
		a.dryRun = true // the real attest up to, not including, the POST
		return runPublishAttest(stdout, stderr, a)
	})

	var out, errBuf bytes.Buffer
	rc := runPublishAll(&out, &errBuf, publishAllArgs{manifestPath: manifest, identity: "id:probe@test",
		keyPath: key, yes: true, noCheckpoint: true})
	all := out.String() + errBuf.String()
	if rc != 0 {
		t.Fatalf("batch exited %d, want 0 (admit and attest both succeed)\n%s", rc, all)
	}
	if len(seen) != 2 {
		t.Fatalf("attest ran %d times, want 2\n%s", len(seen), all)
	}
	for _, a := range seen {
		if a.version == "" {
			t.Errorf("%s: attest got an empty version", a.name)
		}
		if a.bundlePath == "" && a.digestArg == "" {
			t.Errorf("%s: attest got neither bundle nor digest", a.name)
		}
	}
	if strings.Contains(all, "@.skb") || strings.Contains(all, "need --digest") {
		t.Errorf("attest rebuilt a versionless bundle name:\n%s", all)
	}
	if !strings.Contains(out.String(), "batch done: ok=2 fail=0 total=2") {
		t.Errorf("summary line wrong:\n%s", out.String())
	}
}

// The second acceptance point: a deliberately missing bundle turns ONLY the
// attest column red and names it so; the admit stays visibly green.
func TestPublishAllReportSeparatesAdmitFromAttest(t *testing.T) {
	manifest, key := batchFixture(t, "half-one")
	withBatchSeams(t, func(stdout, stderr io.Writer, a publishAdmitArgs) int {
		rc := fakeAdmit(t)(stdout, stderr, a)
		if a.result != nil {
			_ = os.Remove(a.result.bundlePath) // the bundle goes missing before attest
			a.result.digest = ""
		}
		return rc
	}, func(stdout, stderr io.Writer, a publishAttestArgs) int {
		a.dryRun = true
		return runPublishAttest(stdout, stderr, a)
	})

	var out, errBuf bytes.Buffer
	rc := runPublishAll(&out, &errBuf, publishAllArgs{manifestPath: manifest, identity: "id:probe@test",
		keyPath: key, yes: true, noCheckpoint: true})
	if rc == 0 {
		t.Fatalf("batch exited 0 although the attest failed\n%s%s", out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "half-one") || !strings.Contains(out.String(), "admit ok, attest FAIL") {
		t.Errorf("report does not name the half state per entry:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "admit ok=1 fail=0") || !strings.Contains(out.String(), "attest ok=0 fail=1") {
		t.Errorf("report does not count admit and attest separately:\n%s", out.String())
	}
}
