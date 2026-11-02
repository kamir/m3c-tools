package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
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
	var lines []string
	for _, n := range names {
		// No version column: the entry gets the auto version, the BUG-0244 case.
		lines = append(lines, n+"  yellow  batch probe rationale")
	}
	return batchFixtureLines(t, names, lines)
}

// batchFixtureLines creates a skill dir for each name in skills and writes the
// manifest lines verbatim, so a test can list an entry whose skill is missing
// (its admit fails) or one without a level column.
func batchFixtureLines(t *testing.T, skills, lines []string) (manifest, keyPath string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, n := range skills {
		dir := filepath.Join(home, ".claude", "skills", n)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		body := "---\nname: " + n + "\ndescription: batch probe\n---\n\n# " + n + "\n\nSays hello.\n"
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
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
			// What the real runPublishAdmit does when the pack fails.
			fmt.Fprintf(stderr, "publish: %v\n", err)
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
		// The exact bundle the admit packed: auto version 0.0.0, its path,
		// and the digest of its bytes, read here independently of the code.
		if a.version != "0.0.0" {
			t.Errorf("%s: attest got version %q, want 0.0.0", a.name, a.version)
		}
		want := filepath.Join(".", a.name+"@0.0.0.skb")
		if a.bundlePath != want {
			t.Errorf("%s: attest got bundle %q, want %q", a.name, a.bundlePath, want)
		}
		raw, err := os.ReadFile(want)
		if err != nil {
			t.Fatalf("%s: packed bundle missing: %v", a.name, err)
		}
		d, _ := sha256Hex(raw)
		if a.digestArg != "sha256:"+d {
			t.Errorf("%s: attest got digest %q, want sha256:%s", a.name, a.digestArg, d)
		}
	}
	if strings.Contains(all, "@.skb") || strings.Contains(all, "need --digest") {
		t.Errorf("attest rebuilt a versionless bundle name:\n%s", all)
	}
	assertLine(t, out.String(), `==> batch done: ok=2 fail=0 total=2`)
	assertLine(t, out.String(), `admit ok=2 fail=0; attest ok=2 fail=0 skipped=0`)
	assertRow(t, out.String(), "batch-one@0.0.0", "admit ok, attest ok")
	assertRow(t, out.String(), "batch-two@0.0.0", "admit ok, attest ok")
}

// assertLine requires a stdout line that equals want after trimming spaces.
func assertLine(t *testing.T, out, want string) {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) == want {
			return
		}
	}
	t.Errorf("no line %q in:\n%s", want, out)
}

// assertRow requires exactly one per-entry row "<label>  <status>".
func assertRow(t *testing.T, out, label, status string) {
	t.Helper()
	re := regexp.MustCompile(`(?m)^\s+` + regexp.QuoteMeta(label) + `\s+` + regexp.QuoteMeta(status) + `$`)
	if n := len(re.FindAllString(out, -1)); n != 1 {
		t.Errorf("want exactly one row %q / %q, found %d in:\n%s", label, status, n, out)
	}
}

// The other two row kinds: an entry without a level (admit only, attest
// skipped) and an entry whose admit fails (its skill dir does not exist, so the
// real ensureBundle refuses). Neither may reach attest, and each is counted in
// its own column.
func TestPublishAllReportsSkippedAndFailedAdmits(t *testing.T) {
	manifest, key := batchFixtureLines(t,
		[]string{"good-one", "plain-one"},
		[]string{
			"good-one  yellow  batch probe rationale",
			"plain-one",
			"broken-one  yellow  its skill dir is missing",
		})
	var attested []string
	withBatchSeams(t, fakeAdmit(t), func(stdout, stderr io.Writer, a publishAttestArgs) int {
		attested = append(attested, a.name)
		a.dryRun = true
		return runPublishAttest(stdout, stderr, a)
	})

	var out, errBuf bytes.Buffer
	rc := runPublishAll(&out, &errBuf, publishAllArgs{manifestPath: manifest, identity: "id:probe@test",
		keyPath: key, yes: true, noCheckpoint: true})
	if rc == 0 {
		t.Fatalf("batch exited 0 although one admit failed\n%s%s", out.String(), errBuf.String())
	}
	if len(attested) != 1 || attested[0] != "good-one" {
		t.Errorf("attest ran for %v, want only [good-one]", attested)
	}
	assertLine(t, out.String(), `==> batch done: ok=2 fail=1 total=3`)
	assertLine(t, out.String(), `admit ok=2 fail=1; attest ok=1 fail=0 skipped=1`)
	assertRow(t, out.String(), "good-one@0.0.0", "admit ok, attest ok")
	assertRow(t, out.String(), "plain-one@0.0.0", "admit ok, attest skipped (no level)")
	assertRow(t, out.String(), "broken-one", "admit FAIL (rc=1), attest not run")
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

// The batch fakes above copy what the admit reports, so on their own they
// cannot catch a lost assignment in the production admit. This drives the REAL
// runPublishAdmit (dry-run, so no POST) and checks that it fills the result the
// batch hands to attest: the bundle it packed, the auto version and the digest.
func TestRunPublishAdmitReportsWhatItPacked(t *testing.T) {
	_, key := batchFixture(t, "real-admit")
	var res admitResult
	var out, errBuf bytes.Buffer
	rc := runPublishAdmit(&out, &errBuf, publishAdmitArgs{name: "real-admit", identity: "id:probe@test",
		keyPath: key, dryRun: true, noCheckpoint: true, result: &res})
	if rc != 0 {
		t.Fatalf("admit dry run exited %d\n%s%s", rc, out.String(), errBuf.String())
	}
	if res.version != "0.0.0" {
		t.Errorf("result version = %q, want the auto version 0.0.0", res.version)
	}
	raw, err := os.ReadFile(res.bundlePath)
	if err != nil {
		t.Fatalf("result bundle path %q is not readable: %v", res.bundlePath, err)
	}
	d, _ := sha256Hex(raw)
	if res.digest != "sha256:"+d {
		t.Errorf("result digest %q is not the digest of %s (sha256:%s)", res.digest, res.bundlePath, d)
	}
	if !strings.Contains(out.String(), res.digest) {
		t.Errorf("result digest differs from the digest the plan printed:\n%s", out.String())
	}
}
