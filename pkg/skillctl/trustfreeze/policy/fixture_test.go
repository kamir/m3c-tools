package policy

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/compare"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden")

// testTime is the fixed test clock default (SPEC-0470 TF05-AC7).
var testTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// capture is one synthetic capture: required probe ids, probe results and
// artifacts. All values are synthetic.
type capture struct {
	at       time.Time
	required []string
	results  []trustfreeze.ProbeResult
	arts     []trustfreeze.Artifact
}

// identityCapture is a complete walking-skeleton capture. noise varies the
// volatile values (durations, pid, uptime) only.
func identityCapture(at time.Time, osVersion string, noise int) capture {
	obs := trustfreeze.FormatTime(at)
	art := func(id, typ string, attrs map[string]string) trustfreeze.Artifact {
		return trustfreeze.Artifact{
			ID: id, Type: typ, Scope: "device", Source: "common.identity", State: trustfreeze.StateObserved,
			Attributes:  attrs,
			Provenance:  trustfreeze.Provenance{Method: "command", Confidence: trustfreeze.ConfidenceProven, Sources: []string{"command:uname -r"}, ObservedAt: obs},
			Sensitivity: trustfreeze.SensitivityPublic,
		}
	}
	return capture{
		at:       at,
		required: []string{"common.identity"},
		results:  []trustfreeze.ProbeResult{result("common.identity", trustfreeze.StatusCaptured, at, int64(10+noise))},
		arts: []trustfreeze.Artifact{
			art("device/os", "os", map[string]string{
				"os_family": "linux", "arch": "amd64", "os_name": "Ubuntu", "os_version": osVersion,
				"kernel_release": "6.8.0-40-generic", "uptime_seconds": strconv.Itoa(500 + 61*noise),
			}),
			art("device/host", "host", map[string]string{"hostname": "host-a.example"}),
			art("runtime/skillctl", "runtime", map[string]string{"version": "0.0.0-test", "pid": strconv.Itoa(4000 + noise)}),
		},
	}
}

func result(id string, st trustfreeze.ProbeStatus, at time.Time, durMS int64) trustfreeze.ProbeResult {
	return trustfreeze.ProbeResult{
		ProbeID: id, ProbeVersion: "1", Status: st,
		Support:   trustfreeze.SupportRecord{Available: st == trustfreeze.StatusCaptured},
		StartedAt: trustfreeze.FormatTime(at), DurationMS: durMS, Privilege: trustfreeze.PrivilegeUser,
	}
}

// bundle builds a verified bundle value in memory (the caller of compare is
// responsible for verification; here the fixture is trusted by construction).
func (c capture) bundle(t testing.TB, kind trustfreeze.Kind) *trustfreeze.Bundle {
	t.Helper()
	subject := trustfreeze.Subject{ID: trustfreeze.SubjectID("linux", "host-a.example"), OSFamily: "linux"}
	doc := trustfreeze.CaptureDoc{
		SchemaVersion: trustfreeze.SchemaCapture,
		Kind:          trustfreeze.KindCapture,
		Capture: trustfreeze.CaptureMeta{
			StartedAt: trustfreeze.FormatTime(c.at), FinishedAt: trustfreeze.FormatTime(c.at.Add(time.Second)),
			Tool: trustfreeze.CaptureTool, ToolVersion: "0.0.0-test",
			Profile: trustfreeze.ProfileRef{ID: "walking-skeleton", Version: "1", Digest: trustfreeze.Digest([]byte("profile"))},
		},
		Subject:      subject,
		Completeness: trustfreeze.ComputeCompleteness(c.required, c.results),
		Probes:       trustfreeze.Summarize(c.results),
	}
	arts := slices.Clone(c.arts)
	for i := range arts {
		arts[i].Attributes = cloneMap(arts[i].Attributes)
		d, err := trustfreeze.ComputeArtifactDigest(arts[i])
		if err != nil {
			t.Fatal(err)
		}
		arts[i].Digest = d
	}
	state := trustfreeze.StateDoc{Artifacts: arts}
	var files []trustfreeze.FileEntry
	for _, fv := range []struct {
		rel string
		v   any
	}{{trustfreeze.CaptureFile, doc}, {trustfreeze.StateDeviceFile, state}} {
		b, err := trustfreeze.MarshalFile(fv.v)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, trustfreeze.FileEntry{Path: fv.rel, Size: int64(len(b)), SHA256: trustfreeze.SHA256Hex(b)})
	}
	m := trustfreeze.Manifest{
		SchemaVersion: trustfreeze.SchemaManifest, Kind: kind,
		BundleID: trustfreeze.BundleID(kind, c.at, subject.ID), CreatedAt: trustfreeze.FormatTime(c.at),
		Subject: subject, BundlePolicy: trustfreeze.BundlePolicy{RejectAdditions: true}, Files: files,
	}
	d, err := trustfreeze.ComputeContentDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	m.ContentDigest = d
	return &trustfreeze.Bundle{
		Manifest:  m,
		Integrity: trustfreeze.IntegrityResult{OK: true, Kind: kind, ContentDigest: d, Failures: []trustfreeze.IntegrityFailure{}},
		Capture:   &doc,
		State:     &state,
	}
}

func cloneMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func diffOf(t testing.TB, baseline, current capture) compare.Diff {
	t.Helper()
	d, err := compare.Compare(context.Background(), baseline.bundle(t, trustfreeze.KindBaseline), current.bundle(t, trustfreeze.KindCapture), compare.CompareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func defaultPolicy(t testing.TB) Policy {
	t.Helper()
	p, err := DefaultPolicy()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func evaluate(t testing.TB, d compare.Diff, p Policy) Verdict {
	t.Helper()
	v, err := Evaluate(context.Background(), d, p)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func mustFile(t testing.TB, v any) []byte {
	t.Helper()
	b, err := trustfreeze.MarshalFile(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func findingKeys(v Verdict) []string {
	var out []string
	for _, f := range v.Findings {
		out = append(out, f.ID+"="+string(f.Severity)+"@"+f.RuleID)
	}
	return out
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// checkGolden compares got with testdata/name, tolerating a CRLF checkout of
// the golden file while requiring LF-only output.
func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	if bytes.Contains(got, []byte("\r")) {
		t.Fatalf("%s: output contains a carriage return", name)
	}
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -run %s -update to create it)", err, t.Name())
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}
