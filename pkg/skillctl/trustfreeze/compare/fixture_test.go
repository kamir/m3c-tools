package compare

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden")

// testTime is the fixed test clock default (SPEC-0470 TF05-AC7).
var testTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// fixture describes one synthetic capture. Every value is synthetic.
type fixture struct {
	at       time.Time
	host     string
	required []string
	results  []trustfreeze.ProbeResult
	arts     []trustfreeze.Artifact
}

// baseFixture is a complete walking-skeleton capture at time at. noise varies
// every volatile value (durations, pid, uptime, start times) without
// changing anything that counts as drift.
func baseFixture(at time.Time, noise int) fixture {
	obs := trustfreeze.FormatTime(at)
	arts := []trustfreeze.Artifact{
		artifact("device/os", "os", trustfreeze.StateObserved, trustfreeze.ConfidenceProven, obs, map[string]string{
			"os_family": "linux", "arch": "amd64", "os_name": "Ubuntu", "os_version": "24.04",
			"os_build": "", "kernel_release": "6.8.0-40-generic",
			"uptime_seconds": strconv.Itoa(1000 + 37*noise),
		}),
		artifact("device/host", "host", trustfreeze.StateObserved, trustfreeze.ConfidenceProven, obs, map[string]string{
			"hostname": "host-a.example", "boot_time": trustfreeze.FormatTime(at.Add(-time.Hour)),
		}),
		artifact("runtime/skillctl", "runtime", trustfreeze.StateObserved, trustfreeze.ConfidenceCorroborated, obs, map[string]string{
			"version": "0.0.0-test", "pid": strconv.Itoa(4242 + noise), "started_at": obs,
			"duration_ms": strconv.Itoa(12 + noise),
		}),
		artifact("runtime/python", "runtime", trustfreeze.StateDeclared, trustfreeze.ConfidenceReported, obs, map[string]string{
			"version": "3.12.3",
		}),
	}
	arts[1].Sensitivity = trustfreeze.SensitivityInternal
	return fixture{
		at:       at,
		host:     "host-a.example",
		required: []string{"common.identity"},
		results: []trustfreeze.ProbeResult{
			probeResult("common.identity", trustfreeze.StatusCaptured, "", at, int64(15+noise)),
		},
		arts: arts,
	}
}

func artifact(id, typ string, st trustfreeze.EvidenceState, conf trustfreeze.Confidence, obs string, attrs map[string]string) trustfreeze.Artifact {
	return trustfreeze.Artifact{
		ID: id, Type: typ, Scope: "device", Source: "common.identity", State: st,
		Attributes: attrs,
		Provenance: trustfreeze.Provenance{
			Method: "command", Confidence: conf, Sources: []string{"command:uname -r"}, ObservedAt: obs,
		},
		Sensitivity: trustfreeze.SensitivityPublic,
	}
}

func probeResult(id string, st trustfreeze.ProbeStatus, reason string, at time.Time, durMS int64) trustfreeze.ProbeResult {
	r := trustfreeze.ProbeResult{
		ProbeID: id, ProbeVersion: "1", Status: st, Reason: reason,
		Support:   trustfreeze.SupportRecord{Available: st == trustfreeze.StatusCaptured},
		StartedAt: trustfreeze.FormatTime(at), DurationMS: durMS, Privilege: trustfreeze.PrivilegeUser,
	}
	if st != trustfreeze.StatusCaptured && st != trustfreeze.StatusNotApplicable {
		r.Error = &trustfreeze.ProbeError{Class: string(st)}
	}
	return r
}

func (f fixture) subject() trustfreeze.Subject {
	return trustfreeze.Subject{ID: trustfreeze.SubjectID("linux", f.host), OSFamily: "linux"}
}

func (f fixture) captureDoc() trustfreeze.CaptureDoc {
	return trustfreeze.CaptureDoc{
		SchemaVersion: trustfreeze.SchemaCapture,
		Kind:          trustfreeze.KindCapture,
		Capture: trustfreeze.CaptureMeta{
			StartedAt:   trustfreeze.FormatTime(f.at),
			FinishedAt:  trustfreeze.FormatTime(f.at.Add(1500 * time.Millisecond)),
			Tool:        trustfreeze.CaptureTool,
			ToolVersion: "0.0.0-test",
			Profile:     trustfreeze.ProfileRef{ID: "walking-skeleton", Version: "1", Digest: trustfreeze.Digest([]byte("profile"))},
			Actor:       "id:alice@example",
		},
		Subject:      f.subject(),
		Completeness: trustfreeze.ComputeCompleteness(f.required, f.results),
		Probes:       trustfreeze.Summarize(f.results),
	}
}

// artifacts returns a copy of the artifacts with their core digests set,
// in the given order.
func (f fixture) artifacts(t testing.TB) []trustfreeze.Artifact {
	t.Helper()
	out := make([]trustfreeze.Artifact, len(f.arts))
	for i, a := range f.arts {
		d, err := trustfreeze.ComputeArtifactDigest(a)
		if err != nil {
			t.Fatal(err)
		}
		a.Digest = d
		out[i] = a
	}
	return out
}

// memBundle builds a verified bundle value without touching the disk. The
// manifest lists the canonical file bytes the writer would persist, so the
// content digest depends on the content.
func memBundle(t testing.TB, kind trustfreeze.Kind, f fixture) *trustfreeze.Bundle {
	t.Helper()
	doc := f.captureDoc()
	state := trustfreeze.StateDoc{Artifacts: f.artifacts(t)}
	files := []trustfreeze.FileEntry{}
	add := func(rel string, v any) {
		b, err := trustfreeze.MarshalFile(v)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, trustfreeze.FileEntry{Path: rel, Size: int64(len(b)), SHA256: trustfreeze.SHA256Hex(b)})
	}
	add(trustfreeze.CaptureFile, doc)
	for _, r := range f.results {
		p, err := trustfreeze.ProbeResultPath(r.ProbeID)
		if err != nil {
			t.Fatal(err)
		}
		add(p, r)
	}
	add(trustfreeze.StateDeviceFile, state)
	if kind == trustfreeze.KindBaseline {
		add(trustfreeze.ApprovalFile, testApproval(""))
	}
	sortEntries(files)
	m := trustfreeze.Manifest{
		SchemaVersion: trustfreeze.SchemaManifest,
		Kind:          kind,
		BundleID:      trustfreeze.BundleID(kind, f.at, f.subject().ID),
		CreatedAt:     trustfreeze.FormatTime(f.at),
		Subject:       f.subject(),
		BundlePolicy:  trustfreeze.BundlePolicy{RejectAdditions: true},
		Files:         files,
	}
	d, err := trustfreeze.ComputeContentDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	m.ContentDigest = d
	return &trustfreeze.Bundle{
		Manifest:  m,
		Integrity: trustfreeze.IntegrityResult{OK: true, Kind: kind, BundleID: m.BundleID, ContentDigest: d, Failures: []trustfreeze.IntegrityFailure{}},
		Capture:   &doc,
		State:     &state,
	}
}

func sortEntries(fs []trustfreeze.FileEntry) {
	for i := 1; i < len(fs); i++ {
		for j := i; j > 0 && fs[j].Path < fs[j-1].Path; j-- {
			fs[j], fs[j-1] = fs[j-1], fs[j]
		}
	}
}

// testApproval is a synthetic stand-in for seal's approval.json; compare and
// report never interpret it.
func testApproval(captureDigest string) map[string]any {
	return map[string]any{
		"schema_version": trustfreeze.SchemaApproval,
		"reviewer":       "id:charlie@example",
		"change_id":      "CHG-0001",
		"reason":         "synthetic fixture",
		"approved_at":    trustfreeze.FormatTime(testTime.Add(time.Hour)),
		"capture_digest": captureDigest,
	}
}

// diskBundle writes the fixture as a real bundle below parent/name with the
// core writer and reads it back with ReadBundle. A baseline gets a synthetic
// approval and a stand-in signature document (the core does not check it).
// Like the capture engine, it reports every artifact in the normalized_state
// of the probe named by the artifact's source (else the first probe), and
// state/device.json is their union sorted by id: ReadBundle refuses a bundle
// whose documents disagree.
func diskBundle(t testing.TB, parent, name string, kind trustfreeze.Kind, f fixture) *trustfreeze.Bundle {
	t.Helper()
	target := filepath.Join(parent, name)
	w, err := trustfreeze.NewWriter(target, trustfreeze.WriterOptions{Kind: kind})
	if err != nil {
		t.Fatal(err)
	}
	arts := f.artifacts(t)
	results := append([]trustfreeze.ProbeResult(nil), f.results...)
	for _, a := range arts {
		owner := 0
		for i, r := range results {
			if r.ProbeID == a.Source {
				owner = i
			}
		}
		if len(results) == 0 {
			t.Fatal("fixture: artifacts without a probe result")
		}
		results[owner].NormalizedState = append(results[owner].NormalizedState, a)
	}
	trustfreeze.SortArtifacts(arts)
	f.results = results
	for _, r := range f.results {
		p, err := trustfreeze.ProbeResultPath(r.ProbeID)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.WriteJSON(p, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.WriteJSON(trustfreeze.CaptureFile, f.captureDoc()); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteJSON(trustfreeze.StateDeviceFile, trustfreeze.StateDoc{Artifacts: arts}); err != nil {
		t.Fatal(err)
	}
	h := trustfreeze.ManifestHeader{Kind: kind, BundleID: trustfreeze.BundleID(kind, f.at, f.subject().ID), CreatedAt: f.at, Subject: f.subject()}
	if kind == trustfreeze.KindBaseline {
		if err := w.WriteJSON(trustfreeze.ApprovalFile, testApproval("sha256:"+string(bytes.Repeat([]byte("0"), 64)))); err != nil {
			t.Fatal(err)
		}
		_, err = w.FinalizeSigned(h, func(m trustfreeze.Manifest) (any, error) {
			return map[string]string{"schema_version": trustfreeze.SchemaSignature, "stand_in_for": m.ContentDigest}, nil
		})
	} else {
		_, err = w.Finalize(h)
	}
	if err != nil {
		t.Fatal(err)
	}
	b, err := trustfreeze.ReadBundle(target)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustCompare(t testing.TB, baseline, current *trustfreeze.Bundle) Diff {
	t.Helper()
	d, err := Compare(context.Background(), baseline, current, CompareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func mustFile(t testing.TB, v any) []byte {
	t.Helper()
	b, err := trustfreeze.MarshalFile(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
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

// kinds returns "<kind>:<artifact id, else probe id>" for the changes of d
// in order (subject_changed has neither).
func kinds(d Diff) []string {
	out := make([]string, 0, len(d.Changes))
	for _, c := range d.Changes {
		key := c.ArtifactID
		if key == "" {
			key = c.ProbeID
		}
		out = append(out, string(c.Kind)+":"+key)
	}
	return out
}
