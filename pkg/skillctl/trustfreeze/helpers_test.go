package trustfreeze

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden")

// testTime is the fixed test clock default (SPEC-0470 TF05-AC7).
var testTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func testSubject() Subject {
	return Subject{ID: SubjectID("linux", "host-a.example"), OSFamily: "linux"}
}

func sampleArtifacts() []Artifact {
	obs := FormatTime(testTime)
	arts := []Artifact{
		{
			ID: "device/os", Type: "os", Scope: "device", Source: "common.identity",
			State: StateObserved,
			Attributes: map[string]string{
				"os_family": "linux", "arch": "amd64", "os_name": "Ubuntu",
				"os_version": "24.04", "os_build": "", "kernel_release": "6.8.0-generic",
			},
			Provenance:  Provenance{Method: "file", Confidence: ConfidenceProven, Sources: []string{"file:/etc/os-release", "command:uname -r"}, ObservedAt: obs},
			Sensitivity: SensitivityPublic,
		},
		{
			ID: "device/host", Type: "host", Scope: "device", Source: "common.identity",
			State:       StateObserved,
			Attributes:  map[string]string{"hostname": "host-a.example"},
			Provenance:  Provenance{Method: "runtime", Confidence: ConfidenceProven, Sources: []string{"runtime:os.Hostname"}, ObservedAt: obs},
			Sensitivity: SensitivityInternal,
		},
	}
	for i := range arts {
		d, err := ComputeArtifactDigest(arts[i])
		if err != nil {
			panic(err)
		}
		arts[i].Digest = d
	}
	SortArtifacts(arts)
	return arts
}

func sampleProbeResult(id string, status ProbeStatus) ProbeResult {
	r := ProbeResult{
		ProbeID:      id,
		ProbeVersion: "1",
		Status:       status,
		Support:      SupportRecord{Available: true},
		StartedAt:    FormatTime(testTime),
		DurationMS:   12,
		Privilege:    PrivilegeUser,
		Tools: []ToolInvocation{{
			Name: "uname", Path: "/usr/bin/uname", Args: []string{"-r"},
			ExitCode: 0, DurationMS: 3, StdoutBytes: 14,
		}},
		RawEvidence: []EvidenceRef{{Path: "evidence/" + id + "/stdout", Size: 0, SHA256: SHA256Hex(nil), Source: "stdout:uname"}},
	}
	if id == "common.identity" {
		r.NormalizedState = sampleArtifacts()
	}
	if status != StatusCaptured {
		r.Reason = "fixture"
		r.Error = &ProbeError{Class: string(status), Message: "fixture <status> & detail"}
	}
	return r
}

func sampleCaptureDoc(required []string, results []ProbeResult) CaptureDoc {
	return CaptureDoc{
		SchemaVersion: SchemaCapture,
		Kind:          KindCapture,
		Capture: CaptureMeta{
			StartedAt:   FormatTime(testTime),
			FinishedAt:  FormatTime(testTime.Add(1500 * time.Millisecond)),
			Tool:        CaptureTool,
			ToolVersion: "0.0.0-test",
			Profile:     ProfileRef{ID: "walking-skeleton", Version: "1", Digest: Digest([]byte("profile"))},
			Actor:       "id:alice@example",
		},
		Subject:      testSubject(),
		Completeness: ComputeCompleteness(required, results),
		Probes:       Summarize(results),
	}
}

func testHeader(kind Kind) ManifestHeader {
	return ManifestHeader{Kind: kind, BundleID: BundleID(kind, testTime, testSubject().ID), CreatedAt: testTime, Subject: testSubject()}
}

// writeCaptureFiles writes a complete capture bundle into w.
func writeCaptureFiles(t *testing.T, w *Writer, probeIDs ...string) {
	t.Helper()
	var results []ProbeResult
	for _, id := range probeIDs {
		r := sampleProbeResult(id, StatusCaptured)
		results = append(results, r)
		p, err := ProbeResultPath(id)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.WriteJSON(p, r); err != nil {
			t.Fatal(err)
		}
		if _, err := w.WriteEvidence("evidence/"+id+"/stdout", redact.Redacted{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.WriteJSON(CaptureFile, sampleCaptureDoc(probeIDs, results)); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteJSON(StateDeviceFile, StateDoc{Artifacts: sampleArtifacts()}); err != nil {
		t.Fatal(err)
	}
}

// newCapture writes a finalized capture bundle at parent/name.
func newCapture(t *testing.T, parent, name string, probeIDs ...string) (string, Manifest) {
	t.Helper()
	target := filepath.Join(parent, name)
	w, err := NewWriter(target, WriterOptions{Kind: KindCapture})
	if err != nil {
		t.Fatal(err)
	}
	writeCaptureFiles(t, w, probeIDs...)
	m, err := w.Finalize(testHeader(KindCapture))
	if err != nil {
		t.Fatal(err)
	}
	return target, m
}

// testSignature is a stand-in signature document; the core never checks it.
type testSignature struct {
	SchemaVersion string `json:"schema_version"`
	ContentDigest string `json:"content_digest"`
}

// newBaseline copies a capture into a baseline with an approval and a dummy
// signature document, the way seal does it.
func newBaseline(t *testing.T, captureDir string, capture Manifest, target string) Manifest {
	t.Helper()
	w, err := NewWriter(target, WriterOptions{Kind: KindBaseline})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range capture.Files {
		if err := w.CopyManifestedFile(captureDir, capture, f.Path); err != nil {
			t.Fatal(err)
		}
	}
	approval := map[string]string{"schema_version": SchemaApproval, "reviewer": "id:charlie@example", "capture_digest": capture.ContentDigest}
	if err := w.WriteJSON(ApprovalFile, approval); err != nil {
		t.Fatal(err)
	}
	m, err := w.FinalizeSigned(testHeader(KindBaseline), func(m Manifest) (any, error) {
		return testSignature{SchemaVersion: SchemaSignature, ContentDigest: m.ContentDigest}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func readManifestFile(t *testing.T, dir string) Manifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseManifest(b)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// rewriteManifest plays an attacker who can rewrite an unsigned manifest.
// With recompute the content digest is made consistent again, so only the
// targeted check can fire.
func rewriteManifest(t *testing.T, dir string, recompute bool, mutate func(*Manifest)) {
	t.Helper()
	m := readManifestFile(t, dir)
	mutate(&m)
	if recompute {
		d, err := ComputeContentDigest(m)
		if err != nil {
			t.Fatal(err)
		}
		m.ContentDigest = d
	}
	b, err := MarshalFile(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ManifestFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeRaw(t *testing.T, dir, rel string, b []byte) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func requireFailure(t *testing.T, res IntegrityResult, reason IntegrityReason, path string) {
	t.Helper()
	if res.OK {
		t.Fatalf("VerifyDir OK, want failure %s at %q", reason, path)
	}
	for _, f := range res.Failures {
		if f.Reason == reason && (path == "" || f.Path == path) {
			return
		}
	}
	t.Fatalf("no failure %s at %q; got %s", reason, path, describeFailures(res))
}

func describeFailures(res IntegrityResult) string {
	var sb strings.Builder
	for _, f := range res.Failures {
		sb.WriteString(string(f.Reason) + "@" + f.Path + " (" + f.Detail + "); ")
	}
	return sb.String()
}

// hashTree returns path -> content of every regular file below dir.
func hashTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(dir, p)
			out[filepath.ToSlash(rel)] = SHA256Hex(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
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
