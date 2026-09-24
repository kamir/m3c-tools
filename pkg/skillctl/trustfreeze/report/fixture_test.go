package report

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
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/compare"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/policy"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden")

// testTime is the fixed test clock default (SPEC-0470 TF05-AC7).
var testTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

var testSubject = trustfreeze.Subject{ID: trustfreeze.SubjectID("linux", "host-a.example"), OSFamily: "linux"}

// writeCapture writes a synthetic capture (or, with kind baseline, the same
// content plus a synthetic approval and a stand-in signature) below
// parent/name through the core writer and reads it back.
func writeCapture(t testing.TB, parent, name string, kind trustfreeze.Kind, at time.Time, osVersion string, noise int) *trustfreeze.Bundle {
	t.Helper()
	obs := trustfreeze.FormatTime(at)
	arts := []trustfreeze.Artifact{
		{
			ID: "device/os", Type: "os", Scope: "device", Source: "common.identity", State: trustfreeze.StateObserved,
			Attributes: map[string]string{
				"os_family": "linux", "arch": "amd64", "os_name": "Ubuntu", "os_version": osVersion,
				"kernel_release": "6.8.0-40-generic", "uptime_seconds": strconv.Itoa(100 + noise),
			},
			Provenance:  trustfreeze.Provenance{Method: "file", Confidence: trustfreeze.ConfidenceProven, Sources: []string{"file:/etc/os-release"}, ObservedAt: obs},
			Sensitivity: trustfreeze.SensitivityPublic,
		},
		{
			ID: "device/host", Type: "host", Scope: "device", Source: "common.identity", State: trustfreeze.StateObserved,
			Attributes:  map[string]string{"hostname": "host-a.example"},
			Provenance:  trustfreeze.Provenance{Method: "runtime", Confidence: trustfreeze.ConfidenceProven, Sources: []string{"runtime:os.Hostname"}, ObservedAt: obs},
			Sensitivity: trustfreeze.SensitivityInternal,
		},
	}
	for i := range arts {
		d, err := trustfreeze.ComputeArtifactDigest(arts[i])
		if err != nil {
			t.Fatal(err)
		}
		arts[i].Digest = d
	}
	trustfreeze.SortArtifacts(arts)
	results := []trustfreeze.ProbeResult{
		{
			ProbeID: "common.identity", ProbeVersion: "1", Status: trustfreeze.StatusCaptured,
			Support: trustfreeze.SupportRecord{Available: true}, StartedAt: obs, DurationMS: int64(20 + noise),
			Privilege: trustfreeze.PrivilegeUser,
			Tools: []trustfreeze.ToolInvocation{{
				Name: "uname", Path: "/usr/bin/uname", Args: []string{"-r"}, ExitCode: 0, DurationMS: 3, StdoutBytes: 17,
			}},
			NormalizedState: arts,
		},
		{
			ProbeID: "linux.packages", ProbeVersion: "0", Status: trustfreeze.StatusUnsupported,
			Reason: trustfreeze.ReasonNotImplemented, Support: trustfreeze.SupportRecord{Available: false, Reason: trustfreeze.ReasonNotImplemented},
			StartedAt: obs, Privilege: trustfreeze.PrivilegeUser,
		},
	}
	doc := trustfreeze.CaptureDoc{
		SchemaVersion: trustfreeze.SchemaCapture,
		Kind:          trustfreeze.KindCapture,
		Capture: trustfreeze.CaptureMeta{
			StartedAt: obs, FinishedAt: trustfreeze.FormatTime(at.Add(time.Second)),
			Tool: trustfreeze.CaptureTool, ToolVersion: "0.0.0-test",
			Profile: trustfreeze.ProfileRef{ID: "walking-skeleton", Version: "1", Digest: trustfreeze.Digest([]byte("profile"))},
			Actor:   "id:alice@example",
		},
		Subject:      testSubject,
		Completeness: trustfreeze.ComputeCompleteness([]string{"common.identity"}, results),
		Probes:       trustfreeze.Summarize(results),
	}

	target := filepath.Join(parent, name)
	w, err := trustfreeze.NewWriter(target, trustfreeze.WriterOptions{Kind: kind})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		p, err := trustfreeze.ProbeResultPath(r.ProbeID)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.WriteJSON(p, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.WriteJSON(trustfreeze.CaptureFile, doc); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteJSON(trustfreeze.StateDeviceFile, trustfreeze.StateDoc{Artifacts: arts}); err != nil {
		t.Fatal(err)
	}
	h := trustfreeze.ManifestHeader{Kind: kind, BundleID: trustfreeze.BundleID(kind, at, testSubject.ID), CreatedAt: at, Subject: testSubject}
	if kind == trustfreeze.KindBaseline {
		approval := map[string]any{
			"schema_version": trustfreeze.SchemaApproval,
			"reviewer":       "id:charlie@example",
			"change_id":      "CHG-0001",
			"reason":         "synthetic fixture",
			"approved_at":    trustfreeze.FormatTime(at.Add(time.Hour)),
			"capture_digest": trustfreeze.Digest([]byte("synthetic capture manifest")),
			"identities": map[string]any{
				"captured_subject_id": testSubject.ID,
				"reviewer_id":         "id:charlie@example",
				"signing_key_id":      "ed25519:0123456789abcdef",
			},
		}
		if err := w.WriteJSON(trustfreeze.ApprovalFile, approval); err != nil {
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

// scenario writes a baseline and a changed capture below dir and returns the
// diff and the default-policy verdict.
func scenario(t testing.TB, dir string) (*trustfreeze.Bundle, *trustfreeze.Bundle, compare.Diff, policy.Verdict) {
	t.Helper()
	bl := writeCapture(t, dir, "baseline", trustfreeze.KindBaseline, testTime, "24.04", 0)
	cur := writeCapture(t, dir, "current", trustfreeze.KindCapture, testTime.Add(2*time.Hour), "24.10", 7)
	d, err := compare.Compare(context.Background(), bl, cur, compare.CompareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.DefaultPolicy()
	if err != nil {
		t.Fatal(err)
	}
	v, err := policy.Evaluate(context.Background(), d, p)
	if err != nil {
		t.Fatal(err)
	}
	return bl, cur, d, v
}

// writeDiffBundle stores a diff and its verdict as a diff bundle, the layout
// the CLI is expected to use (compare.DiffFile, policy.VerdictFile).
func writeDiffBundle(t testing.TB, dir string, d compare.Diff, v *policy.Verdict) *trustfreeze.Bundle {
	t.Helper()
	target := filepath.Join(dir, "diff")
	w, err := trustfreeze.NewWriter(target, trustfreeze.WriterOptions{Kind: trustfreeze.KindDiff})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteJSON(compare.DiffFile, d); err != nil {
		t.Fatal(err)
	}
	if v != nil {
		if err := w.WriteJSON(policy.VerdictFile, v); err != nil {
			t.Fatal(err)
		}
	}
	at := testTime.Add(3 * time.Hour)
	if _, err := w.Finalize(trustfreeze.ManifestHeader{Kind: trustfreeze.KindDiff, BundleID: trustfreeze.BundleID(trustfreeze.KindDiff, at, testSubject.ID), CreatedAt: at, Subject: testSubject}); err != nil {
		t.Fatal(err)
	}
	b, err := trustfreeze.ReadBundle(target)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustReport(t testing.TB, r Report, err error) []byte {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Marshal(r)
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
