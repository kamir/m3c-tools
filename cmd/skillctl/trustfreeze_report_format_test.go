package main

// FR-0472: --format of `trust-freeze report` names the format of the report
// FILE. It does not decide whether the status document on stdout is JSON;
// stdout of report is always a JSON document with result_class. Before
// FR-0472 the same flag carried both meanings, which these tests hold down.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tfReportStdoutJSON runs report with args and requires one JSON document with
// result_class on stdout, whatever --format says.
func tfReportStdoutJSON(t *testing.T, e *tfTestEnv, wantCode int, wantClass string, args ...string) map[string]any {
	t.Helper()
	code, out, errOut := e.run(args...)
	if code != wantCode {
		t.Fatalf("%v: exit %d, want %d\nstdout:\n%s\nstderr:\n%s", args, code, wantCode, out, errOut)
	}
	var doc map[string]any
	dec := json.NewDecoder(strings.NewReader(out))
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("%v: stdout is not a JSON document: %v\nstdout:\n%s\nstderr:\n%s", args, err, out, errOut)
	}
	if dec.More() {
		t.Fatalf("%v: stdout holds more than one JSON document:\n%s", args, out)
	}
	if got := doc["result_class"]; got != wantClass {
		t.Fatalf("%v: result_class %v, want %s\n%s", args, got, wantClass, out)
	}
	return doc
}

// TestTrustFreezeReportStdoutStaysJSON: the status document of report is JSON
// for every --format value and on every path, the usage-error path included.
// Before FR-0472 stdout was JSON only when --format itself said json, so a
// caller that asked for another report format silently lost the machine
// readable status, and a typo in another flag produced no usage_error
// document.
func TestTrustFreezeReportStdoutStaysJSON(t *testing.T) {
	e := newTFEnv(t)
	capDir := e.path("cap")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", capDir)
	outDir := e.path("out")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		t.Fatal(err)
	}

	t.Run("planned format", func(t *testing.T) {
		doc := tfReportStdoutJSON(t, e, exitUsage, tfResultUsage,
			"report", "--input", capDir, "--output", filepath.Join(outDir, "a.md"), "--format", "markdown")
		if s, _ := doc["error"].(string); !strings.Contains(s, "not implemented in this version") {
			t.Fatalf("error %q does not name the planned format", s)
		}
	})

	t.Run("unknown format", func(t *testing.T) {
		doc := tfReportStdoutJSON(t, e, exitUsage, tfResultUsage,
			"report", "--input", capDir, "--output", filepath.Join(outDir, "a.txt"), "--format", "postscript")
		if s, _ := doc["error"].(string); !strings.Contains(s, "postscript") {
			t.Fatalf("error %q does not name the rejected value", s)
		}
	})

	t.Run("unknown flag beside a non-json format", func(t *testing.T) {
		doc := tfReportStdoutJSON(t, e, exitUsage, tfResultUsage,
			"report", "--input", capDir, "--bogus", "--format", "markdown")
		if s, _ := doc["error"].(string); !strings.Contains(s, "bogus") {
			t.Fatalf("error %q does not name the unknown flag", s)
		}
	})

	t.Run("missing input beside a non-json format", func(t *testing.T) {
		tfReportStdoutJSON(t, e, exitUsage, tfResultUsage, "report", "--output", outDir, "--format", "markdown")
	})
}
