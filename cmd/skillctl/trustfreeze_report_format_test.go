package main

// FR-0472: --format of `trust-freeze report` names the format of the report
// FILE. It does not decide whether the status document on stdout is JSON;
// stdout of report is always a JSON document with result_class. Before
// FR-0472 the same flag carried both meanings, which these tests hold down.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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

// TestTrustFreezeReportWritesYAML: --format yaml writes the same projection as
// YAML, an existing directory gets report.yaml, and report_sha256 is the
// SHA-256 of the file that was written.
func TestTrustFreezeReportWritesYAML(t *testing.T) {
	e := newTFEnv(t)
	capDir := e.path("cap")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", capDir)
	dir := e.path("yaml-out")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Not e.runJSON: that appends --format json, which would win as the last
	// value on the command line.
	doc := tfReportStdoutJSON(t, e, exitOK, tfResultOK, "report", "--input", capDir, "--output", dir, "--format", "yaml")
	target := filepath.Join(dir, "report.yaml")
	raw, err := os.ReadFile(target) // #nosec G304 -- written by this test under t.TempDir()
	if err != nil {
		t.Fatalf("--format yaml did not write %s: %v", target, err)
	}
	sum := sha256.Sum256(raw)
	if got, _ := doc["report_sha256"].(string); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("report_sha256 %q is not the digest of the written file", got)
	}
	// The same fields as the JSON of the same bundle.
	jsonFile := e.path("report.json")
	e.runJSON(exitOK, tfResultOK, "report", "--input", capDir, "--output", jsonFile)
	jraw, err := os.ReadFile(jsonFile) // #nosec G304 -- written by this test under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	var fromYAML, fromJSON map[string]any
	if err := yaml.Unmarshal(raw, &fromYAML); err != nil {
		t.Fatalf("the report is not YAML: %v", err)
	}
	if err := json.Unmarshal(jraw, &fromJSON); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schema_version", "capture"} {
		if _, ok := fromYAML[key]; !ok {
			t.Fatalf("the YAML report has no %s: %v", key, fromYAML)
		}
	}
	if fromYAML["schema_version"] != fromJSON["schema_version"] {
		t.Fatalf("schema_version %v, want %v", fromYAML["schema_version"], fromJSON["schema_version"])
	}
	// Two runs of the same bundle give the same bytes.
	second := filepath.Join(dir, "again.yaml")
	tfReportStdoutJSON(t, e, exitOK, tfResultOK, "report", "--input", capDir, "--output", second, "--format", "yaml")
	again, err := os.ReadFile(second) // #nosec G304 -- written by this test under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("two YAML reports of the same bundle differ")
	}
	// And the status document on stdout stays JSON.
	tfReportStdoutJSON(t, e, exitOK, tfResultOK,
		"report", "--input", capDir, "--output", filepath.Join(dir, "third.yaml"), "--format", "yaml")
}

// TestTrustFreezeReportWritesHTML: --format html writes one self-contained
// page, an existing directory gets report.html, the page carries the guidance
// and the digests of the projection, and it references nothing from outside.
func TestTrustFreezeReportWritesHTML(t *testing.T) {
	e := newTFEnv(t)
	capDir := e.path("cap")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", capDir)
	dir := e.path("html-out")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	doc := tfReportStdoutJSON(t, e, exitOK, tfResultOK, "report", "--input", capDir, "--output", dir, "--format", "html")
	target := filepath.Join(dir, "report.html")
	raw, err := os.ReadFile(target) // #nosec G304 -- written by this test under t.TempDir()
	if err != nil {
		t.Fatalf("--format html did not write %s: %v", target, err)
	}
	sum := sha256.Sum256(raw)
	if got, _ := doc["report_sha256"].(string); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("report_sha256 %q is not the digest of the written file", got)
	}
	page := string(raw)
	for _, want := range []string{
		"<!DOCTYPE html>", "A record of what one machine looked like at one moment.",
		"skillctl trust-freeze verify --bundle", "Not on this page",
	} {
		if !strings.Contains(html.UnescapeString(page), want) {
			t.Fatalf("the page does not carry %q", want)
		}
	}
	// The content digest of the capture is on the page, in groups of eight.
	digest, _ := doc["input"].(map[string]any)
	cd, _ := digest["content_digest"].(string)
	if cd == "" {
		t.Fatal("the status document names no content digest")
	}
	if !strings.Contains(page, tfGroupEight(cd)) {
		t.Fatalf("the page does not carry the content digest %q in groups of eight", cd)
	}
	// Nothing is loaded from outside: no scheme, no script, no link, no font.
	for _, forbidden := range []string{"https://", "http://", "<script", "<link", "@import", "@font-face", "url("} {
		if strings.Contains(page, forbidden) {
			t.Fatalf("the page carries %q", forbidden)
		}
	}
	// The mode of the file is 0600, as for every other report format.
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
	}
}

// tfGroupEight is the grouping the page uses for a digest: the prefix, then the
// value in groups of eight characters.
func tfGroupEight(v string) string {
	prefix, rest := "", v
	if i := strings.Index(v, ":"); i >= 0 {
		prefix, rest = v[:i+1], v[i+1:]
	}
	var groups []string
	for len(rest) > 8 {
		groups = append(groups, rest[:8])
		rest = rest[8:]
	}
	if rest != "" {
		groups = append(groups, rest)
	}
	return prefix + strings.Join(groups, " ")
}
