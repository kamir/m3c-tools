package main

// FR-0472: the four guarantees of --output hold for every report format. They
// live in tfReportTarget and tfWriteNewFile and are format-independent by
// construction, which is exactly why they are measured per format: a later
// change that renders a format on its own path would lose them silently.
//
//	1. never over an existing file
//	2. never inside the input bundle
//	3. never inside any other trust-freeze bundle
//	4. mode 0600

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// tfReportFormatCases are the formats and the file name an --output directory
// gets for each.
var tfReportFormatCases = []struct {
	format string
	file   string
}{
	{"json", "report.json"},
	{"yaml", "report.yaml"},
	{"html", "report.html"},
}

func TestTrustFreezeReportOutputGuarantees(t *testing.T) {
	e := newTFEnv(t)
	capDir, otherDir := e.path("cap"), e.path("other")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", capDir)
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", otherDir)

	for _, tc := range tfReportFormatCases {
		t.Run(tc.format, func(t *testing.T) {
			dir := e.path("out-" + tc.format)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}

			// A directory gets the file name of the format, and the file has
			// mode 0600, because a report can carry the host name.
			tfReportStdoutJSON(t, e, exitOK, tfResultOK, "report", "--input", capDir, "--output", dir, "--format", tc.format)
			written := filepath.Join(dir, tc.file)
			fi, err := os.Stat(written)
			if err != nil {
				t.Fatalf("--output <directory> did not write %s: %v", tc.file, err)
			}
			if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
				t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
			}

			// 1. Never over an existing file: the same call again fails.
			doc := tfReportStdoutJSON(t, e, exitGeneric, tfResultExecution,
				"report", "--input", capDir, "--output", written, "--format", tc.format)
			if s, _ := doc["error"].(string); !strings.Contains(s, "file exists") {
				t.Fatalf("error %q does not say that the file exists", s)
			}

			// 2. Never inside the input bundle.
			doc = tfReportStdoutJSON(t, e, exitGeneric, tfResultExecution,
				"report", "--input", capDir, "--output", filepath.Join(capDir, tc.file), "--format", tc.format)
			if s, _ := doc["error"].(string); !strings.Contains(s, "must not be written inside the input bundle") {
				t.Fatalf("error %q does not refuse the input bundle", s)
			}

			// 3. Never inside another trust-freeze bundle.
			doc = tfReportStdoutJSON(t, e, exitGeneric, tfResultExecution,
				"report", "--input", capDir, "--output", filepath.Join(otherDir, tc.file), "--format", tc.format)
			if s, _ := doc["error"].(string); !strings.Contains(s, "must not be written inside the trust-freeze bundle") {
				t.Fatalf("error %q does not refuse the other bundle", s)
			}

			// The bundle stays untouched: a refused report writes nothing.
			tfMustNotExist(t, filepath.Join(capDir, tc.file))
			tfMustNotExist(t, filepath.Join(otherDir, tc.file))
		})
	}
}

// TestTrustFreezeReportOutputFollowsASymlinkIntoTheBundle: a target directory
// that is a symbolic link into the input bundle is refused as well. The code
// resolves the parent with EvalSymlinks; this test holds it there.
func TestTrustFreezeReportOutputFollowsASymlinkIntoTheBundle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a symbolic link needs a privilege on Windows")
	}
	e := newTFEnv(t)
	capDir := e.path("cap")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", capDir)
	link := e.path("link-into-bundle")
	if err := os.Symlink(capDir, link); err != nil {
		t.Fatal(err)
	}
	for _, tc := range tfReportFormatCases {
		doc := tfReportStdoutJSON(t, e, exitGeneric, tfResultExecution,
			"report", "--input", capDir, "--output", filepath.Join(link, tc.file), "--format", tc.format)
		s, _ := doc["error"].(string)
		if !strings.Contains(s, "must not be written inside the input bundle") &&
			!strings.Contains(s, "must not be written inside the trust-freeze bundle") {
			t.Fatalf("%s: error %q does not refuse the bundle behind the symbolic link", tc.format, s)
		}
		tfMustNotExist(t, filepath.Join(capDir, tc.file))
	}
}

// TestTrustFreezeReportOutputCaseInsensitiveBundlePath: where the file system
// does not distinguish upper and lower case, the bundle path is compared in
// lower case, so a differently spelled path is refused too. On a
// case-sensitive file system the differently spelled path is another path, and
// there is nothing to refuse.
func TestTrustFreezeReportOutputCaseInsensitiveBundlePath(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("the file system distinguishes upper and lower case here")
	}
	e := newTFEnv(t)
	capDir := e.path("cap")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", capDir)
	shouted := filepath.Join(filepath.Dir(capDir), strings.ToUpper(filepath.Base(capDir)))
	for _, tc := range tfReportFormatCases {
		doc := tfReportStdoutJSON(t, e, exitGeneric, tfResultExecution,
			"report", "--input", capDir, "--output", filepath.Join(shouted, strings.ToUpper(tc.file)), "--format", tc.format)
		s, _ := doc["error"].(string)
		if !strings.Contains(s, "must not be written inside the input bundle") &&
			!strings.Contains(s, "must not be written inside the trust-freeze bundle") {
			t.Fatalf("%s: error %q does not refuse the bundle spelled in upper case", tc.format, s)
		}
	}
}
