package screenshot

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// captureMock — test helper for mocking screencapture exec calls.
// (Uses different type name from clipboard_test.go's mockCommander.)
// ---------------------------------------------------------------------------

type captureMock struct {
	calls       []captureMockCall
	failOn      string // command name to fail on
	failErr     error
	createFiles bool // if true, create output files for screencapture
}

type captureMockCall struct {
	Name string
	Args []string
}

func (m *captureMock) Run(name string, args ...string) ([]byte, error) {
	m.calls = append(m.calls, captureMockCall{Name: name, Args: args})

	if m.failOn != "" && name == m.failOn {
		return nil, m.failErr
	}

	// If screencapture and createFiles, write a fake PNG at the last arg path.
	if name == "screencapture" && m.createFiles && len(args) > 0 {
		outPath := args[len(args)-1]
		os.MkdirAll(filepath.Dir(outPath), 0o755)
		os.WriteFile(outPath, []byte("FAKE-PNG-DATA"), 0o644)
	}

	return nil, nil
}

// seqMock returns different results for sequential calls.
type seqMock struct {
	calls     []captureMockCall
	responses []seqResponse
	callIdx   int
	outputDir string
}

type seqResponse struct {
	out []byte
	err error
}

func (s *seqMock) Run(name string, args ...string) ([]byte, error) {
	s.calls = append(s.calls, captureMockCall{Name: name, Args: args})
	idx := s.callIdx
	s.callIdx++

	// For screencapture calls, create the output file.
	if name == "screencapture" && len(args) > 0 {
		outPath := args[len(args)-1]
		os.MkdirAll(filepath.Dir(outPath), 0o755)
		os.WriteFile(outPath, []byte("FAKE-PNG"), 0o644)
	}

	// For osascript calls that contain the output dir (clipboard extract),
	// create the file at the path embedded in the script.
	if name == "osascript" && s.outputDir != "" {
		for _, a := range args {
			if strings.Contains(a, s.outputDir) {
				// Extract the POSIX file path from the AppleScript.
				// The script uses: POSIX file "/path/to/file.png"
				lines := strings.Split(a, "\n")
				for _, line := range lines {
					if strings.Contains(line, "POSIX file") {
						start := strings.Index(line, `"`)
						end := strings.LastIndex(line, `"`)
						if start >= 0 && end > start {
							p := line[start+1 : end]
							os.MkdirAll(filepath.Dir(p), 0o755)
							os.WriteFile(p, []byte("FAKE-PNG"), 0o644)
						}
					}
				}
				// Fallback: create a generic file if no path found in script.
				matches, _ := filepath.Glob(filepath.Join(s.outputDir, "m3c-clipboard-*.png"))
				if len(matches) == 0 {
					f := filepath.Join(s.outputDir, "m3c-clipboard-mock.png")
					os.MkdirAll(filepath.Dir(f), 0o755)
					os.WriteFile(f, []byte("FAKE-PNG"), 0o644)
				}
			}
		}
	}

	if idx < len(s.responses) {
		return s.responses[idx].out, s.responses[idx].err
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// Tests: buildArgs (screencapture CLI argument construction)
// ---------------------------------------------------------------------------

func TestBuildArgsFullScreen(t *testing.T) {
	args := buildArgs(Options{Mode: FullScreen, Silent: true}, "/tmp/out.png")
	for _, a := range args {
		if a == "-w" || a == "-s" {
			t.Fatalf("full-screen mode should not have %s flag", a)
		}
	}
	assertHas(t, args, "-x")
	assertHas(t, args, "-t")
	assertHas(t, args, "png")
	if args[len(args)-1] != "/tmp/out.png" {
		t.Fatalf("last arg should be output path, got %s", args[len(args)-1])
	}
}

func TestBuildArgsWindow(t *testing.T) {
	args := buildArgs(Options{Mode: Window}, "/tmp/out.png")
	assertHas(t, args, "-w")
}

func TestBuildArgsRegion(t *testing.T) {
	args := buildArgs(Options{Mode: Region, HideCursor: true}, "/tmp/out.png")
	assertHas(t, args, "-s")
	assertHas(t, args, "-C")
}

func TestBuildArgsDefaults(t *testing.T) {
	args := buildArgs(Options{}, "/tmp/out.png")
	for _, a := range args {
		if a == "-x" || a == "-C" {
			t.Fatalf("default options should not have %s flag", a)
		}
	}
}

func TestBuildArgsAlwaysHasPngFormat(t *testing.T) {
	args := buildArgs(Options{}, "/any/path.png")
	foundT := false
	for i, a := range args {
		if a == "-t" && i+1 < len(args) && args[i+1] == "png" {
			foundT = true
			break
		}
	}
	if !foundT {
		t.Fatal("expected -t png in args")
	}
}

func TestBuildArgsOutputPathAlwaysLast(t *testing.T) {
	for _, mode := range []Mode{FullScreen, Window, Region} {
		args := buildArgs(Options{Mode: mode, HideCursor: true, Silent: true}, "/some/file.png")
		last := args[len(args)-1]
		if last != "/some/file.png" {
			t.Errorf("mode %d: expected last arg to be output path, got %s", mode, last)
		}
	}
}

func TestBuildArgsCombinedFlags(t *testing.T) {
	args := buildArgs(Options{Mode: Region, HideCursor: true, Silent: true}, "/out.png")
	assertHas(t, args, "-s")
	assertHas(t, args, "-C")
	assertHas(t, args, "-x")
	assertHas(t, args, "-t")
	assertHas(t, args, "png")
	if args[len(args)-1] != "/out.png" {
		t.Fatal("last arg should be output path")
	}
}

// ---------------------------------------------------------------------------
// Tests: CaptureWith (exec mocking for screencapture)
// ---------------------------------------------------------------------------

func TestCaptureWithMockSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	mock := &captureMock{createFiles: true}

	path, err := CaptureWith(mock, Options{
		Mode:      Region,
		OutputDir: tmpDir,
		Filename:  "test-shot.png",
		Silent:    true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(path, "test-shot.png") {
		t.Errorf("expected path to end with test-shot.png, got %s", path)
	}

	if len(mock.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(mock.calls))
	}
	call := mock.calls[0]
	if call.Name != "screencapture" {
		t.Fatalf("expected screencapture, got %s", call.Name)
	}
	assertHas(t, call.Args, "-s") // Region mode
	assertHas(t, call.Args, "-x") // Silent
}

func TestCaptureWithMockWindowMode(t *testing.T) {
	tmpDir := t.TempDir()
	mock := &captureMock{createFiles: true}

	_, err := CaptureWith(mock, Options{
		Mode:      Window,
		OutputDir: tmpDir,
		Filename:  "win.png",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertHas(t, mock.calls[0].Args, "-w")
}

func TestCaptureWithMockFullScreen(t *testing.T) {
	tmpDir := t.TempDir()
	mock := &captureMock{createFiles: true}

	_, err := CaptureWith(mock, Options{
		Mode:      FullScreen,
		OutputDir: tmpDir,
		Filename:  "full.png",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, a := range mock.calls[0].Args {
		if a == "-w" || a == "-s" {
			t.Fatalf("full-screen should not have %s", a)
		}
	}
}

func TestCaptureWithMockFailure(t *testing.T) {
	tmpDir := t.TempDir()
	mock := &captureMock{
		failOn:  "screencapture",
		failErr: fmt.Errorf("exit status 1"),
	}

	_, err := CaptureWith(mock, Options{
		OutputDir: tmpDir,
		Filename:  "fail.png",
	})
	if err == nil {
		t.Fatal("expected error from failed screencapture")
	}
	if !strings.Contains(err.Error(), "screencapture failed") {
		t.Errorf("expected 'screencapture failed', got: %v", err)
	}
}

func TestCaptureWithUserCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	// Mock succeeds but doesn't create file (user pressed Escape).
	mock := &captureMock{createFiles: false}

	_, err := CaptureWith(mock, Options{
		OutputDir: tmpDir,
		Filename:  "cancelled.png",
	})
	if err == nil {
		t.Fatal("expected error for cancelled capture")
	}
	if !strings.Contains(err.Error(), "not created") {
		t.Errorf("expected 'not created', got: %v", err)
	}
}

func TestCaptureWithCreatesOutputDir(t *testing.T) {
	base := t.TempDir()
	nestedDir := filepath.Join(base, "deep", "nested")
	mock := &captureMock{createFiles: true}

	_, err := CaptureWith(mock, Options{
		OutputDir: nestedDir,
		Filename:  "nested.png",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(nestedDir); statErr != nil {
		t.Fatal("nested output dir should have been created")
	}
}

func TestCaptureWithDefaultFilename(t *testing.T) {
	tmpDir := t.TempDir()
	mock := &captureMock{createFiles: true}

	path, err := CaptureWith(mock, Options{OutputDir: tmpDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	base := filepath.Base(path)
	if !strings.HasPrefix(base, "m3c-screenshot-") {
		t.Errorf("expected default filename prefix 'm3c-screenshot-', got %s", base)
	}
	if !strings.HasSuffix(base, ".png") {
		t.Errorf("expected .png suffix, got %s", base)
	}
}

func TestCaptureWithHideCursorFlag(t *testing.T) {
	tmpDir := t.TempDir()
	mock := &captureMock{createFiles: true}

	_, err := CaptureWith(mock, Options{
		OutputDir:  tmpDir,
		Filename:   "cursor.png",
		HideCursor: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertHas(t, mock.calls[0].Args, "-C")
}

// ---------------------------------------------------------------------------
// Tests: CaptureClipboardFirstWith (clipboard-first with fallback)
// ---------------------------------------------------------------------------

func TestCaptureClipboardFirstWithImage(t *testing.T) {
	tmpDir := t.TempDir()

	// CaptureClipboardFirstWith calls:
	//   1. DetectClipboardImageWith → osascript "clipboard info"
	//   2. ExtractClipboardImageWith → DetectClipboardImageWith again → osascript "clipboard info"
	//   3. ExtractClipboardImageWith → extractClipboardPNG → osascript (extract script)
	// So we need 3 responses: detect, detect again, extract.
	mock := &seqMock{
		responses: []seqResponse{
			{out: []byte(`«class PNGf», 42318`)}, // 1st clipboard info (CaptureClipboardFirstWith)
			{out: []byte(`«class PNGf», 42318`)}, // 2nd clipboard info (ExtractClipboardImageWith)
			{out: nil},                             // extract script → success
		},
		outputDir: tmpDir,
	}

	path, err := CaptureClipboardFirstWith(mock, tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(filepath.Base(path), "clipboard") {
		t.Errorf("expected clipboard filename, got %s", filepath.Base(path))
	}

	// First call should be osascript for clipboard detection.
	if len(mock.calls) < 1 || mock.calls[0].Name != "osascript" {
		t.Error("first call should be osascript for clipboard check")
	}

	// No screencapture call should have been made.
	for _, c := range mock.calls {
		if c.Name == "screencapture" {
			t.Error("screencapture should not be called when clipboard has image")
		}
	}
}

func TestCaptureClipboardFirstFallsBack(t *testing.T) {
	tmpDir := t.TempDir()

	mock := &seqMock{
		responses: []seqResponse{
			{out: []byte(`«class utf8», 42, «class ut16», 86`)}, // no image
			{out: nil}, // screencapture success
		},
		outputDir: tmpDir,
	}

	path, err := CaptureClipboardFirstWith(mock, tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have fallen back to screencapture.
	foundScreencapture := false
	for _, c := range mock.calls {
		if c.Name == "screencapture" {
			foundScreencapture = true
			assertHas(t, c.Args, "-s") // Region
			assertHas(t, c.Args, "-x") // Silent
		}
	}
	if !foundScreencapture {
		t.Error("should have fallen back to screencapture")
	}

	base := filepath.Base(path)
	if strings.Contains(base, "clipboard") {
		t.Error("should not contain 'clipboard' in filename for interactive fallback")
	}
}

// ---------------------------------------------------------------------------
// Tests: Mode constants
// ---------------------------------------------------------------------------

func TestModeValues(t *testing.T) {
	if FullScreen != 0 {
		t.Error("FullScreen should be 0")
	}
	if Window != 1 {
		t.Error("Window should be 1")
	}
	if Region != 2 {
		t.Error("Region should be 2")
	}
}

// ---------------------------------------------------------------------------
// Tests: Real Capture creates output dir (conditional on macOS display)
// ---------------------------------------------------------------------------

func TestCaptureOutputDir(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "m3c-screenshot-test-dir")
	os.RemoveAll(tmpDir)
	defer os.RemoveAll(tmpDir)

	_, err := Capture(Options{
		OutputDir: tmpDir,
		Mode:      FullScreen,
	})
	// We expect an error (no display in CI), but the dir should exist.
	if err != nil {
		if _, statErr := os.Stat(tmpDir); statErr != nil {
			t.Fatal("output dir should have been created even on capture failure")
		}
	}
}

// ---------------------------------------------------------------------------
// Shared mock types (used by both screenshot_test.go and clipboard_test.go)
// ---------------------------------------------------------------------------

// mockCall records a single command invocation.
type mockCall struct {
	Name string
	Args []string
}

// mockResult holds the return values for a mocked command.
type mockResult struct {
	Output []byte
	Err    error
}

// mockCmd records calls and returns pre-configured results keyed by command name.
type mockCmd struct {
	calls   []mockCall
	results map[string]mockResult
	// writeFile, when non-empty, causes the mock to create a PNG file when
	// "screencapture" is invoked.
	writeFile string
}

func newMockCmd() *mockCmd {
	return &mockCmd{results: make(map[string]mockResult)}
}

// key builds a results lookup key from a command name.
func key(name string) string { return name }

func (m *mockCmd) Run(name string, args ...string) ([]byte, error) {
	m.calls = append(m.calls, mockCall{Name: name, Args: args})

	if name == "screencapture" && m.writeFile != "" && len(args) > 0 {
		outPath := args[len(args)-1]
		os.MkdirAll(filepath.Dir(outPath), 0o755)
		os.WriteFile(outPath, []byte("FAKE-PNG-DATA"), 0o644)
	}

	if r, ok := m.results[key(name)]; ok {
		return r.Output, r.Err
	}
	return nil, nil
}

// funcCommander wraps a function as a Commander.
type funcCommander struct {
	fn func(name string, args ...string) ([]byte, error)
}

func (f *funcCommander) Run(name string, args ...string) ([]byte, error) {
	return f.fn(name, args...)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func assertHas(t *testing.T, slice []string, val string) {
	t.Helper()
	for _, s := range slice {
		if s == val {
			return
		}
	}
	t.Fatalf("expected args to contain %q, got %v", val, slice)
}
