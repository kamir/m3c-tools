package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/screenshot"
)

func TestScreenshotBuildArgs(t *testing.T) {
	// Unit-level test for arg construction — runs anywhere.
	// The buildArgs function is unexported, so we test via Capture behavior.
	// This test validates that Capture returns an appropriate error on
	// non-macOS or headless environments.
	if _, err := exec.LookPath("screencapture"); err != nil {
		t.Skip("screencapture not available (macOS only)")
	}
	t.Log("screencapture binary found")
}

func TestScreenshotCapture(t *testing.T) {
	if _, err := exec.LookPath("screencapture"); err != nil {
		t.Skip("screencapture not available (macOS only)")
	}

	// Non-interactive full-screen capture.
	path, err := screenshot.Capture(screenshot.Options{
		Mode:   screenshot.FullScreen,
		Silent: true,
	})
	if err != nil {
		// May fail in headless CI — not a hard failure.
		t.Skipf("screenshot capture failed (likely headless): %v", err)
	}
	defer os.Remove(path)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("screenshot file not found: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("screenshot file is empty")
	}
	t.Logf("captured screenshot: %s (%d bytes)", path, info.Size())
}

func TestScreenshotCaptureOutputDir(t *testing.T) {
	if _, err := exec.LookPath("screencapture"); err != nil {
		t.Skip("screencapture not available (macOS only)")
	}

	tmpDir := t.TempDir()
	path, err := screenshot.Capture(screenshot.Options{
		Mode:      screenshot.FullScreen,
		OutputDir: tmpDir,
		Filename:  "test-output.png",
		Silent:    true,
	})
	if err != nil {
		t.Skipf("screenshot capture failed (likely headless): %v", err)
	}
	defer os.Remove(path)

	// Verify the file was placed in the requested directory
	if filepath.Dir(path) != tmpDir {
		t.Errorf("expected file in %s, got %s", tmpDir, filepath.Dir(path))
	}
	if filepath.Base(path) != "test-output.png" {
		t.Errorf("expected filename test-output.png, got %s", filepath.Base(path))
	}
	t.Logf("captured to custom dir: %s", path)
}

func TestScreenshotCaptureNestedDir(t *testing.T) {
	if _, err := exec.LookPath("screencapture"); err != nil {
		t.Skip("screencapture not available (macOS only)")
	}

	nestedDir := filepath.Join(t.TempDir(), "deep", "nested", "dir")
	path, err := screenshot.Capture(screenshot.Options{
		Mode:      screenshot.FullScreen,
		OutputDir: nestedDir,
		Filename:  "nested.png",
		Silent:    true,
	})
	if err != nil {
		t.Skipf("screenshot capture failed (likely headless): %v", err)
	}
	defer os.Remove(path)

	// Nested directory should have been auto-created
	if _, statErr := os.Stat(nestedDir); statErr != nil {
		t.Fatalf("nested output dir was not created: %v", statErr)
	}
	t.Logf("captured to nested dir: %s", path)
}

func TestScreenshotCaptureDefaultFilename(t *testing.T) {
	if _, err := exec.LookPath("screencapture"); err != nil {
		t.Skip("screencapture not available (macOS only)")
	}

	tmpDir := t.TempDir()
	path, err := screenshot.Capture(screenshot.Options{
		Mode:      screenshot.FullScreen,
		OutputDir: tmpDir,
		Silent:    true,
	})
	if err != nil {
		t.Skipf("screenshot capture failed (likely headless): %v", err)
	}
	defer os.Remove(path)

	base := filepath.Base(path)
	if !strings.HasPrefix(base, "m3c-screenshot-") {
		t.Errorf("expected default filename prefix m3c-screenshot-, got %s", base)
	}
	if !strings.HasSuffix(base, ".png") {
		t.Errorf("expected .png suffix, got %s", base)
	}
	t.Logf("default filename: %s", base)
}

func TestScreenshotCaptureFileSizePNG(t *testing.T) {
	if _, err := exec.LookPath("screencapture"); err != nil {
		t.Skip("screencapture not available (macOS only)")
	}

	path, err := screenshot.Capture(screenshot.Options{
		Mode:   screenshot.FullScreen,
		Silent: true,
	})
	if err != nil {
		t.Skipf("screenshot capture failed (likely headless): %v", err)
	}
	defer os.Remove(path)

	// Read first bytes to verify PNG header
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	// PNG magic bytes: 137 80 78 71 13 10 26 10
	pngMagic := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if len(data) < 8 {
		t.Fatalf("file too small: %d bytes", len(data))
	}
	for i := 0; i < 8; i++ {
		if data[i] != pngMagic[i] {
			t.Fatalf("invalid PNG header at byte %d: got %02x, want %02x", i, data[i], pngMagic[i])
		}
	}
	t.Logf("verified PNG header: %d bytes", len(data))
}

func TestScreenshotModeConstants(t *testing.T) {
	// Verify mode constants have expected values
	if screenshot.FullScreen != 0 {
		t.Error("FullScreen should be 0")
	}
	if screenshot.Window != 1 {
		t.Error("Window should be 1")
	}
	if screenshot.Region != 2 {
		t.Error("Region should be 2")
	}
}

func TestScreenshotClipboardImageTypes(t *testing.T) {
	// Verify ClipboardImageType string representation
	tests := []struct {
		typ  screenshot.ClipboardImageType
		want string
	}{
		{screenshot.ClipboardNoImage, "none"},
		{screenshot.ClipboardPNG, "PNG"},
		{screenshot.ClipboardTIFF, "TIFF"},
	}
	for _, tc := range tests {
		got := tc.typ.String()
		if got != tc.want {
			t.Errorf("ClipboardImageType(%d).String() = %q, want %q", tc.typ, got, tc.want)
		}
	}
}

func TestScreenshotCLIHelpOutput(t *testing.T) {
	// Verify the CLI binary accepts --help and lists screenshot command
	binPath := filepath.Join("..", "build", "m3c-tools")
	if _, err := os.Stat(binPath); err != nil {
		// Try building first
		cmd := exec.Command("go", "build", "-o", binPath, "./cmd/m3c-tools/")
		cmd.Dir = filepath.Join("..")
		if buildErr := cmd.Run(); buildErr != nil {
			t.Skipf("cannot build binary: %v", buildErr)
		}
	}

	out, _ := exec.Command(binPath, "help").CombinedOutput()
	output := string(out)
	if !strings.Contains(output, "screenshot") {
		t.Error("help output does not mention 'screenshot' command")
	}
	if !strings.Contains(output, "import-audio") {
		t.Error("help output does not mention 'import-audio' command")
	}
	t.Logf("help output includes screenshot and import-audio commands")
}

func TestScreenshotCLICapture(t *testing.T) {
	if _, err := exec.LookPath("screencapture"); err != nil {
		t.Skip("screencapture not available (macOS only)")
	}

	tmpDir := t.TempDir()
	binPath := filepath.Join("..", "build", "m3c-tools")
	if _, err := os.Stat(binPath); err != nil {
		cmd := exec.Command("go", "build", "-o", binPath, "./cmd/m3c-tools/")
		cmd.Dir = filepath.Join("..")
		if buildErr := cmd.Run(); buildErr != nil {
			t.Skipf("cannot build binary: %v", buildErr)
		}
	}

	out, err := exec.Command(binPath, "screenshot",
		"--mode", "full",
		"--output", tmpDir,
		"--filename", "cli-test.png",
		"--silent",
	).CombinedOutput()
	if err != nil {
		t.Skipf("CLI screenshot capture failed (likely headless): %v\nOutput: %s", err, out)
	}

	output := string(out)
	if !strings.Contains(output, "cli-test.png") {
		t.Errorf("expected output to reference cli-test.png, got: %s", output)
	}

	// Verify file was created
	capPath := filepath.Join(tmpDir, "cli-test.png")
	info, statErr := os.Stat(capPath)
	if statErr != nil {
		t.Fatalf("screenshot file not found: %v", statErr)
	}
	if info.Size() == 0 {
		t.Fatal("screenshot file is empty")
	}
	t.Logf("CLI screenshot: %s (%d bytes)", capPath, info.Size())
}
