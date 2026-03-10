package screenshot

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Tests: classifyClipboardImage (pure parsing, no OS calls)
// ---------------------------------------------------------------------------

func TestClassifyClipboardImagePNG(t *testing.T) {
	info := `«class PNGf», 42318, «class TIFF», 93272, «class 8BPS», 94080`
	got := classifyClipboardImage(info)
	if got != ClipboardPNG {
		t.Fatalf("expected ClipboardPNG, got %v", got)
	}
}

func TestClassifyClipboardImageTIFFOnly(t *testing.T) {
	info := `«class TIFF», 93272, «class 8BPS», 94080`
	got := classifyClipboardImage(info)
	if got != ClipboardTIFF {
		t.Fatalf("expected ClipboardTIFF, got %v", got)
	}
}

func TestClassifyClipboardImageNoImage(t *testing.T) {
	info := `«class utf8», 42, «class ut16», 86`
	got := classifyClipboardImage(info)
	if got != ClipboardNoImage {
		t.Fatalf("expected ClipboardNoImage, got %v", got)
	}
}

func TestClassifyClipboardImageEmpty(t *testing.T) {
	got := classifyClipboardImage("")
	if got != ClipboardNoImage {
		t.Fatalf("expected ClipboardNoImage for empty input, got %v", got)
	}
}

func TestClassifyClipboardImagePNGPreferred(t *testing.T) {
	// When both PNG and TIFF are present, PNG should be preferred.
	info := `«class TIFF», 93272, «class PNGf», 42318`
	got := classifyClipboardImage(info)
	if got != ClipboardPNG {
		t.Fatalf("expected ClipboardPNG when both present, got %v", got)
	}
}

func TestClassifyClipboardImagePublicPNG(t *testing.T) {
	info := `public.png, 42318`
	got := classifyClipboardImage(info)
	if got != ClipboardPNG {
		t.Fatalf("expected ClipboardPNG for public.png, got %v", got)
	}
}

func TestClassifyClipboardImagePublicTIFF(t *testing.T) {
	info := `public.tiff, 93272`
	got := classifyClipboardImage(info)
	if got != ClipboardTIFF {
		t.Fatalf("expected ClipboardTIFF for public.tiff, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// Tests: ClipboardImageType.String
// ---------------------------------------------------------------------------

func TestClipboardImageTypeString(t *testing.T) {
	tests := []struct {
		typ  ClipboardImageType
		want string
	}{
		{ClipboardNoImage, "none"},
		{ClipboardPNG, "PNG"},
		{ClipboardTIFF, "TIFF"},
	}
	for _, tc := range tests {
		if got := tc.typ.String(); got != tc.want {
			t.Errorf("ClipboardImageType(%d).String() = %q, want %q", tc.typ, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests: DetectClipboardImageWith (mocked Commander)
// ---------------------------------------------------------------------------

func TestDetectClipboardImageWithPNG(t *testing.T) {
	mock := newMockCmd()
	mock.results[key("osascript")] = mockResult{
		Output: []byte(`«class PNGf», 42318, «class TIFF», 93272`),
	}

	got, err := DetectClipboardImageWith(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != ClipboardPNG {
		t.Fatalf("expected ClipboardPNG, got %v", got)
	}
}

func TestDetectClipboardImageWithTIFF(t *testing.T) {
	mock := newMockCmd()
	mock.results[key("osascript")] = mockResult{
		Output: []byte(`«class TIFF», 93272`),
	}

	got, err := DetectClipboardImageWith(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != ClipboardTIFF {
		t.Fatalf("expected ClipboardTIFF, got %v", got)
	}
}

func TestDetectClipboardImageWithNoImage(t *testing.T) {
	mock := newMockCmd()
	mock.results[key("osascript")] = mockResult{
		Output: []byte(`«class utf8», 42`),
	}

	got, err := DetectClipboardImageWith(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != ClipboardNoImage {
		t.Fatalf("expected ClipboardNoImage, got %v", got)
	}
}

func TestDetectClipboardImageWithError(t *testing.T) {
	mock := newMockCmd()
	mock.results[key("osascript")] = mockResult{
		Err: fmt.Errorf("osascript failed"),
	}

	_, err := DetectClipboardImageWith(mock)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "clipboard check failed") {
		t.Errorf("expected 'clipboard check failed', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests: ExtractClipboardImageWith (mocked Commander)
// ---------------------------------------------------------------------------

func TestExtractClipboardImageWithNoImage(t *testing.T) {
	mock := newMockCmd()
	mock.results[key("osascript")] = mockResult{
		Output: []byte(`«class utf8», 42`),
	}

	_, err := ExtractClipboardImageWith(mock, "")
	if err == nil {
		t.Fatal("expected error for no image")
	}
	if err.Error() != "no image data on clipboard" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractClipboardImageWithPNG(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "test.png")

	// ExtractClipboardImageWith calls DetectClipboardImageWith (1 osascript)
	// then extractClipboardPNG (1 osascript). Use funcCommander to handle both.
	callCount := 0
	mock := &funcCommander{fn: func(name string, args ...string) ([]byte, error) {
		callCount++
		if callCount == 1 {
			// Clipboard info query.
			return []byte(`«class PNGf», 42318`), nil
		}
		// Extract call: simulate writing the PNG file.
		_ = os.MkdirAll(filepath.Dir(outPath), 0o755)
		_ = os.WriteFile(outPath, []byte("FAKE-PNG-DATA"), 0o644)
		return nil, nil
	}}

	got, err := ExtractClipboardImageWith(mock, outPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != outPath {
		t.Fatalf("expected %s, got %s", outPath, got)
	}

	// Verify file exists and has content.
	info, err := os.Stat(got)
	if err != nil {
		t.Fatalf("output file not found: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("output file is empty")
	}
}

func TestExtractClipboardImageCreatesDir(t *testing.T) {
	base := t.TempDir()
	nestedDir := filepath.Join(base, "deep", "nested")
	outPath := filepath.Join(nestedDir, "test.png")

	callCount := 0
	mock := &funcCommander{fn: func(name string, args ...string) ([]byte, error) {
		callCount++
		if callCount == 1 {
			return []byte(`«class PNGf», 42318`), nil
		}
		// Extract: the dir should already be created by ExtractClipboardImageWith.
		os.WriteFile(outPath, []byte("FAKE-PNG-DATA"), 0o644)
		return nil, nil
	}}

	got, err := ExtractClipboardImageWith(mock, outPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != outPath {
		t.Fatalf("expected %s, got %s", outPath, got)
	}

	// Verify the nested directory was created.
	if _, err := os.Stat(nestedDir); err != nil {
		t.Fatalf("nested dir should have been created: %v", err)
	}
}

func TestExtractClipboardImageEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "empty.png")

	// Sequence mock: detect PNG, then "extract" writes an empty file.
	callCount := 0
	emptyMock := &funcCommander{fn: func(name string, args ...string) ([]byte, error) {
		callCount++
		if callCount == 1 {
			// Clipboard info.
			return []byte(`«class PNGf», 42318`), nil
		}
		// Extract: create an empty file.
		os.WriteFile(outPath, []byte{}, 0o644)
		return nil, nil
	}}

	_, err := ExtractClipboardImageWith(emptyMock, outPath)
	if err == nil {
		t.Fatal("expected error for empty file")
	}
	if err.Error() != "clipboard image file is empty" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractClipboardImageDefaultPath(t *testing.T) {
	// When outPath is empty, a default timestamped path is used.
	callCount := 0
	var createdPath string
	mock := &funcCommander{fn: func(name string, args ...string) ([]byte, error) {
		callCount++
		if callCount == 1 {
			return []byte(`«class PNGf», 42318`), nil
		}
		// Extract: find the path from the AppleScript and create the file.
		for _, a := range args {
			if strings.Contains(a, "m3c-clipboard-") {
				// Parse the path from the script.
				lines := strings.Split(a, "\n")
				for _, line := range lines {
					if strings.Contains(line, "POSIX file") {
						// Extract quoted path.
						start := strings.Index(line, `"`)
						end := strings.LastIndex(line, `"`)
						if start >= 0 && end > start {
							createdPath = line[start+1 : end]
							_ = os.MkdirAll(filepath.Dir(createdPath), 0o755)
							_ = os.WriteFile(createdPath, []byte("FAKE-PNG"), 0o644)
						}
					}
				}
			}
		}
		return nil, nil
	}}

	got, err := ExtractClipboardImageWith(mock, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(filepath.Base(got), "m3c-clipboard-") {
		t.Errorf("expected default filename with m3c-clipboard- prefix, got %s", filepath.Base(got))
	}
	if !strings.HasSuffix(got, ".png") {
		t.Errorf("expected .png suffix, got %s", got)
	}
	// Clean up.
	_ = os.Remove(got)
}
