package screenshot

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ClipboardImageType represents the type of image found on the clipboard.
type ClipboardImageType int

const (
	// ClipboardNoImage indicates no image data on the clipboard.
	ClipboardNoImage ClipboardImageType = iota
	// ClipboardPNG indicates PNG image data on the clipboard.
	ClipboardPNG
	// ClipboardTIFF indicates TIFF image data on the clipboard.
	ClipboardTIFF
)

// String returns a human-readable label for the clipboard image type.
func (t ClipboardImageType) String() string {
	switch t {
	case ClipboardPNG:
		return "PNG"
	case ClipboardTIFF:
		return "TIFF"
	default:
		return "none"
	}
}

// DetectClipboardImage checks the macOS clipboard and returns the specific
// image type found. It distinguishes PNG from TIFF (unlike ClipboardHasImage
// which returns a simple bool). PNG is preferred when both are present.
func DetectClipboardImage() (ClipboardImageType, error) {
	return DetectClipboardImageWith(defaultCmd)
}

// DetectClipboardImageWith checks the clipboard using the given Commander.
func DetectClipboardImageWith(cmd Commander) (ClipboardImageType, error) {
	out, err := cmd.Run("osascript", "-e", "clipboard info")
	if err != nil {
		return ClipboardNoImage, fmt.Errorf("clipboard check failed: %w", err)
	}
	return classifyClipboardImage(string(out)), nil
}

// classifyClipboardImage inspects the output of `osascript -e 'clipboard info'`
// and returns the best image type found. PNG is preferred over TIFF.
func classifyClipboardImage(info string) ClipboardImageType {
	lower := strings.ToLower(info)
	// macOS clipboard info contains type descriptors like:
	//   «class PNGf», 42318
	//   «class TIFF», 93272
	//   public.png, public.tiff, etc.
	hasPNG := strings.Contains(lower, "pngf") ||
		strings.Contains(lower, "public.png") ||
		strings.Contains(lower, "«class png »")

	hasTIFF := strings.Contains(lower, "tiff") ||
		strings.Contains(lower, "public.tiff")

	// Prefer PNG (lossless, no conversion needed).
	if hasPNG {
		return ClipboardPNG
	}
	if hasTIFF {
		return ClipboardTIFF
	}
	return ClipboardNoImage
}

// ExtractClipboardImage extracts image data from the macOS clipboard and
// writes it as a PNG file. If outPath is empty, a timestamped file is
// created in os.TempDir(). Returns the path to the written file.
//
// The function checks for PNG data first (preferred, written directly).
// If only TIFF data is available, it extracts the TIFF and converts it
// to PNG using the macOS sips utility.
func ExtractClipboardImage(outPath string) (string, error) {
	return ExtractClipboardImageWith(defaultCmd, outPath)
}

// ExtractClipboardImageWith extracts clipboard image using the given Commander.
func ExtractClipboardImageWith(cmd Commander, outPath string) (string, error) {
	imgType, err := DetectClipboardImageWith(cmd)
	if err != nil {
		return "", err
	}
	if imgType == ClipboardNoImage {
		return "", fmt.Errorf("no image data on clipboard")
	}

	if outPath == "" {
		outPath = filepath.Join(os.TempDir(),
			fmt.Sprintf("m3c-clipboard-%s.png", time.Now().Format("20060102-150405")))
	}

	// Ensure parent directory exists.
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return "", fmt.Errorf("create output dir: %w", err)
	}

	switch imgType {
	case ClipboardPNG:
		if err := extractClipboardPNG(cmd, outPath); err != nil {
			return "", err
		}
	case ClipboardTIFF:
		if err := extractClipboardTIFF(cmd, outPath); err != nil {
			return "", err
		}
	}

	// Verify the file was written.
	info, err := os.Stat(outPath)
	if err != nil {
		return "", fmt.Errorf("clipboard image not written: %w", err)
	}
	if info.Size() == 0 {
		_ = os.Remove(outPath)
		return "", fmt.Errorf("clipboard image file is empty")
	}

	return outPath, nil
}

// extractClipboardPNG writes PNG clipboard data directly to outPath via AppleScript.
func extractClipboardPNG(cmd Commander, outPath string) error {
	script := fmt.Sprintf(`
set outFile to POSIX file %q
try
	set imgData to the clipboard as «class PNGf»
	set fRef to open for access outFile with write permission
	set eof fRef to 0
	write imgData to fRef
	close access fRef
on error
	error "no PNG image on clipboard"
end try`, outPath)

	if _, err := cmd.Run("osascript", "-e", script); err != nil {
		return fmt.Errorf("extract PNG from clipboard: %w", err)
	}
	return nil
}

// extractClipboardTIFF extracts TIFF data from the clipboard to a temp file,
// then converts it to PNG using the macOS sips utility.
func extractClipboardTIFF(cmd Commander, outPath string) error {
	// Write TIFF to a temp file first.
	tiffPath := outPath + ".tiff"
	defer func() { _ = os.Remove(tiffPath) }()

	script := fmt.Sprintf(`
set outFile to POSIX file %q
try
	set imgData to the clipboard as «class TIFF»
	set fRef to open for access outFile with write permission
	set eof fRef to 0
	write imgData to fRef
	close access fRef
on error
	error "no TIFF image on clipboard"
end try`, tiffPath)

	if _, err := cmd.Run("osascript", "-e", script); err != nil {
		return fmt.Errorf("extract TIFF from clipboard: %w", err)
	}

	// Convert TIFF → PNG using sips (built-in macOS image tool).
	if _, err := exec.LookPath("sips"); err != nil {
		return fmt.Errorf("sips not found: %w (macOS only)", err)
	}

	if _, err := cmd.Run("sips", "-s", "format", "png", tiffPath, "--out", outPath); err != nil {
		return fmt.Errorf("sips TIFF→PNG conversion failed: %w", err)
	}

	return nil
}
