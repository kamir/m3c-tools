package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuildAppBundle verifies that `make build-app` produces a valid macOS .app
// bundle with the expected directory structure, Info.plist, executable, and icon.
func TestBuildAppBundle(t *testing.T) {
	// Find the repo root (where the Makefile lives)
	repoRoot := findRepoRoot(t)

	// Run make build-app
	cmd := exec.Command("make", "build-app")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make build-app failed: %v\n%s", err, out)
	}
	t.Logf("make build-app output:\n%s", out)

	appBundle := filepath.Join(repoRoot, "build", "M3C-Tools.app")

	// 1. Verify .app bundle directory exists
	info, err := os.Stat(appBundle)
	if err != nil {
		t.Fatalf(".app bundle not found at %s: %v", appBundle, err)
	}
	if !info.IsDir() {
		t.Fatalf(".app bundle is not a directory: %s", appBundle)
	}

	// 2. Verify Contents/ directory structure
	requiredDirs := []string{
		"Contents",
		"Contents/MacOS",
		"Contents/Resources",
	}
	for _, dir := range requiredDirs {
		p := filepath.Join(appBundle, dir)
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("Missing directory %s: %v", dir, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s is not a directory", dir)
		}
	}

	// 3. Verify Info.plist exists and contains required keys
	plistPath := filepath.Join(appBundle, "Contents", "Info.plist")
	plistData, err := os.ReadFile(plistPath)
	if err != nil {
		t.Fatalf("Cannot read Info.plist: %v", err)
	}
	plist := string(plistData)

	requiredPlistKeys := []string{
		"CFBundleName",
		"CFBundleIdentifier",
		"CFBundleVersion",
		"CFBundleExecutable",
		"CFBundlePackageType",
		"LSUIElement",
		"com.kamir.m3c-tools",
		"m3c-tools",
	}
	for _, key := range requiredPlistKeys {
		if !strings.Contains(plist, key) {
			t.Errorf("Info.plist missing expected content: %s", key)
		}
	}
	t.Logf("Info.plist: %d bytes, all required keys present", len(plistData))

	// 4. Verify executable exists and is executable
	execPath := filepath.Join(appBundle, "Contents", "MacOS", "m3c-tools")
	execInfo, err := os.Stat(execPath)
	if err != nil {
		t.Fatalf("Executable not found: %v", err)
	}
	if execInfo.Size() == 0 {
		t.Error("Executable is empty")
	}
	// Check it's actually executable (has at least one execute bit)
	if execInfo.Mode()&0111 == 0 {
		t.Error("Executable does not have execute permission")
	}
	t.Logf("Executable: %s (%d bytes, mode=%s)", execPath, execInfo.Size(), execInfo.Mode())

	// 5. Verify icon file exists in Resources (either icon.png or m3c-tools.icns)
	resourcesDir := filepath.Join(appBundle, "Contents", "Resources")
	iconFound := false
	for _, iconName := range []string{"icon.png", "icon.icns", "m3c-tools.icns"} {
		iconPath := filepath.Join(resourcesDir, iconName)
		iconInfo, err := os.Stat(iconPath)
		if err == nil {
			if iconInfo.Size() == 0 {
				t.Errorf("Icon file %s is empty", iconName)
			} else {
				t.Logf("Icon: %s (%d bytes)", iconPath, iconInfo.Size())
			}
			iconFound = true
			break
		}
	}
	if !iconFound {
		t.Error("No icon file found in Resources/ (expected icon.png or m3c-tools.icns)")
	}

	// 6. Verify the executable can at least print help (basic sanity)
	helpCmd := exec.Command(execPath, "help")
	helpOut, err := helpCmd.CombinedOutput()
	if err != nil {
		t.Logf("Warning: help command returned error: %v (may be expected)", err)
	}
	if !strings.Contains(string(helpOut), "m3c-tools") {
		t.Error("Executable help output doesn't contain expected 'm3c-tools' string")
	}
	t.Logf("Help output: %d bytes", len(helpOut))
}

// findRepoRoot walks up from the test file's directory to find the Makefile.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	// Start from the working directory
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Cannot get working directory: %v", err)
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "Makefile")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("Cannot find repo root (Makefile) starting from %s", wd)
		}
		dir = parent
	}
}
