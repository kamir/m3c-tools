package trustfreeze

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestHomeRootViaLinkedParent: the home root reached through a symlinked
// parent is refused like its plain spelling, and --force deletes nothing in
// it. The string comparison alone let this through and removed user files.
func TestHomeRootViaLinkedParent(t *testing.T) {
	tmp := t.TempDir()
	homes := filepath.Join(tmp, "home")
	if err := os.Mkdir(homes, 0o700); err != nil {
		t.Fatal(err)
	}
	home, _ := newCapture(t, homes, "alice", "common.identity") // a manifest.json planted in the home root
	writeRaw(t, homes, "alice/precious.txt", []byte("user data"))
	link := filepath.Join(tmp, "l")
	if err := os.Symlink(homes, link); err != nil {
		t.Skipf("no symlink here: %v", err)
	}
	alias := filepath.Join(link, "alice")
	for _, target := range []string{alias, link} {
		if _, err := NewWriter(target, WriterOptions{Kind: KindCapture, Force: true, HomeRoot: home}); !errors.Is(err, ErrUnsafeTarget) {
			t.Fatalf("NewWriter(%s) = %v, want ErrUnsafeTarget (home root or ancestor by identity)", target, err)
		}
	}
	if _, err := os.Stat(filepath.Join(home, "precious.txt")); err != nil {
		t.Fatalf("user file gone: %v", err)
	}
}

// TestCommitRechecksTarget: a target that becomes the home root after
// NewWriter (here: the home root is given only at commit time through the
// options) is refused at commit, before anything is renamed or removed.
func TestCommitRechecksTarget(t *testing.T) {
	tmp := t.TempDir()
	target, _ := newCapture(t, tmp, "bundle", "common.identity")
	writeRaw(t, tmp, "bundle/precious.txt", []byte("user data"))
	w, err := NewWriter(target, WriterOptions{Kind: KindCapture, Force: true})
	if err != nil {
		t.Skipf("the planted file makes the target unreplaceable already: %v", err)
	}
	w.opts.HomeRoot = target
	writeCaptureFiles(t, w, "common.identity")
	if _, err := w.Finalize(testHeader(KindCapture)); !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("Finalize = %v, want ErrUnsafeTarget", err)
	}
	if _, err := os.Stat(filepath.Join(target, "precious.txt")); err != nil {
		t.Fatalf("user file gone: %v", err)
	}
}

// TestDarwinDataVolumeRefused: /System/Volumes/Data shares its device number
// with "/" on macOS, so it is refused by name and identity.
func TestDarwinDataVolumeRefused(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin only")
	}
	if _, err := os.Stat("/System/Volumes/Data"); err != nil {
		t.Skip("no data volume mount here")
	}
	if err := checkTargetLocation("/System/Volumes/Data", ""); !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("checkTargetLocation(/System/Volumes/Data) = %v, want ErrUnsafeTarget", err)
	}
}

// TestCanonicalPathWindowsDeviceSpellings pins spellings CanonicalPath
// already refuses: device names with any extension or case (stricter than
// Windows, on purpose), console names, a device name with a trailing dot,
// and the \\?\ and \\.\ prefixes.
func TestCanonicalPathWindowsDeviceSpellings(t *testing.T) {
	for _, p := range []string{"AUX", "prn.json", "COM0", "LPT0", "CONIN$", "Con.tar.gz", "nul.", `\\?\C:\x`, `\\.\COM1`, "evidence/a/con"} {
		if got, err := CanonicalPath(p); !errors.Is(err, ErrBadPath) {
			t.Errorf("CanonicalPath(%q) = %q, %v; want ErrBadPath", p, got, err)
		}
	}
}
