package plaud

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestWindowsBrowserCandidatesRejectRelativeRoots(t *testing.T) {
	for _, base := range []string{"", ".", "relative", "../outside", `C:relative`} {
		t.Run(base, func(t *testing.T) {
			if candidates := windowsBrowserCandidates(func(string) string { return base }); len(candidates) != 0 {
				t.Fatalf("nonabsolute root %q produced executable candidates: %v", base, candidates)
			}
		})
	}
}

func TestWindowsBrowserCandidatesPreserveInstallPreference(t *testing.T) {
	root := t.TempDir()
	variables := map[string]string{
		"ProgramFiles":      filepath.Join(root, "programs"),
		"ProgramFiles(x86)": "relative-invalid",
		"LOCALAPPDATA":      filepath.Join(root, "local"),
	}
	want := []string{
		filepath.Join(root, "programs", "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(root, "local", "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(root, "programs", "Microsoft", "Edge", "Application", "msedge.exe"),
	}
	got := windowsBrowserCandidates(func(name string) string { return variables[name] })
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
}
