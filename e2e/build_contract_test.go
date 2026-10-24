package e2e

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func runE2EBuildProbe(t *testing.T, extraEnv []string, wantExit int, marker string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	cmd := exec.Command(executable, "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.v")
	cmd.Env = append(os.Environ(), "M3C_E2E_BUILD_PROBE="+t.Name(), "HOME="+home,
		"USERPROFILE="+home, "M3C_TOKEN_STORE=file", "M3C_ER1_KEYCHAIN=off")
	cmd.Env = append(cmd.Env, extraEnv...)
	out, err := cmd.CombinedOutput()
	exit := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("start probe: %v", err)
		}
		exit = exitErr.ExitCode()
	}
	if exit != wantExit || !strings.Contains(string(out), marker) {
		t.Fatalf("probe exit=%d, want=%d and marker %q: %s", exit, wantExit, marker, out)
	}
	if wantExit != 0 && strings.Contains(string(out), "--- SKIP:") {
		t.Fatalf("failed prerequisite/build became SKIP: %s", out)
	}
}

func TestE2E_BinaryBuildFailureIsFailure(t *testing.T) {
	if os.Getenv("M3C_E2E_BUILD_PROBE") == t.Name() {
		builtBinaryOnce.Do(func() { builtBinaryErr = errors.New("injected build failure") })
		BinaryPath(t)
		return
	}
	runE2EBuildProbe(t, nil, 1, "BinaryPath: injected build failure")
}

func TestE2E_AppBundlePrerequisiteContract(t *testing.T) {
	if os.Getenv("M3C_E2E_BUILD_PROBE") == t.Name() {
		t.Setenv("PATH", t.TempDir())
		requireAppBundlePrerequisites(t)
		return
	}
	runE2EBuildProbe(t, []string{"M3C_REQUIRE_APP_BUNDLE=1"}, 1, "required app bundle prerequisites missing")
	runE2EBuildProbe(t, []string{"M3C_REQUIRE_APP_BUNDLE=0"}, 0, "--- SKIP:")
}

func TestE2E_AppBundleBuildFailureIsFailure(t *testing.T) {
	if os.Getenv("M3C_E2E_BUILD_PROBE") == t.Name() {
		requireBuild(t, exec.Command(filepath.Join(t.TempDir(), "missing-build-tool")))
		return
	}
	runE2EBuildProbe(t, nil, 1, "required build failed")
}
