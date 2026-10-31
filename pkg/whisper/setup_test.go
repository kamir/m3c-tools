package whisper

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSetupVenvStandaloneIgnoresExternalScripts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix setup uses bash")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash unavailable")
	}
	home := t.TempDir()
	bin := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	python := `#!/bin/bash
set -eu
case "$1" in
  --version) echo 'Python 3.11.2' ;;
  -m)
    test "$2" = venv
    mkdir -p "$3/bin"
    cp "$0" "$3/bin/python"
    cat > "$3/bin/pip" <<'PIP'
#!/bin/bash
set -eu
if [ "$1" = show ]; then
  echo 'Version: test-fixture'
elif [ "$1" = install ] && [ "$2" = openai-whisper ]; then
  printf '#!/bin/bash\necho fixture-whisper\n' > "$(dirname "$0")/whisper"
  chmod +x "$(dirname "$0")/whisper"
fi
PIP
    chmod +x "$3/bin/pip"
    ;;
  *) exit 9 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "python3"), []byte(python), 0700); err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cwd, "scripts"), 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(home, "external-script-ran")
	t.Setenv("SETUP_TEST_MARKER", marker)
	malicious := []byte("#!/bin/bash\ntouch \"$SETUP_TEST_MARKER\"\nexit 99\n")
	for _, name := range []string{"setup-venv.sh", "scripts/setup-venv.sh"} {
		if err := os.WriteFile(filepath.Join(cwd, name), malicious, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(cwd)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var output bytes.Buffer
	if err := SetupVenv(ctx, false, &output, &output); err != nil {
		t.Fatalf("standalone setup: %v\n%s", err, &output)
	}
	if _, err := os.Stat(VenvWhisperPath()); err != nil {
		t.Fatalf("setup did not install whisper: %v\n%s", err, &output)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("external setup script ran: %v", err)
	}
	if !strings.Contains(output.String(), "Setup complete!") {
		t.Fatalf("missing successful setup output:\n%s", &output)
	}

	// Existing environments survive a normal rerun, but --force rebuilds them.
	sentinel := filepath.Join(VenvDir(), "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := SetupVenv(ctx, false, &output, &output); err != nil {
		t.Fatalf("rerun: %v\n%s", err, &output)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("normal rerun removed existing environment: %v", err)
	}
	if err := SetupVenv(ctx, true, &output, &output); err != nil {
		t.Fatalf("forced setup: %v\n%s", err, &output)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("force did not rebuild environment: %v", err)
	}
	if _, err := os.Stat(VenvWhisperPath()); err != nil {
		t.Fatal(err)
	}
}

func TestSetupVenvPropagatesInstallationFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix setup uses bash")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash unavailable")
	}
	t.Setenv("HOME", t.TempDir())
	bin := t.TempDir()
	python := "#!/bin/bash\nif [ \"$1\" = --version ]; then echo 'Python 3.11.2'; else exit 23; fi\n"
	if err := os.WriteFile(filepath.Join(bin, "python3"), []byte(python), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	var output bytes.Buffer
	err := SetupVenv(context.Background(), false, &output, &output)
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 23 {
		t.Fatalf("error = %v, want installer exit 23\n%s", err, &output)
	}
}
