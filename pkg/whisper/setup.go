package whisper

import (
	"context"
	_ "embed"
	"io"
	"os/exec"
	"strings"
)

//go:embed setup-venv.sh
var setupVenvScript string

// SetupVenv installs the local Unix Whisper environment using the script embedded
// in the binary. A standalone release needs no adjacent files, and a script in
// the working directory or installation directory cannot replace this payload.
func SetupVenv(ctx context.Context, force bool, stdout, stderr io.Writer) error {
	args := []string{"-s", "--"}
	if force {
		args = append(args, "--force")
	}
	cmd := exec.CommandContext(ctx, "bash", args...)
	cmd.Stdin = strings.NewReader(setupVenvScript)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}
