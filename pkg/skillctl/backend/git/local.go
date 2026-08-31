package git

// SPEC-0359 D1: the `local://` scheme — a git skill registry on the LOCAL
// filesystem, no remote service required. The FOLDER is the registry.
//
//   local://<path>       a bare git repo (read-write): publish/list/pull/attest/revoke
//   local://<file.bundle> a git bundle (read-only snapshot): the offline "request" —
//                         a peer pulls + verifies from it, but cannot publish into it.
//
// It reuses the provider-neutral gitBackend verbatim (clone-then-write, the
// core.symlinks=false + lstat symlink defense, the SEC-M9 validators, the §7
// verifying pull) — only the remote is a path instead of an https URL. Because
// the wire format is frozen and byte-exact, "work locally, push to a central
// GitLab/GitHub later" is a plain `git push` (digests + signatures survive).

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
)

func init() {
	artifact.Register("local", openLocal)
}

// openLocal maps local://<path> to a gitBackend whose "remote" is a local path.
// The path must already exist (a bare repo made by `registry init`, or a .bundle);
// git treats both as valid clone sources.
func openLocal(spec string, opts artifact.OpenOptions) (artifact.Backend, error) {
	path, err := resolveLocalPath(spec)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("local: registry path %q not found — run `skillctl registry init --registry %s` first (or check the .bundle path): %w", path, spec, err)
	}
	b := newGitBackend(path, "local")
	b.applyCreds(opts) // no-op for local (no token), kept for symmetry
	return b, nil
}

// resolveLocalPath turns local://<path> into an absolute filesystem path.
// Accepts local:///abs/path, local://~/under-home, local://relative. Rejects a
// leading '-' (would be parsed as a git flag) and an empty path.
func resolveLocalPath(spec string) (string, error) {
	if !strings.HasPrefix(spec, "local://") {
		return "", fmt.Errorf("local: expected local://<path>, got %q", spec)
	}
	p := strings.TrimPrefix(spec, "local://")
	if p == "" {
		return "", fmt.Errorf("local: empty path in %q", spec)
	}
	if strings.HasPrefix(p, "-") {
		return "", fmt.Errorf("local: path may not start with '-' (%q)", p)
	}
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		p = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(p, "~"), "/"))
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return abs, nil
}

// InitLocalRegistry creates (or re-initializes, idempotently) a BARE git repo at
// the local:// path so it can be published into. Returns the resolved path.
// Bare is required: the backend pushes to it, and git refuses a push to the
// checked-out branch of a non-bare repo.
func InitLocalRegistry(spec string) (string, error) {
	path, err := resolveLocalPath(spec)
	if err != nil {
		return "", err
	}
	// `git init --bare` is safe to re-run on an existing bare repo.
	out, err := exec.Command("git", "-c", "init.defaultBranch=main", "init", "--bare", path).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git init --bare %s: %w: %s", path, err, strings.TrimSpace(string(out)))
	}
	return path, nil
}

// ExportBundle writes a single-file git bundle of the local registry's full ref
// set (--all: every branch + tag). The bundle is a portable, verifiable,
// READ-ONLY snapshot — the decentralized "pull request" / air-gap handoff: a peer
// runs `skillctl pull --registry local://<bundle>` and the §7 gauntlet verifies
// it against their own pinned trust roots.
func ExportBundle(spec, outPath string) error {
	path, err := resolveLocalPath(spec)
	if err != nil {
		return err
	}
	if outPath == "" {
		return fmt.Errorf("local: export needs an output path (--out)")
	}
	out, err := exec.Command("git", "-C", path, "bundle", "create", outPath, "--all").CombinedOutput()
	if err != nil {
		return fmt.Errorf("git bundle create %s: %w: %s", outPath, err, strings.TrimSpace(string(out)))
	}
	return nil
}
