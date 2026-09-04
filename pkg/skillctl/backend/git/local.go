package git

// SPEC-0359 D1: the `local://` scheme: a git skill registry on the LOCAL
// filesystem, no remote service required. The FOLDER is the registry.
//
//   local://<path>       a bare git repo (read-write): publish/list/pull/attest/revoke
//   local://<file.bundle> a git bundle (read-only snapshot): the offline "request":
//                         a peer pulls + verifies from it, but cannot publish into it.
//
// It reuses the provider-neutral gitBackend verbatim (clone-then-write, the
// core.symlinks=false + lstat symlink defense, the SEC-M9 validators, the §7
// verifying pull), only the remote is a path instead of an https URL. Because
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
		return nil, fmt.Errorf("local: registry path %q not found: run `skillctl registry init --registry %s` first (or check the .bundle path): %w", path, spec, err)
	}
	b := newGitBackend(path, "local")
	_ = b.applyCreds(opts) // no-op for local (filesystem path, no token, never http://), kept for symmetry
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
	if err := ensureInitTarget(path); err != nil {
		return "", err
	}
	// `git init --bare` is safe to re-run on an existing bare repo (idempotent).
	out, err := exec.Command("git", "-c", "init.defaultBranch=main", "init", "--bare", path).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git init --bare %s: %w: %s", path, err, strings.TrimSpace(string(out)))
	}
	return path, nil
}

// ensureInitTarget refuses to `git init --bare` over an existing NON-EMPTY,
// NON-REPO directory: the classic `local://~` / `local://.` dropped-subpath typo
// that would otherwise scatter bare-repo plumbing (HEAD/config/objects/refs)
// across $HOME or the cwd. Allowed: the path is absent, an empty dir, or already a
// git repo (so idempotent re-init still works).
func ensureInitTarget(path string) error {
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil // absent → git init creates it fresh
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("local: %q exists and is not a directory", path)
	}
	if isGitRepo(path) {
		return nil // already a registry → idempotent re-init
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("local: refusing to init a registry over the non-empty directory %q (it is not a git repo): point --registry at a new or empty path, e.g. local://%s", path, filepath.Join(path, "skills.git"))
	}
	return nil
}

// isGitRepo reports whether path is already a git repository: a bare repo (HEAD
// + objects/ at the root) or a working repo (a .git directory).
func isGitRepo(path string) bool {
	if _, err := os.Stat(filepath.Join(path, "objects")); err == nil {
		if _, err := os.Stat(filepath.Join(path, "HEAD")); err == nil {
			return true
		}
	}
	if fi, err := os.Stat(filepath.Join(path, ".git")); err == nil && fi.IsDir() {
		return true
	}
	return false
}

// ExportBundle writes a single-file git bundle of the local registry's full ref
// set (--all: every branch + tag). The bundle is a portable, verifiable,
// READ-ONLY snapshot: the decentralized "pull request" / air-gap handoff: a peer
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
	if strings.HasPrefix(outPath, "-") {
		// outPath is the only caller-controlled arg (--all is a fixed literal);
		// rejecting a leading '-' closes git-flag injection into bundle create.
		return fmt.Errorf("local: --out path may not start with '-' (%q)", outPath)
	}
	out, err := exec.Command("git", "-C", path, "bundle", "create", outPath, "--all").CombinedOutput()
	if err != nil {
		return fmt.Errorf("git bundle create %s: %w: %s", outPath, err, strings.TrimSpace(string(out)))
	}
	return nil
}
