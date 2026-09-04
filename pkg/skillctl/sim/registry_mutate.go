package sim

// registry_mutate.go gives the adversary the one capability a signature cannot
// take away: control of the STORE. A hostile mirror, a compromised CI token or a
// malicious maintainer can delete an event, rename it, or reorder the tree. It
// cannot forge a signature, and the whole design rests on the difference.
//
// These mutations are why the corpus needs a real git registry rather than a
// mock: the interesting attacks are on the carrier, and a mock carrier proves
// nothing about the real one.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// mutateRegistry clones the bare registry, applies fn to every event file that
// belongs to the skill's digest, and pushes the result back. fn receives the
// clone root and the repo-relative path of one event file.
func (w *World) mutateRegistry(skill string, fn func(dir, evPath string) error) error {
	b := w.bundles[skill]
	if b == nil {
		return fmt.Errorf("sim: %s not packed", skill)
	}
	bare := strings.TrimPrefix(w.Registry, "local://")
	clone, err := os.MkdirTemp(w.Root, "mutate-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(clone)

	if out, err := git(clone, "clone", "--quiet", bare, "."); err != nil {
		return fmt.Errorf("clone: %v: %s", err, out)
	}
	evDir := filepath.Join("events", strings.TrimPrefix(b.digest, "sha256:"))
	entries, err := os.ReadDir(filepath.Join(clone, evDir))
	if err != nil {
		return fmt.Errorf("no events for %s: %w", skill, err)
	}
	touched := false
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		before := filepath.Join(evDir, e.Name())
		if err := fn(clone, before); err != nil {
			return err
		}
		touched = true
	}
	if !touched {
		return nil
	}
	if out, err := git(clone, "add", "-A"); err != nil {
		return fmt.Errorf("add: %v: %s", err, out)
	}
	// An empty commit means fn changed nothing; that is not an error, the
	// adversary simply had nothing to do here.
	if out, err := git(clone, "commit", "--quiet", "-m", "adversary: mutate registry"); err != nil {
		if strings.Contains(out, "nothing to commit") {
			return nil
		}
		return fmt.Errorf("commit: %v: %s", err, out)
	}
	if out, err := git(clone, "push", "--quiet", "origin", "HEAD"); err != nil {
		return fmt.Errorf("push: %v: %s", err, out)
	}
	return nil
}

func git(dir string, args ...string) (string, error) {
	// #nosec G204 -- git is the registry backend under test. Arguments are literals
	// from this file; the only variable is the clone directory the harness created.
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=sim", "GIT_AUTHOR_EMAIL=sim@local",
		"GIT_COMMITTER_NAME=sim", "GIT_COMMITTER_EMAIL=sim@local",
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TamperStoredBundle flips a byte in the .skb AS STORED IN THE REGISTRY, after a
// clean admit. This is the mirror-compromise case: the events are untouched and
// correctly signed, only the artifact was swapped. The digest gate is the only
// thing standing between the victim and the attacker's bytes.
func (w *World) TamperStoredBundle(skill string) error {
	b := w.bundles[skill]
	if b == nil {
		return fmt.Errorf("sim: %s not packed", skill)
	}
	bare := strings.TrimPrefix(w.Registry, "local://")
	clone, err := os.MkdirTemp(w.Root, "mutate-blob-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(clone)
	if out, err := git(clone, "clone", "--quiet", bare, "."); err != nil {
		return fmt.Errorf("clone: %v: %s", err, out)
	}
	blob := filepath.Join(clone, "skills", skill, b.version, "bundle.skb")
	if err := flipByte(blob, 200); err != nil {
		return err
	}
	if out, err := git(clone, "add", "-A"); err != nil {
		return fmt.Errorf("add: %v: %s", err, out)
	}
	if out, err := git(clone, "commit", "--quiet", "-m", "adversary: swap the stored artifact"); err != nil {
		return fmt.Errorf("commit: %v: %s", err, out)
	}
	if out, err := git(clone, "push", "--quiet", "origin", "HEAD"); err != nil {
		return fmt.Errorf("push: %v: %s", err, out)
	}
	return nil
}
