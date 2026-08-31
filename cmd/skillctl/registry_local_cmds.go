package main

// `skillctl registry init` + `registry export` — SPEC-0359 local-folder registry.
// Manage a skill registry in a local folder with NO remote service; push to a
// central GitLab/GitHub later (plain `git push`), or hand off a verifiable
// snapshot (git bundle) for someone to review/request.

import (
	"flag"
	"fmt"
	"io"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	backendgit "github.com/kamir/m3c-tools/pkg/skillctl/backend/git"
)

func runRegistryInit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("registry init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	spec := fs.String("registry", "", "Local registry to create: local://<path> (a bare git repo).")
	if err := fs.Parse(reorderFlagArgs(fs, args)); err != nil {
		return 2
	}
	if artifact.SchemeOf(*spec) != "local" {
		fmt.Fprintf(stderr, "registry init: only local:// registries are created locally (got %q).\n  For gitlab://github:// create the project on the server; for ER1 use the self tenant.\n", *spec)
		return 2
	}
	path, err := backendgit.InitLocalRegistry(*spec)
	if err != nil {
		fmt.Fprintf(stderr, "registry init: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "initialized local skill registry: %s\n", path)
	fmt.Fprintf(stdout, "  publish:  skillctl publish <skill> --registry %s ...\n", *spec)
	fmt.Fprintf(stdout, "  pull:     skillctl pull --registry %s\n", *spec)
	fmt.Fprintf(stdout, "  push up:  git -C %s push --mirror <gitlab-or-github-url>\n", path)
	return 0
}

func runRegistryExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("registry export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	spec := fs.String("registry", "", "Local registry to export: local://<path>.")
	out := fs.String("out", "", "Output bundle file, e.g. skills.bundle.")
	if err := fs.Parse(reorderFlagArgs(fs, args)); err != nil {
		return 2
	}
	if artifact.SchemeOf(*spec) != "local" {
		fmt.Fprintf(stderr, "registry export: --registry must be local://<path> (got %q)\n", *spec)
		return 2
	}
	if *out == "" {
		fmt.Fprintln(stderr, "registry export: --out <file.bundle> is required")
		return 2
	}
	if err := backendgit.ExportBundle(*spec, *out); err != nil {
		fmt.Fprintf(stderr, "registry export: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "exported registry snapshot: %s\n", *out)
	fmt.Fprintf(stdout, "  hand it to a peer; they review + verify with:\n")
	fmt.Fprintf(stdout, "    skillctl registry ls --registry local://%s\n", *out)
	fmt.Fprintf(stdout, "    skillctl pull --registry local://%s   # §7 gauntlet verifies against THEIR trust roots\n", *out)
	return 0
}
