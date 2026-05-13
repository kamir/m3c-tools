package main

// `skillctl registry ls` + `skillctl registry show` — SPEC-0225 P2.1.
//
// Pure read paths against the ER1 `self` registry. No verification; ls/show
// just render the picture so the operator can decide what to pull. Verification
// happens in `pull`.

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

func runRegistry(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printRegistryUsage(stderr)
		return 2
	}
	switch args[0] {
	case "ls":
		return runRegistryLs(args[1:], stdout, stderr)
	case "show":
		return runRegistryShow(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		printRegistryUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "registry: unknown subcommand %q\n", args[0])
		printRegistryUsage(stderr)
		return 2
	}
}

func printRegistryUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: skillctl registry <ls|show> [flags]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  ls    [--latest] [--skill <name>] [--er1-target ...] [--er1-context ...]")
	fmt.Fprintln(w, "        List bundles in the `self` registry, grouped by skill.")
	fmt.Fprintln(w, "  show  <name | sha256:<hex>>  [--er1-target ...] [--er1-context ...]")
	fmt.Fprintln(w, "        Show the full event timeline for one skill or one digest.")
}

func runRegistryLs(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("registry ls", flag.ContinueOnError)
	fs.SetOutput(stderr)
	latest := fs.Bool("latest", false, "Collapse to the newest non-revoked digest per skill.")
	skillName := fs.String("skill", "", "Filter: only this skill.")
	er1Target := fs.String("er1-target", envOr("ER1_TARGET", "prod"), "ER1 target.")
	er1Context := fs.String("er1-context", envOr("ER1_CONTEXT", "skills"), "ER1 context.")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := resolveER1Config(*er1Target)
	if err != nil {
		fmt.Fprintf(stderr, "registry ls: %v\n", err)
		return 1
	}
	listing, err := registry.ListRegistry(cfg, *er1Context, registry.ListOpts{
		OnlySkill:  *skillName,
		OnlyLatest: *latest,
	})
	if err != nil {
		fmt.Fprintf(stderr, "registry ls: %v\n", err)
		return 1
	}
	if len(listing.Skills) == 0 {
		fmt.Fprintln(stdout, "(no skills in registry)")
		return 0
	}
	fmt.Fprintf(stdout, "%-32s %-10s %-72s %-8s %s\n", "skill", "version", "latest digest", "gov", "status")
	fmt.Fprintln(stdout, strings.Repeat("-", 132))
	for _, s := range listing.Skills {
		status := "ok"
		if s.IsRevoked {
			status = "REVOKED"
		}
		fmt.Fprintf(stdout, "%-32s %-10s %-72s %-8s %s\n", s.Name, strOr(s.LatestVersion, "?"), s.LatestDigest, strOr(s.LatestGovernance, "—"), status)
	}
	return 0
}

func runRegistryShow(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("registry show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	er1Target := fs.String("er1-target", envOr("ER1_TARGET", "prod"), "ER1 target.")
	er1Context := fs.String("er1-context", envOr("ER1_CONTEXT", "skills"), "ER1 context.")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "registry show: name or sha256:<hex> required")
		return 2
	}
	cfg, err := resolveER1Config(*er1Target)
	if err != nil {
		fmt.Fprintf(stderr, "registry show: %v\n", err)
		return 1
	}
	view, err := registry.ShowSkill(cfg, *er1Context, fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "registry show: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "skill:           %s\n", view.Name)
	fmt.Fprintf(stdout, "latest version:  %s\n", strOr(view.LatestVersion, "?"))
	fmt.Fprintf(stdout, "latest digest:   %s\n", view.LatestDigest)
	fmt.Fprintf(stdout, "latest gov:      %s\n", strOr(view.LatestGovernance, "—"))
	if view.IsRevoked {
		fmt.Fprintln(stdout, "status:          REVOKED")
	} else {
		fmt.Fprintln(stdout, "status:          ok")
	}
	fmt.Fprintln(stdout, "\nevents (newest first):")
	fmt.Fprintln(stdout, strings.Repeat("-", 80))
	for _, e := range view.Events {
		fmt.Fprintf(stdout, "  %-19s  %-9s  doc=%s\n", e.OccurredAt, e.Kind, e.DocID)
		if e.Governance != "" {
			fmt.Fprintf(stdout, "    governance: %s\n", e.Governance)
		}
		if e.Host != "" {
			fmt.Fprintf(stdout, "    host:       %s\n", e.Host)
		}
		if e.Transport != "" {
			fmt.Fprintf(stdout, "    transport:  %s\n", e.Transport)
		}
		if e.Rationale != "" {
			fmt.Fprintf(stdout, "    rationale:  %s\n", e.Rationale)
		}
	}
	return 0
}
