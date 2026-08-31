package main

// `skillctl registry ls` + `skillctl registry show` — SPEC-0225 P2.1.
//
// Pure read paths against the ER1 `self` registry. No verification; ls/show
// just render the picture so the operator can decide what to pull. Verification
// happens in `pull`.

import (
	"context"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	"github.com/kamir/m3c-tools/pkg/skillctl/artifactauth"
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
	registrySpec := fs.String("registry", "self", "Registry: \"self\"/\"er1://…\" (ER1) or \"gitlab://host/group/proj\".")
	er1Target := fs.String("er1-target", envOr("ER1_TARGET", "prod"), "ER1 target.")
	er1Context := fs.String("er1-context", envOr("ER1_CONTEXT", "skills"), "ER1 context.")
	if err := fs.Parse(reorderFlagArgs(fs, args)); err != nil {
		return 2
	}
	if artifact.SchemeOf(*registrySpec) != "er1" {
		return runRegistryLsBackend(*registrySpec, *skillName, *latest, stdout, stderr)
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
		fmt.Fprintf(stdout, "%-32s %-10s %-72s %-8s %s\n", safeCell(s.Name), strOr(safeCell(s.LatestVersion), "?"), safeCell(s.LatestDigest), strOr(safeCell(s.LatestGovernance), "—"), status)
	}
	return 0
}

// runRegistryLsBackend renders `registry ls` from a SPEC-0356 artifact backend
// (gitlab:// / github://) via artifact.Open + Backend.List — the same view as the
// ER1 path, sourced from the git registry. Read-only.
func runRegistryLsBackend(spec, skillName string, latest bool, stdout, stderr io.Writer) int {
	be, err := artifact.Open(spec, artifact.OpenOptions{Creds: artifactauth.New()})
	if err != nil {
		fmt.Fprintf(stderr, "registry ls: open %s: %v\n", spec, err)
		return 1
	}
	defer be.Close()
	listing, err := be.List(context.Background(), artifact.ListFilter{Name: skillName, Latest: latest}, artifact.Page{})
	if err != nil {
		fmt.Fprintf(stderr, "registry ls: %v\n", err)
		return 1
	}
	if listing == nil || len(listing.Skills) == 0 {
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
		fmt.Fprintf(stdout, "%-32s %-10s %-72s %-8s %s\n", safeCell(s.Name), strOr(safeCell(s.LatestVersion), "?"), safeCell(s.LatestDigest), strOr(safeCell(s.LatestGovernance), "—"), status)
	}
	return 0
}

func runRegistryShow(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("registry show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	registrySpec := fs.String("registry", "self", "Registry: \"self\"/\"er1://…\" (ER1) or \"gitlab://host/group/proj\".")
	er1Target := fs.String("er1-target", envOr("ER1_TARGET", "prod"), "ER1 target.")
	er1Context := fs.String("er1-context", envOr("ER1_CONTEXT", "skills"), "ER1 context.")
	if err := fs.Parse(reorderFlagArgs(fs, args)); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "registry show: name or sha256:<hex> required")
		return 2
	}
	if artifact.SchemeOf(*registrySpec) != "er1" {
		return runRegistryShowBackend(*registrySpec, fs.Arg(0), stdout, stderr)
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

// runRegistryShowBackend renders `registry show` for a SPEC-0356 artifact backend
// (gitlab:// / github://) from its GovernanceLog event timeline — the git-native
// peer of ShowSkill, sourced from events/<digesthex>/ in the repo. Read-only; no
// verification (that is `pull`). Accepts a skill name or a sha256:<hex> digest.
func runRegistryShowBackend(spec, key string, stdout, stderr io.Writer) int {
	be, err := artifact.Open(spec, artifact.OpenOptions{Creds: artifactauth.New()})
	if err != nil {
		fmt.Fprintf(stderr, "registry show: open %s: %v\n", spec, err)
		return 1
	}
	defer be.Close()
	gl, ok := be.(artifact.GovernanceLog)
	if !ok {
		fmt.Fprintf(stderr, "registry show: backend %q exposes no signed event timeline\n", spec)
		return 1
	}
	ctx := context.Background()
	isDigest := strings.HasPrefix(key, "sha256:")

	var filter artifact.ListFilter
	if !isDigest {
		filter.Name = key
	}
	page, err := gl.Events(ctx, filter, artifact.Page{})
	if err != nil {
		fmt.Fprintf(stderr, "registry show: %v\n", err)
		return 1
	}
	evs := page.Events
	if isDigest {
		filtered := evs[:0:0]
		for _, e := range evs {
			if e.Digest == key {
				filtered = append(filtered, e)
			}
		}
		evs = filtered
	}
	if len(evs) == 0 {
		fmt.Fprintf(stdout, "(no events for %q in %s)\n", key, spec)
		return 0
	}

	// Header: name from the events; latest version/digest via Resolve (name query)
	// or the pinned digest (digest query); status = revoked if a revoke event exists.
	name := key
	for _, e := range evs {
		if n := envString(e.Envelope, "name"); n != "" {
			name = n
			break
		}
	}
	latestVer, latestDig := "", key
	if !isDigest {
		latestDig = ""
		if ref, rerr := be.Resolve(ctx, artifact.RefQuery{Name: key}); rerr == nil {
			latestVer, latestDig = ref.Version, ref.Digest
		}
	}
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].OccurredAt.After(evs[j].OccurredAt) })
	latestGov, revoked := "", false
	for _, e := range evs {
		if latestDig != "" && e.Digest != latestDig {
			continue
		}
		if e.Kind == artifact.KindAttest && latestGov == "" && e.Governance != "" {
			latestGov = e.Governance
		}
		if e.Kind == artifact.KindRevoke {
			revoked = true
		}
	}

	fmt.Fprintf(stdout, "skill:           %s\n", safeCell(name))
	fmt.Fprintf(stdout, "registry:        %s\n", spec) // operator-provided, trusted
	if latestVer != "" {
		fmt.Fprintf(stdout, "latest version:  %s\n", safeCell(latestVer))
	}
	fmt.Fprintf(stdout, "latest digest:   %s\n", strOr(safeCell(latestDig), "?"))
	fmt.Fprintf(stdout, "latest gov:      %s\n", strOr(safeCell(latestGov), "—"))
	if revoked {
		fmt.Fprintln(stdout, "status:          REVOKED")
	} else {
		fmt.Fprintln(stdout, "status:          ok")
	}
	fmt.Fprintln(stdout, "\nevents (newest first):")
	fmt.Fprintln(stdout, strings.Repeat("-", 80))
	for _, e := range evs {
		occ := "?"
		if !e.OccurredAt.IsZero() {
			occ = e.OccurredAt.UTC().Format("2006-01-02T15:04:05Z")
		}
		fmt.Fprintf(stdout, "  %-20s  %-9s  %s\n", occ, safeCell(string(e.Kind)), shortDigest(e.Digest))
		if e.Governance != "" {
			fmt.Fprintf(stdout, "    governance: %s\n", safeCell(e.Governance))
		}
		if e.Host != "" {
			fmt.Fprintf(stdout, "    host:       %s\n", safeCell(e.Host))
		}
		if e.Rationale != "" {
			fmt.Fprintf(stdout, "    rationale:  %s\n", safeCell(e.Rationale))
		}
	}
	return 0
}

func envString(env map[string]any, k string) string {
	if env == nil {
		return ""
	}
	s, _ := env[k].(string)
	return s
}

func shortDigest(d string) string {
	h := strings.TrimPrefix(safeCell(d), "sha256:")
	if len(h) > 12 {
		return "sha256:" + h[:12] + "…"
	}
	return "sha256:" + h
}

// safeCell strips control characters from a repo-sourced string and caps its
// length before it reaches a terminal. The git host is UNTRUSTED (SPEC-0356 §6):
// an event/bundle.json field (name, governance, host, rationale, digest) can
// carry ANSI escape sequences that rewrite earlier output — e.g. overwrite a
// printed `status: REVOKED` with `ok` in the operator's decide-what-to-pull view.
// Display-only defense; the authoritative pull gauntlet re-verifies independently
// of the terminal. Mirrors the install path's control-char rejection.
func safeCell(s string) string {
	const max = 200
	var b strings.Builder
	for _, r := range s {
		if r == '\t' {
			r = ' '
		}
		if unicode.IsControl(r) {
			continue // drop C0/C1 incl. ESC, CR, LF, backspace
		}
		if b.Len() >= max {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
