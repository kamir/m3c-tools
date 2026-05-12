package main

// `skillctl project` — resolve the PLM project context for the current
// working directory from the SPEC-0214 descriptor `.m3c/project.yaml`
// (falling back to a dir-slug when no descriptor is present). This is the
// client side of SPEC-0214: skills (e.g. /session-state, SPEC-0213) call this
// to learn project id + ER1 target/context without guessing.
//
//   skillctl project show                 print the resolved context (human)
//   skillctl project resolve [--field F]  print one field (script-friendly);
//                                         F ∈ project_id|name|client|status|
//                                              er1-target|er1-context|er1-url|
//                                              github-repo|source|descriptor-path|
//                                              commit-sha|channel:<kind>  (the ref
//                                              of the primary channel of <kind>)
//   skillctl project channels [--kind K]  list the v2 `channels:` block — one
//                                         "kind  role  ref  [label]" per line
//                                         (SPEC-0217); --kind filters by kind
//   skillctl project path                 print the descriptor path, or "(none)"
//
// Optional: -C <dir> resolves relative to <dir> instead of $PWD.

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/kamir/m3c-tools/pkg/m3cproject"
)

func runProject(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: skillctl project <show|resolve|channels|path> [-C dir] [--field name] [--kind kind]")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("project "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("C", "", "resolve relative to this directory instead of the current one")
	field := fs.String("field", "project_id", "field to print (resolve only)")
	kind := fs.String("kind", "", "channel kind filter (channels only)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	d, err := m3cproject.Load(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl project: %v\n", err)
		return 1
	}

	switch sub {
	case "show":
		printProjectContext(stdout, d)
		return 0
	case "path":
		if d.FoundPath == "" {
			fmt.Fprintln(stdout, "(none)")
		} else {
			fmt.Fprintln(stdout, d.FoundPath)
		}
		return 0
	case "channels":
		for _, ch := range d.Channels {
			if *kind != "" && !strings.EqualFold(ch.Kind, *kind) {
				continue
			}
			line := fmt.Sprintf("%-14s %-9s %s", ch.Kind, ch.Role, ch.Ref)
			if ch.Label != "" {
				line += "   # " + ch.Label
			}
			fmt.Fprintln(stdout, line)
		}
		return 0
	case "resolve":
		val, ok := projectField(d, *field)
		if !ok {
			fmt.Fprintf(stderr, "skillctl project resolve: unknown --field %q\n", *field)
			return 2
		}
		fmt.Fprintln(stdout, val)
		return 0
	default:
		fmt.Fprintf(stderr, "skillctl project: unknown subcommand %q\n", sub)
		return 2
	}
}

// primaryChannelRef returns the `ref` of the primary channel of `kind` (or the
// first channel of that kind if none is marked primary), or "".
func primaryChannelRef(d *m3cproject.Descriptor, kind string) string {
	var first string
	for _, ch := range d.Channels {
		if !strings.EqualFold(ch.Kind, kind) {
			continue
		}
		if strings.EqualFold(ch.Role, "primary") {
			return ch.Ref
		}
		if first == "" {
			first = ch.Ref
		}
	}
	return first
}

func projectField(d *m3cproject.Descriptor, name string) (string, bool) {
	switch strings.ToLower(name) {
	case "project_id", "project-id", "id":
		return d.Plm.ProjectID, true
	case "name":
		return d.Plm.Name, true
	case "client":
		return d.Plm.Client, true
	case "status":
		return d.Plm.Status, true
	case "project_type", "type":
		return d.Plm.ProjectType, true
	case "er1-target", "er1_target", "target":
		return d.EffectiveER1Target(), true
	case "er1-context", "er1_context", "context":
		return d.EffectiveER1Context(), true
	case "er1-url", "er1_url", "url":
		return d.ER1.URL, true
	case "github-repo", "github_repo", "repo":
		return d.Repo.GithubRepoURL, true
	case "source", "id-source", "project_id_source":
		return string(d.IDSource), true
	case "descriptor-path", "path":
		return d.FoundPath, true
	case "commit-sha", "descriptor-sha", "commit_sha":
		return d.CommitSHAFromGit(), true
	case "repo-root", "repo_root":
		return d.RepoRoot, true
	}
	// channel:<kind> — the ref of the primary channel of that kind (SPEC-0217 v2).
	if strings.HasPrefix(strings.ToLower(name), "channel:") {
		k := name[len("channel:"):]
		return primaryChannelRef(d, k), true
	}
	return "", false
}

func printProjectContext(w io.Writer, d *m3cproject.Descriptor) {
	src := string(d.IDSource)
	fmt.Fprintf(w, "project_id        %s   (source: %s)\n", d.Plm.ProjectID, src)
	if d.IDSource == m3cproject.SourceDescriptor {
		fmt.Fprintf(w, "name              %s\n", d.Plm.Name)
		fmt.Fprintf(w, "client            %s\n", d.Plm.Client)
		fmt.Fprintf(w, "status            %s   type: %s\n", d.Plm.Status, d.Plm.ProjectType)
	}
	fmt.Fprintf(w, "er1.target        %s\n", d.EffectiveER1Target())
	if d.ER1.URL != "" {
		fmt.Fprintf(w, "er1.url           %s   (informational; `target` is authoritative — ADR-0003)\n", d.ER1.URL)
	}
	fmt.Fprintf(w, "er1.context       %s\n", d.EffectiveER1Context())
	if d.Repo.GithubRepoURL != "" {
		fmt.Fprintf(w, "repo              %s   (sync path: %s)\n", d.Repo.GithubRepoURL, orDefault(d.Repo.SyncTargetPath, "NOTES"))
	}
	if len(d.Memory.TagFilter) > 0 || d.Memory.DisableFilter {
		fmt.Fprintf(w, "memory.tag_filter %v   disable_filter: %t\n", d.Memory.TagFilter, d.Memory.DisableFilter)
	}
	if len(d.Channels) > 0 {
		fmt.Fprintf(w, "channels          %d  (SPEC-0217 — `skillctl project channels` for the list):\n", len(d.Channels))
		for _, ch := range d.Channels {
			lbl := ""
			if ch.Label != "" {
				lbl = "  # " + ch.Label
			}
			fmt.Fprintf(w, "  - %-14s %-9s %s%s\n", ch.Kind, ch.Role, ch.Ref, lbl)
		}
	}
	if d.FoundPath != "" {
		fmt.Fprintf(w, "descriptor        %s\n", d.FoundPath)
		if sha := d.CommitSHAFromGit(); sha != "" {
			fmt.Fprintf(w, "descriptor_sha    %s\n", sha)
		}
		if d.Source.PLMDocUpdatedAt != "" && d.Source.PLMDocUpdatedAt != "null" {
			fmt.Fprintf(w, "plm_updated_at    %s   (compare against live PLM /projects/<id> to detect staleness — SPEC-0214 §6)\n", d.Source.PLMDocUpdatedAt)
		}
	} else {
		fmt.Fprintf(w, "descriptor        (none — falling back to dir-slug; run aims-core PLM with github_sync_enabled to get one)\n")
	}
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "ER1 credential resolves via Keychain -> Secret Manager -> env (ADR-0003), keyed by er1.target.")
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
