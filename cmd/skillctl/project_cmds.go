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
//                                              commit-sha
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
		fmt.Fprintln(stderr, "usage: skillctl project <show|resolve|path> [-C dir] [--field name]")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("project "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("C", "", "resolve relative to this directory instead of the current one")
	field := fs.String("field", "project_id", "field to print (resolve only)")
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
