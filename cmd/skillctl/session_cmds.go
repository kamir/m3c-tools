package main

// `skillctl session` — the SPEC-0213 "session-state in ER1" model for callers
// outside Claude Code (CI jobs, the menubar app, scripts). The Go mirror of the
// `/session-state` skill; reuses pkg/session (which reuses pkg/er1 + pkg/m3cproject).
//
//   skillctl session open       [--session ID] [--project ID] [--intent "..."]
//                               [--continues CTX/DOC] [--er1-target T] [--er1-context C]
//   skillctl session checkpoint --session ID [--note "..."] [--auto] [--todos "..."]
//   skillctl session close      --session ID [--summary "..."] [--distill] [--todos "..."]
//   skillctl session list       [--project ID] [--host NAME] [--open-only] [--er1-target T]
//   skillctl session show       <session_id|doc_id> [--er1-target T]
//   skillctl session resume     [--project ID] [--host NAME] [--latest] [--er1-target T]
//
// -C <dir> resolves the project context relative to <dir> instead of $PWD.
// Writes go to /upload_2 at the descriptor-resolved ER1 target (ADR-0003 matrix);
// the ER1 credential resolves from ER1_API_KEY or the `aims-core-er1` Keychain item.

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/kamir/m3c-tools/pkg/session"
)

func runSession(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: skillctl session <open|checkpoint|close|resume|list|show> [flags]")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("session "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("C", "", "resolve the project context relative to this directory")
	sid := fs.String("session", "", "session id (the harness session_id; required for checkpoint/close)")
	project := fs.String("project", "", "PLM project id override (default: from .m3c/project.yaml)")
	er1Target := fs.String("er1-target", "", "ER1 target override (prod|local|stage|<url>)")
	er1Context := fs.String("er1-context", "", "ER1 context override")
	intent := fs.String("intent", "", "session intent (open only)")
	continues := fs.String("continues", "", "<ctx>/<doc_id> of a prior session-state item to thread the chain (open only)")
	note := fs.String("note", "", "checkpoint note prose")
	summary := fs.String("summary", "", "close summary (verbatim — your words)")
	auto := fs.Bool("auto", false, "checkpoint: build a git-diff/todo snapshot rather than prose (skips if nothing changed)")
	distill := fs.Bool("distill", false, "close: mark the close-checkpoint auto:generated (agent-authored summary, SPEC-0210)")
	todos := fs.String("todos", "", "open-items text for the checkpoint body")
	host := fs.String("host", "", "filter by host (list/resume)")
	openOnly := fs.Bool("open-only", false, "list: exclude closed sessions")
	latest := fs.Bool("latest", false, "resume: pick the newest session (default true when only one matches)")
	model := fs.String("model", "skillctl", "the agent/model recorded as opened_by")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	rest := fs.Args()

	switch sub {
	case "open":
		r, err := session.Open(session.OpenOpts{
			WorkingDir: *dir, SessionID: *sid, Project: *project,
			ER1Target: *er1Target, ER1Context: *er1Context,
			Intent: *intent, ContinuesFrom: *continues, Model: *model,
		})
		if err != nil {
			fmt.Fprintf(stderr, "skillctl session open: %v\n", err)
			return 1
		}
		state := "opened"
		if r.AlreadyExists {
			state = "already open"
		}
		fmt.Fprintf(stdout, "session %s — %s — ER1 doc %s — project %s (%s) — host %s%s — er1 %s\n",
			r.Ident.SessionID, state, r.DocID, r.Ident.Project, r.Ident.ProjectSrc, r.Ident.Host,
			deviceSuffix(r.Ident.Device), r.Ident.ER1Target)
		return 0

	case "checkpoint":
		if *sid == "" {
			fmt.Fprintln(stderr, "skillctl session checkpoint: --session is required")
			return 2
		}
		r, err := session.Checkpoint(session.CheckpointOpts{
			WorkingDir: *dir, SessionID: *sid, Project: *project,
			ER1Target: *er1Target, ER1Context: *er1Context,
			Note: *note, Auto: *auto, Todos: *todos,
		})
		if err != nil {
			fmt.Fprintf(stderr, "skillctl session checkpoint: %v\n", err)
			return 1
		}
		if r.Skipped {
			fmt.Fprintf(stdout, "session %s — checkpoint skipped: %s\n", *sid, r.SkipReason)
			return 0
		}
		fmt.Fprintf(stdout, "session %s — checkpoint ER1 doc %s (parent %s)\n", *sid, r.DocID, r.SessionDocID)
		return 0

	case "close":
		if *sid == "" {
			fmt.Fprintln(stderr, "skillctl session close: --session is required")
			return 2
		}
		// close = a final checkpoint carrying claude-code.checkpoint.close.
		// --summary is the user's verbatim wrap-up; --distill marks it auto:generated.
		noteText := *summary
		distilled := *distill
		if noteText == "" && !distilled {
			// bare close: a short auto wrap — treat as distill-lite
			noteText = "Session closed (auto wrap). Branch " + "" // body fills git state
			distilled = true
		}
		r, err := session.Checkpoint(session.CheckpointOpts{
			WorkingDir: *dir, SessionID: *sid, Project: *project,
			ER1Target: *er1Target, ER1Context: *er1Context,
			Note: noteText, Todos: *todos, Closing: true, Distilled: distilled,
		})
		if err != nil {
			fmt.Fprintf(stderr, "skillctl session close: %v\n", err)
			return 1
		}
		dirty := ""
		if r.Ident.Dirty {
			dirty = "  ⚠ uncommitted changes"
		}
		ahead := ""
		if r.Ident.Ahead > 0 {
			ahead = fmt.Sprintf("  ⚠ %d commit(s) not pushed", r.Ident.Ahead)
		}
		fmt.Fprintf(stdout, "session %s — closed — close-checkpoint ER1 doc %s (parent %s)%s%s\n",
			*sid, r.DocID, r.SessionDocID, dirty, ahead)
		return 0

	case "list":
		rows, err := session.List(session.ListOpts{
			WorkingDir: *dir, Project: *project, Host: *host,
			ER1Target: *er1Target, OpenOnly: *openOnly,
		})
		if err != nil {
			fmt.Fprintf(stderr, "skillctl session list: %v\n", err)
			return 1
		}
		if len(rows) == 0 {
			fmt.Fprintln(stdout, "(no session-state items)")
			return 0
		}
		for _, r := range rows {
			fmt.Fprintf(stdout, "%-22s  %s\n", r.DocID, summarizeTags(r.Tags))
		}
		return 0

	case "show":
		if len(rest) == 0 {
			fmt.Fprintln(stderr, "usage: skillctl session show <session_id|doc_id>")
			return 2
		}
		// minimal: list and filter — full flatten-with-checkpoints is the
		// /session-state skill's job (it has the richer ER1 read path).
		rows, err := session.List(session.ListOpts{WorkingDir: *dir, ER1Target: *er1Target})
		if err != nil {
			fmt.Fprintf(stderr, "skillctl session show: %v\n", err)
			return 1
		}
		needle := rest[0]
		for _, r := range rows {
			if r.DocID == needle || hasTagVal(r.Tags, "session:"+needle) {
				fmt.Fprintf(stdout, "doc_id: %s\ntags: %s\n", r.DocID, strings.Join(r.Tags, ", "))
				return 0
			}
		}
		fmt.Fprintf(stderr, "skillctl session show: no session matching %q\n", needle)
		return 1

	case "resume":
		rows, err := session.List(session.ListOpts{WorkingDir: *dir, Project: *project, Host: *host, ER1Target: *er1Target})
		if err != nil {
			fmt.Fprintf(stderr, "skillctl session resume: %v\n", err)
			return 1
		}
		if len(rows) == 0 {
			fmt.Fprintln(stdout, "(no prior session-state items for this project)")
			return 0
		}
		_ = latest // (newest-first ordering is server-dependent; we just print what we got)
		r := rows[0]
		fmt.Fprintf(stdout, "resume candidate — doc %s\ntags: %s\n", r.DocID, strings.Join(r.Tags, ", "))
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "To continue here, run:")
		fmt.Fprintf(stdout, "  skillctl session open --continues <ctx>/%s\n", r.DocID)
		fmt.Fprintln(stdout, "(or use the `/session-state resume` skill for a full briefing assembled from the checkpoint chain.)")
		return 0

	default:
		fmt.Fprintf(stderr, "skillctl session: unknown subcommand %q\n", sub)
		return 2
	}
}

func deviceSuffix(d string) string {
	if d == "" {
		return ""
	}
	return " (device " + d + ")"
}

// summarizeTags pulls the human-meaningful bits out of a session item's tags.
func summarizeTags(tags []string) string {
	var project, host, dev, sid, cw string
	closed := false
	for _, t := range tags {
		switch {
		case strings.HasPrefix(t, "project:"):
			project = t[len("project:"):]
		case strings.HasPrefix(t, "host:"):
			host = t[len("host:"):]
		case strings.HasPrefix(t, "device:"):
			dev = t[len("device:"):]
		case strings.HasPrefix(t, "session:"):
			sid = t[len("session:"):]
		case strings.HasPrefix(t, "cw:"):
			cw = t[len("cw:"):]
		case t == "claude-code.session.closed":
			closed = true
		}
	}
	state := "open"
	if closed {
		state = "closed"
	}
	at := host
	if dev != "" {
		at = host + "/" + dev
	}
	return fmt.Sprintf("%-7s  %-24s  @ %-16s  %s  session:%s", state, project, at, cw, sid)
}

func hasTagVal(tags []string, v string) bool {
	for _, t := range tags {
		if t == v {
			return true
		}
	}
	return false
}
