package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// `skillctl drift`: what does this machine carry, and does it match the catalog
// (FR-0278).
//
// Why this exists. On 2026-09-15 two machines were compared by hand, with a
// throwaway shell script over 110 checksums. It found two artefacts that had
// silently diverged. A comparison nobody can repeat is not a check, it is an
// anecdote, and the next divergence would have gone unnoticed exactly as the
// last two did.
//
// What it can and cannot know, stated up front because the report is only
// useful if its limits are:
//
//   - An artefact installed through `pull` carries a provenance sidecar with
//     the digest it came from. That digest is comparable to the catalog and
//     yields a real verdict.
//   - An artefact that arrived some other way (copied, edited in place,
//     authored here) has NO sidecar. Then this command cannot say whether it
//     matches, only that nothing vouches for it. That is reported as its own
//     state and never silently folded into "fine".
//
// The second case is not an edge case. On the machine where artefacts are
// AUTHORED, it is the normal case, and saying so is the point.

type driftRow struct {
	Name   string
	Kind   string
	Local  string // digest from the sidecar, or a word saying why there is none
	Remote string // latest digest in the catalog
	State  string
}

const (
	driftCurrent     = "aktuell"
	driftStale       = "veraltet"
	driftUnvouched   = "ohne Nachweis"
	driftMissing     = "fehlt lokal"
	driftUncataloged = "nicht im Katalog"
)

func runDrift(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("drift", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		er1Target  = fs.String("er1-target", envOr("ER1_TARGET", "prod"), "ER1 target: prod | stage | local.")
		er1Context = fs.String("er1-context", envOr("ER1_CONTEXT", "skills"), "ER1 context to query.")
		kindFlag   = fs.String("kind", "", "Restrict to one kind: skill | agent. Empty compares both.")
		quiet      = fs.Bool("only-findings", false, "Print only rows that are not aktuell.")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := resolveER1Config(*er1Target)
	if err != nil {
		fmt.Fprintf(stderr, "drift: %v\n", err)
		return 1
	}
	listing, err := registry.ListRegistry(cfg, *er1Context, registry.ListOpts{OnlyKind: *kindFlag})
	if err != nil {
		fmt.Fprintf(stderr, "drift: %v\n", err)
		return 1
	}
	remote := map[string]registry.SkillView{}
	for _, s := range listing.Skills {
		remote[s.Kind+":"+s.Name] = s
	}

	local, err := scanLocal(*kindFlag)
	if err != nil {
		fmt.Fprintf(stderr, "drift: %v\n", err)
		return 1
	}

	rows := compareDrift(local, remote)

	host, _ := os.Hostname()
	fmt.Fprintf(stdout, "Maschine:  %s\n", host)
	fmt.Fprintf(stdout, "Katalog:   %s, %d Eintraege\n\n", *er1Context, len(remote))

	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ART\tNAME\tLOKAL\tKATALOG\tBEFUND")
	counts := map[string]int{}
	for _, r := range rows {
		counts[r.State]++
		if *quiet && r.State == driftCurrent {
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Kind, r.Name, r.Local, r.Remote, r.State)
	}
	_ = tw.Flush()

	fmt.Fprintf(stdout, "\n%d Artefakte verglichen:\n", len(rows))
	for _, k := range []string{driftCurrent, driftStale, driftUnvouched, driftMissing, driftUncataloged} {
		if counts[k] > 0 {
			fmt.Fprintf(stdout, "  %-18s %d\n", k, counts[k])
		}
	}

	if counts[driftUnvouched] > 0 {
		fmt.Fprintf(stdout, "\n%d Artefakte tragen keinen Herkunftsnachweis. Fuer sie sagt dieser Befehl\n", counts[driftUnvouched])
		fmt.Fprintln(stdout, "NICHT, dass sie stimmen, sondern nur, dass nichts fuer sie buergt. Auf der")
		fmt.Fprintln(stdout, "Maschine, auf der Artefakte entstehen, ist das der Normalfall.")
	}
	if counts[driftStale] > 0 || counts[driftMissing] > 0 || counts[driftUncataloged] > 0 {
		return 1
	}
	return 0
}

// scanLocal walks the two install locations and reads what vouches for each
// artefact.
func scanLocal(only string) (map[string]driftRow, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	out := map[string]driftRow{}

	if only == "" || only == skillbundle.KindSkill {
		dir := filepath.Join(home, ".claude", "skills")
		entries, err := os.ReadDir(dir)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			row := driftRow{Name: e.Name(), Kind: skillbundle.KindSkill, Local: driftUnvouched}
			if d := sidecarDigest(filepath.Join(dir, e.Name(), registry.ProvenanceSidecarName)); d != "" {
				row.Local = short(d)
			}
			out[row.Kind+":"+row.Name] = row
		}
	}

	if only == "" || only == skillbundle.KindAgent {
		dir := filepath.Join(home, ".claude", "agents")
		entries, err := os.ReadDir(dir)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
				continue
			}
			name := strings.TrimSuffix(e.Name(), ".md")
			row := driftRow{Name: name, Kind: skillbundle.KindAgent, Local: driftUnvouched}
			// An agent is a file, so its sidecar lives beside it in a dotted
			// directory (SPEC-0432 §14).
			if d := sidecarDigest(filepath.Join(dir, ".provenance", name+".json")); d != "" {
				row.Local = short(d)
			}
			out[row.Kind+":"+row.Name] = row
		}
	}
	return out, nil
}

func sidecarDigest(path string) string {
	side, err := registry.LoadProvenanceFile(path)
	if err != nil || side == nil {
		return ""
	}
	return side.BundleDigest
}

func short(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// compareDrift is pure, so the verdicts are testable without a registry or a
// home directory.
func compareDrift(local map[string]driftRow, remote map[string]registry.SkillView) []driftRow {
	var rows []driftRow
	seen := map[string]bool{}

	for key, row := range local {
		seen[key] = true
		rv, ok := remote[key]
		if !ok {
			row.Remote = "n/a"
			row.State = driftUncataloged
			rows = append(rows, row)
			continue
		}
		row.Remote = short(rv.LatestDigest)
		switch {
		case row.Local == driftUnvouched:
			row.State = driftUnvouched
		case row.Local == row.Remote:
			row.State = driftCurrent
		default:
			row.State = driftStale
		}
		rows = append(rows, row)
	}

	for key, rv := range remote {
		if seen[key] {
			continue
		}
		kind, name, _ := strings.Cut(key, ":")
		rows = append(rows, driftRow{
			Name: name, Kind: kind,
			Local: "<fehlt>", Remote: short(rv.LatestDigest), State: driftMissing,
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].State != rows[j].State {
			return rows[i].State < rows[j].State
		}
		if rows[i].Kind != rows[j].Kind {
			return rows[i].Kind < rows[j].Kind
		}
		return rows[i].Name < rows[j].Name
	})
	return rows
}
