// envreport_cmds.go: das Verb `skillctl envreport` (SPEC-0428 T-06).
//
// Dieses Verb ist die einzige Stelle, an der ein Skill-Env-Report entstehen
// und abgelegt werden kann. Zwei Entscheidungen darin sind bewusst unbequem:
//
//  1. TROCKENLAUF IST DIE VORGABE. Ohne --schreiben wird nichts abgelegt, nur
//     gezeigt. Die uebliche Vorgabe waere umgekehrt; sie ist hier falsch, weil
//     ein Fehlgriff ein Personendatum erzeugt und nicht bloss eine Datei.
//  2. DIE EINWILLIGUNG IST EIN PFLICHTFELD AUF DER BEFEHLSZEILE. Es gibt
//     keinen Vorgabewert und kein "spaeter nachtragen". Wer beobachtet wird,
//     muss es wissen (SPEC-0428 Grenze 3), und die Angabe steht deshalb dort,
//     wo sie jemand tippt.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/audit"
	"github.com/kamir/m3c-tools/pkg/skillctl/envreport"
	"github.com/kamir/m3c-tools/pkg/skillctl/scanner"
)

const envreportUsage = `skillctl envreport - erhebt einen Skill-Env-Report und zeigt oder legt ihn ab.

  skillctl envreport --mandant <id> --prinzipal <id> [flags]

Pflichtangaben:
  --mandant <id>          Mandant der Umgebung
  --prinzipal <id>        Person, um deren Umgebung es geht
  --einwilligung-art      "selbst" | "eingesetzt"
  --einwilligung-beleg    woran die Zustimmung oder Benachrichtigung haengt
  --aufbewahrung-tage <n> Aufbewahrungsfrist in Tagen (kein Vorgabewert)

Optional:
  --source claude|user|plugins|all   Erhebungsquelle (Vorgabe: all)
  --json                             Bericht als JSON statt als Tabelle
  --schreiben                        LEGT AB. Ohne dieses Flag: Trockenlauf.

Der Trockenlauf ist die Vorgabe. Ein Fehlgriff erzeugt hier ein Personendatum
und nicht bloss eine Datei.
`

func runEnvreport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("envreport", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, envreportUsage) }

	mandant := fs.String("mandant", "", "Mandant der Umgebung")
	prinzipal := fs.String("prinzipal", "", "Person, um deren Umgebung es geht")
	art := fs.String("einwilligung-art", "", `"selbst" oder "eingesetzt"`)
	beleg := fs.String("einwilligung-beleg", "", "woran die Einwilligung haengt")
	tage := fs.Int("aufbewahrung-tage", 0, "Aufbewahrungsfrist in Tagen")
	source := fs.String("source", "all", "claude | user | plugins | all")
	alsJSON := fs.Bool("json", false, "Bericht als JSON")
	schreiben := fs.Bool("schreiben", false, "ablegen statt nur zeigen")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	switch {
	case *mandant == "":
		fmt.Fprintln(stderr, "skillctl envreport: --mandant fehlt")
		return exitUsage
	case *prinzipal == "":
		fmt.Fprintln(stderr, "skillctl envreport: --prinzipal fehlt")
		return exitUsage
	case *tage <= 0:
		fmt.Fprintln(stderr, "skillctl envreport: --aufbewahrung-tage fehlt. "+
			"Eine Aussage ueber das Arbeitsverhalten eines Menschen, die nie verfaellt, "+
			"ist keine Aufbewahrung.")
		return exitUsage
	case *art == "" || *beleg == "":
		fmt.Fprintln(stderr, "skillctl envreport: --einwilligung-art und --einwilligung-beleg fehlen. "+
			"Wer beobachtet wird, muss es wissen (SPEC-0428 Grenze 3).")
		return exitUsage
	}

	host, err := os.Hostname()
	if err != nil {
		fmt.Fprintf(stderr, "skillctl envreport: hostname: %v\n", err)
		return exitGeneric
	}
	env, err := envreport.NeueENV(*mandant, *prinzipal, host)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl envreport: %v\n", err)
		return exitUsage
	}

	roots, err := resolveAuditRoots(*source)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl envreport: %v\n", err)
		return exitUsage
	}
	sc := &scanner.Scanner{Roots: roots, WithTrust: true}
	inv, err := sc.Scan()
	if err != nil {
		fmt.Fprintf(stderr, "skillctl envreport: scan failed: %v\n", err)
		return exitGeneric
	}
	// Kein Ampelboden bei der Erhebung: der Bericht MISST, er urteilt nicht.
	// Das Urteil gegen einen Boden ist envreport.Pruefe (T-04), und es gehoert
	// dem Regelwerk der Umgebung, nicht der Erhebung.
	ar := audit.Compute(inv, resolveMinimum(""))

	jetzt := time.Now().UTC()
	// Im Trockenlauf ist die Nummer 1: sie kommt sonst aus der Ablage, und
	// die wird hier absichtlich nicht befragt.
	rep, err := envreport.AusAudit(ar, envreport.Optionen{
		ENV:             env,
		Principal:       *prinzipal,
		Jetzt:           jetzt,
		AufbewahrungBis: jetzt.AddDate(0, 0, *tage),
		Seq:             envreport.FesteSeq(1),
	})
	if err != nil {
		fmt.Fprintf(stderr, "skillctl envreport: %v\n", err)
		return exitGeneric
	}

	ein := envreport.Einwilligung{
		Principal: *prinzipal, Erteilt: jetzt, Art: *art, Beleg: *beleg,
	}
	// Die Grenzen laufen auch im Trockenlauf. Ein Trockenlauf, der andere
	// Regeln kennt als der Ernstfall, belegt nichts ueber den Ernstfall.
	if err := envreport.PruefeAblage(rep, ein, jetzt); err != nil {
		fmt.Fprintf(stderr, "skillctl envreport: %v\n", err)
		return exitGeneric
	}

	if *alsJSON {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Fprintln(stdout, string(b))
	} else {
		emitEnvreport(rep, stdout)
	}

	if !*schreiben {
		fmt.Fprintf(stdout, "\nTrockenlauf. Nichts abgelegt. Mit --schreiben wird ein\n"+
			"Personendatum in ER1 angelegt; das ist ein eigener Vorgang.\n")
		return 0
	}

	fmt.Fprintf(stderr, "skillctl envreport: --schreiben ist noch nicht verdrahtet.\n"+
		"Der Ablagepfad (pkg/skillctl/envreport.ER1Store) ist gebaut und geprueft,\n"+
		"die Verdrahtung an die ER1-Zugangsdaten fehlt bewusst noch: der erste\n"+
		"echte Bericht ist ein Checkpoint und kein Nebeneffekt eines Flags.\n")
	return exitGeneric
}

func emitEnvreport(r envreport.Report, w io.Writer) {
	fmt.Fprintf(w, "ENV       %s\n", r.ENV)
	fmt.Fprintf(w, "erhoben   %s\n", r.TakenAt.Format(time.RFC3339))
	fmt.Fprintf(w, "Frist     %s\n", r.AufbewahrungBis.Format("2006-01-02"))
	fmt.Fprintf(w, "Lage      %s\n", r.Posture)
	fmt.Fprintf(w, "Digest    %s\n", r.Digest())
	fmt.Fprintf(w, "\n%-34s %-9s %-8s %s\n", "FAEHIGKEIT", "VERTRAUEN", "TIER", "AMPEL")
	for _, z := range r.Zeilen {
		ampel := z.Policy.GovernanceFloor
		if ampel == "" {
			ampel = "unbeurteilt"
		}
		fmt.Fprintf(w, "%-34s %-9s %-8s %s\n", z.Skill.Name, z.Trust.State, z.Skill.Tier, ampel)
	}
	fmt.Fprintf(w, "\n%d Faehigkeiten\n", len(r.Zeilen))
}
