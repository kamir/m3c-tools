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

	er1cfgpkg "github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/skillctl/audit"
	"github.com/kamir/m3c-tools/pkg/skillctl/envreport"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
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
	er1Target := fs.String("er1-target", "prod", "prod | stage | local")
	er1Context := fs.String("er1-context", "", "ER1-Kontext (Vorgabe: <mandant>___skillenv)")

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

	// --- Ab hier verlaesst ein Personendatum die Maschine. ---------------
	cfg, err := resolveER1Config(*er1Target)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl envreport: %v\n", err)
		return exitGeneric
	}
	ctxID := *er1Context
	if ctxID == "" {
		ctxID = *mandant + "___skillenv"
	}
	store := &envreport.ER1Store{
		ContextID: ctxID,
		Up:        er1Adapter{cfg},
		Ls:        er1Adapter{cfg},
		Jetzt:     func() time.Time { return time.Now().UTC() },
	}
	// Die Nummer kommt jetzt aus der Ablage und nicht mehr aus dem Trockenlauf.
	seq, err := store.NaechsteSeq(env.String())
	if err != nil {
		fmt.Fprintf(stderr, "skillctl envreport: naechste report_seq: %v\n", err)
		return exitGeneric
	}
	rep.Seq = seq

	fmt.Fprintf(stdout, "\nSchreibe nach ER1: Kontext %s, report_seq %d.\n", ctxID, seq)
	abgelegt, err := store.Ablegen(rep, ein)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl envreport: %v\n", err)
		return exitGeneric
	}
	fmt.Fprintf(stdout, "Abgelegt: %s (seq %d, %s)\n", abgelegt.DocID, abgelegt.Seq, abgelegt.Digest)

	// Nachpruefen statt melden: ein Schreibvorgang, der nur behauptet
	// geschrieben zu haben, ist in dieser Klasse der teuerste Fehler.
	zurueck, err := store.Liste(env.String())
	if err != nil {
		fmt.Fprintf(stderr, "skillctl envreport: Nachpruefung fehlgeschlagen: %v\n", err)
		return exitGeneric
	}
	gefunden := false
	for _, a := range zurueck {
		if a.Seq == abgelegt.Seq {
			gefunden = true
		}
	}
	if !gefunden {
		fmt.Fprintf(stderr, "skillctl envreport: der abgelegte Bericht liest sich nicht zurueck. "+
			"Der Schreibvorgang meldete Erfolg; die Ablage kennt ihn nicht.\n")
		return exitGeneric
	}
	fmt.Fprintf(stdout, "Nachgeprueft: %d Bericht(e) in dieser Umgebung.\n", len(zurueck))
	return 0
}

// er1Adapter verbindet den ER1Store mit dem Transport der Registry. Er ist
// bewusst duenn: der Store kennt kein HTTP, und die Registry kennt keine
// Berichte.
type er1Adapter struct{ cfg *er1cfgpkg.Config }

func (a er1Adapter) UploadText(body, filename, tags, contentType, contextID string) (string, error) {
	return registry.UploadTextItem(a.cfg, body, filename, tags, contentType, contextID)
}

func (a er1Adapter) ListByTags(contextID string, tags []string) ([]envreport.RohPosten, error) {
	items, err := registry.ListItemsByTags(a.cfg, contextID, tags)
	if err != nil {
		return nil, err
	}
	out := make([]envreport.RohPosten, 0, len(items))
	for _, it := range items {
		out = append(out, envreport.RohPosten{DocID: it.DocID, Tags: it.Tags})
	}
	return out, nil
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
