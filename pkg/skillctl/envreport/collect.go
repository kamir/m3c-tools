// collect.go: die Erhebung (SPEC-0428 T-02).
//
// Der Bericht entsteht aus dem, was `skillctl audit --source all` sieht, und
// aus nichts anderem. Das ist AC-03 und zugleich eine Abgrenzung: dieses Paket
// baut KEINEN zweiten Scanner. Wenn der Audit eine Faehigkeit nicht sieht,
// steht sie nicht im Bericht, und das ist dann ein Befund am Audit und keiner
// hier.
//
// audit.Verdict traegt Name, Tier, State, GovernanceLevel und BundleDigest
// bereits; die Abbildung unten ist deshalb eine Uebersetzung und keine zweite
// Erhebung.
package envreport

import (
	"fmt"
	"sort"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/audit"
)

// SeqQuelle liefert die naechste laufende Nummer FUER EINE ENV. Sie ist eine
// Schnittstelle, weil die Nummer aus der Ablage kommt (T-03) und die Erhebung
// nicht wissen soll, welche Ablage das ist.
type SeqQuelle interface {
	NaechsteSeq(env string) (int, error)
}

// FesteSeq ist eine SeqQuelle fuer Tests und fuer den ersten Lauf.
type FesteSeq int

func (f FesteSeq) NaechsteSeq(string) (int, error) { return int(f), nil }

// Optionen steuern die Erhebung.
type Optionen struct {
	ENV             ENV
	Principal       string
	Jetzt           time.Time
	AufbewahrungBis time.Time
	Seq             SeqQuelle
}

// AusAudit uebersetzt einen audit.Report in einen Skill-Env-Report.
//
// Die Gesamtlage (posture) leitet sich aus den Zeilen ab und wird nicht
// geraten:
//
//	contaminated  mindestens ein BROKEN
//	drift         mindestens ein UNVERIFIED oder BELOW_MIN
//	ok            sonst
//
// Ein leerer Bericht ist `ok` und nicht etwa `drift`: eine Umgebung ohne
// Faehigkeiten ist nicht verdaechtig, sie ist leer.
func AusAudit(r audit.Report, o Optionen) (Report, error) {
	if o.Seq == nil {
		return Report{}, fmt.Errorf("Erhebung ohne SeqQuelle: die Nummer kommt aus der Ablage")
	}
	if o.AufbewahrungBis.IsZero() {
		return Report{}, ErrFristFehlt
	}
	seq, err := o.Seq.NaechsteSeq(o.ENV.String())
	if err != nil {
		return Report{}, fmt.Errorf("naechste report_seq: %w", err)
	}

	zeilen := make([]Zeile, 0, len(r.Verdicts))
	for _, v := range r.Verdicts {
		zeilen = append(zeilen, Zeile{
			Skill: SkillRef{
				Name:   v.Name,
				Tier:   v.Tier,
				Digest: v.BundleDigest,
			},
			Trust: Trust{
				State:  string(v.State),
				Reason: v.Reason,
			},
			Policy: Policy{
				// GovernanceLevel ist "" wenn kein Frontmatter oder kein Feld.
				// Das bleibt "" und wird NICHT zu "green" gemacht: ein
				// ungesetzter Wert ist unbeurteilt, nicht unbedenklich
				// (SPEC-0427 E3). Im Bestand betrifft das 18 von 253 Posten.
				GovernanceFloor: v.GovernanceLevel,
			},
		})
	}
	sort.Slice(zeilen, func(i, j int) bool { return zeilen[i].Skill.Name < zeilen[j].Skill.Name })

	rep := Report{
		ENV:             o.ENV.String(),
		Principal:       o.Principal,
		Seq:             seq,
		TakenAt:         o.Jetzt.UTC(),
		Posture:         lageAus(zeilen),
		AufbewahrungBis: o.AufbewahrungBis.UTC(),
		Zeilen:          zeilen,
	}
	if err := rep.Validate(); err != nil {
		return Report{}, err
	}
	return rep, nil
}

func lageAus(zeilen []Zeile) Posture {
	lage := PostureOK
	for _, z := range zeilen {
		switch z.Trust.State {
		case string(audit.StateBroken):
			return PostureContaminated
		case string(audit.StateUnverified), string(audit.StateBelowMin):
			lage = PostureDrift
		}
	}
	return lage
}

// FehlendeSeq nennt die Luecken in einer Folge erhobener Nummern (AC-07).
//
// Eine Luecke bedeutet: ein Bericht fehlt. Das ist erkennbar, OHNE die
// Berichte zu zaehlen, und genau darum gibt es die laufende Nummer. Ein
// Aufbewahrungssystem, dem man das Fehlen nicht ansieht, belegt nichts.
//
// geloescht nennt die Nummern, die absichtlich entfernt wurden (T-05). Eine
// Loeschung ist KEINE fehlende Erhebung, sonst meldete jede rechtmaessige
// Loeschung fuer immer einen Defekt.
func FehlendeSeq(vorhanden []int, geloescht map[int]bool) []int {
	if len(vorhanden) == 0 {
		return nil
	}
	hat := make(map[int]bool, len(vorhanden))
	hoechste := 0
	for _, s := range vorhanden {
		hat[s] = true
		if s > hoechste {
			hoechste = s
		}
	}
	var luecken []int
	for i := 1; i < hoechste; i++ {
		if !hat[i] && !geloescht[i] {
			luecken = append(luecken, i)
		}
	}
	return luecken
}
