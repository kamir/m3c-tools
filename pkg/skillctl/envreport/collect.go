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
	"errors"
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
		return Report{}, errors.New("collect: no SeqQuelle; the sequence number comes from the store")
	}
	if o.AufbewahrungBis.IsZero() {
		return Report{}, ErrFristFehlt
	}
	seq, err := o.Seq.NaechsteSeq(o.ENV.String())
	if err != nil {
		return Report{}, fmt.Errorf("next report_seq: %w", err)
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

// FehlendeSeq nennt die Luecken INNERHALB des aufbewahrten Fensters (AC-07).
//
// Nur innerhalb: alles unterhalb der niedrigsten vorhandenen Nummer ist nicht
// fehlend, sondern NICHT MEHR AUFBEWAHRT, und das ist eine andere Aussage.
//
// Der Unterschied ist nicht theoretisch. Die erste Fassung lief von 1 bis zur
// hoechsten Nummer und meldete nach jedem rechtmaessigen Aufbewahrungslauf den
// gesamten verfallenen Anfang als Luecke: aus [3 4 5] wurde die Meldung [1 2].
// Ein Pruefer, der bei ordnungsgemaessem Betrieb rot meldet, wird nach dem
// dritten Mal ignoriert, und dann faellt die echte Luecke auch nicht mehr auf.
//
// Nebenwirkung, und sie ist erwuenscht: fuer den Normalfall braucht es KEIN
// Loeschprotokoll. Ein Verzeichnis darueber, was von wem geloescht wurde, waere
// selbst ein Personendatum, und zwar eines, das die Loeschung ueberlebt.
//
// geloescht bleibt fuer den Fall, dass mitten im Fenster etwas absichtlich
// entfernt wurde und ein Beleg dafuer vorliegt.
func FehlendeSeq(vorhanden []int, geloescht map[int]bool) []int {
	if len(vorhanden) == 0 {
		return nil
	}
	niedrigste, hoechste := vorhanden[0], vorhanden[0]
	hat := make(map[int]bool, len(vorhanden))
	for _, s := range vorhanden {
		hat[s] = true
		if s < niedrigste {
			niedrigste = s
		}
		if s > hoechste {
			hoechste = s
		}
	}
	var luecken []int
	for i := niedrigste + 1; i < hoechste; i++ {
		if !hat[i] && !geloescht[i] {
			luecken = append(luecken, i)
		}
	}
	return luecken
}

// Fenster beschreibt, was von einer Umgebung noch aufbewahrt wird.
type Fenster struct {
	Von, Bis int   // niedrigste und hoechste aufbewahrte Nummer, 0 wenn leer
	Luecken  []int // fehlende Nummern INNERHALB des Fensters
	Anzahl   int
}

// FensterAus bildet das Aufbewahrungsfenster ab. Es macht die Unterscheidung
// sichtbar, die FehlendeSeq intern trifft: was fehlt, und was nur nicht mehr
// aufbewahrt wird.
func FensterAus(vorhanden []int, geloescht map[int]bool) Fenster {
	f := Fenster{Anzahl: len(vorhanden), Luecken: FehlendeSeq(vorhanden, geloescht)}
	if len(vorhanden) == 0 {
		return f
	}
	f.Von, f.Bis = vorhanden[0], vorhanden[0]
	for _, s := range vorhanden {
		if s < f.Von {
			f.Von = s
		}
		if s > f.Bis {
			f.Bis = s
		}
	}
	return f
}
