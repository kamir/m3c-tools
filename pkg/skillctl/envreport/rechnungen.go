// rechnungen.go: die vier Rechnungen auf Berichten (SPEC-0428 T-04).
//
// Der Bericht ist die Einheit; alles Weitere ist eine Rechnung darauf:
//
//	Deckung        der Katalog gegen die Vereinigung aller Berichte
//	Konformitaet   ein Bericht gegen die Soll- und die Verbotsmenge
//	Vergleich      Bericht(A, t) gegen Bericht(B, t)      <- eigene Freigabe
//	Entwicklung    Bericht(A, t0) gegen Bericht(A, t1)
//
// Die vierte ist der Grund fuer die Unveraenderlichkeit der Ablage. Die dritte
// ist die, aus der eine Leistungsueberwachung wird, wenn niemand die Grenze
// zieht; sie steht deshalb hinter einer eigenen Freigabe und nicht hinter dem
// Lesezugriff auf die eigene Umgebung (SPEC-0428 Grenze 5, AC-10).
package envreport

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var (
	ErrFreigabeFehlt      = errors.New("comparison across principals requires its own authorization")
	ErrFreigabeAbgelaufen = errors.New("comparison authorization has expired")
	ErrFremdeUmgebung     = errors.New("evolution compares one environment with itself; these are two")
)

// ---------------------------------------------------------------- Entwicklung

// Aenderungsart benennt, WAS sich zwischen zwei Berichten geaendert hat.
type Aenderungsart string

const (
	Hinzugekommen Aenderungsart = "hinzugekommen"
	Entfallen     Aenderungsart = "entfallen"
	VersionNeu    Aenderungsart = "version-geaendert"
	VertrauenNeu  Aenderungsart = "vertrauen-geaendert"
)

// Aenderung ist eine Zeile im Entwicklungsbericht.
type Aenderung struct {
	Art     Aenderungsart
	Skill   string
	Vorher  string // Version bzw. Vertrauenszustand, je nach Art
	Nachher string
}

// Entwicklung vergleicht zwei Berichte DERSELBEN Umgebung (AC-09).
//
// Sie meldet vier Klassen und nicht bloss "geaendert": eine entfallene
// Faehigkeit ist ein anderer Vorgang als eine, deren Vertrauenszustand
// gekippt ist, und wer beide gleich nennt, kann auf keine von beiden
// reagieren.
//
// Die Reihenfolge der Rueckgabe ist stabil (nach Skillname, dann Art), damit
// zwei Laeufe vergleichbar bleiben.
func Entwicklung(vorher, nachher Report) ([]Aenderung, error) {
	if vorher.ENV != nachher.ENV {
		return nil, fmt.Errorf("%w: %q und %q", ErrFremdeUmgebung, vorher.ENV, nachher.ENV)
	}
	alt := indexZeilen(vorher)
	neu := indexZeilen(nachher)

	var out []Aenderung
	for name, n := range neu {
		a, stand := alt[name]
		if !stand {
			out = append(out, Aenderung{Art: Hinzugekommen, Skill: name, Nachher: n.Trust.State})
			continue
		}
		if a.Skill.Version != n.Skill.Version {
			out = append(out, Aenderung{Art: VersionNeu, Skill: name,
				Vorher: a.Skill.Version, Nachher: n.Skill.Version})
		}
		if a.Trust.State != n.Trust.State {
			out = append(out, Aenderung{Art: VertrauenNeu, Skill: name,
				Vorher: a.Trust.State, Nachher: n.Trust.State})
		}
	}
	for name, a := range alt {
		if _, stand := neu[name]; !stand {
			out = append(out, Aenderung{Art: Entfallen, Skill: name, Vorher: a.Trust.State})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Skill != out[j].Skill {
			return out[i].Skill < out[j].Skill
		}
		return out[i].Art < out[j].Art
	})
	return out, nil
}

func indexZeilen(r Report) map[string]Zeile {
	m := make(map[string]Zeile, len(r.Zeilen))
	for _, z := range r.Zeilen {
		m[z.Skill.Name] = z
	}
	return m
}

// ------------------------------------------------------------------- Deckung

// Deckung ist das Ergebnis des Abgleichs Katalog gegen beobachtete Umgebungen.
type Deckung struct {
	InBeiden      []string
	NurImKatalog  []string
	NurBeobachtet []string
}

// Decke vergleicht die Katalognamen mit der Vereinigung aller Berichte (AC-08).
//
// Die Vereinigung, nicht der neueste Bericht: eine Faehigkeit, die auf EINER
// Maschine liegt, ist beobachtet, auch wenn sie auf einer anderen fehlt.
func Decke(katalog []string, berichte []Report) Deckung {
	imKatalog := mengeAus(katalog)
	beobachtet := map[string]bool{}
	for _, r := range berichte {
		for _, z := range r.Zeilen {
			beobachtet[z.Skill.Name] = true
		}
	}
	var d Deckung
	for n := range imKatalog {
		if beobachtet[n] {
			d.InBeiden = append(d.InBeiden, n)
		} else {
			d.NurImKatalog = append(d.NurImKatalog, n)
		}
	}
	for n := range beobachtet {
		if !imKatalog[n] {
			d.NurBeobachtet = append(d.NurBeobachtet, n)
		}
	}
	sort.Strings(d.InBeiden)
	sort.Strings(d.NurImKatalog)
	sort.Strings(d.NurBeobachtet)
	return d
}

func mengeAus(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// -------------------------------------------------------------- Konformitaet

// Regelwerk ist die Soll- und die Verbotsmenge einer Umgebung.
type Regelwerk struct {
	Soll     []string // muss vorhanden sein
	Verboten []string // darf nicht vorhanden sein
	// AmpelBoden ist die niedrigste zulaessige Stufe. Leer heisst: kein Boden.
	// Ein UNGESETZTER Wert im Bericht ist NICHT gruen, sondern unbeurteilt,
	// und faellt damit unter jeden gesetzten Boden (SPEC-0427 E3).
	AmpelBoden string
}

// Verstoss ist ein einzelner Regelbruch.
type Verstoss struct {
	Art   string // "fehlt", "verboten", "unter-boden", "unbeurteilt"
	Skill string
	Info  string
}

var ampelRang = map[string]int{"green": 3, "yellow": 2, "red": 1}

// Pruefe haelt einen Bericht gegen ein Regelwerk.
func Pruefe(r Report, w Regelwerk) []Verstoss {
	da := indexZeilen(r)
	var out []Verstoss
	for _, n := range w.Soll {
		if _, ok := da[n]; !ok {
			out = append(out, Verstoss{Art: "fehlt", Skill: n, Info: "mandated but not present"})
		}
	}
	for _, n := range w.Verboten {
		if _, ok := da[n]; ok {
			out = append(out, Verstoss{Art: "verboten", Skill: n, Info: "forbidden but present"})
		}
	}
	if w.AmpelBoden != "" {
		boden := ampelRang[w.AmpelBoden]
		for _, z := range r.Zeilen {
			stufe := z.Policy.GovernanceFloor
			if stufe == "" {
				out = append(out, Verstoss{Art: "unbeurteilt", Skill: z.Skill.Name,
					Info: "no governance level; unassessed is not green"})
				continue
			}
			if ampelRang[stufe] < boden {
				out = append(out, Verstoss{Art: "unter-boden", Skill: z.Skill.Name,
					Info: fmt.Sprintf("%s is below the floor %s", stufe, w.AmpelBoden)})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Skill != out[j].Skill {
			return out[i].Skill < out[j].Skill
		}
		return out[i].Art < out[j].Art
	})
	return out
}

// ------------------------------------------------------------------ Vergleich

// Freigabe ist die eigene Erlaubnis fuer einen Vergleich ZWISCHEN Personen
// (SPEC-0428 Grenze 5, AC-10). Sie ist nicht dasselbe wie das Leserecht auf
// die eigene Umgebung, und sie wird deshalb getrennt gefuehrt und getrennt
// erteilt.
type Freigabe struct {
	// Prinzipale nennt ausdruecklich, WER verglichen werden darf. Eine
	// Freigabe "fuer alle" gibt es nicht: sie waere keine Freigabe.
	Prinzipale []string
	// Zweck benennt, wofuer. Ohne Zweck keine Freigabe.
	Zweck string
	// GueltigBis begrenzt sie zeitlich. Eine unbefristete Freigabe fuer einen
	// Personenvergleich ist eine dauerhafte Ueberwachungserlaubnis.
	GueltigBis time.Time
	// Erteiler nennt, wer sie gegeben hat.
	Erteiler string
}

func (f Freigabe) deckt(a, b string, jetzt time.Time) error {
	if strings.TrimSpace(f.Zweck) == "" || strings.TrimSpace(f.Erteiler) == "" {
		return fmt.Errorf("%w: authorization needs a purpose and an issuer", ErrFreigabeFehlt)
	}
	if f.GueltigBis.IsZero() {
		return fmt.Errorf("%w: authorization without an end date is not one", ErrFreigabeFehlt)
	}
	if jetzt.After(f.GueltigBis) {
		return fmt.Errorf("%w: expired %s", ErrFreigabeAbgelaufen, f.GueltigBis.Format("2006-01-02"))
	}
	hat := mengeAus(f.Prinzipale)
	for _, p := range []string{a, b} {
		if !hat[p] {
			// Die Meldung nennt den fehlenden Rechtsgrund, NICHT die Daten
			// (AC-10). Der Name des Prinzipals ist hier der Gegenstand der
			// Erlaubnis und keine Messung ueber ihn.
			return fmt.Errorf("%w: authorization does not name principal %q", ErrFreigabeFehlt, p)
		}
	}
	return nil
}

// Unterschied ist eine Zeile im Personenvergleich.
type Unterschied struct {
	Skill string
	NurA  bool
	NurB  bool
}

// Vergleiche stellt zwei Berichte VERSCHIEDENER Personen gegenueber.
//
// Ohne deckende Freigabe liefert die Funktion einen Fehler und **keine Daten**
// (AC-10). Genau das ist der Punkt: waere die Rueckgabe teilweise gefuellt,
// haette die Sperre keinen Wert.
func Vergleiche(a, b Report, f Freigabe, jetzt time.Time) ([]Unterschied, error) {
	if a.Principal == b.Principal {
		// Derselbe Mensch auf zwei Maschinen ist kein Personenvergleich.
		// Das braucht keine Freigabe und faellt unter die eigene Umgebung.
		return unterschiede(a, b), nil
	}
	if err := f.deckt(a.Principal, b.Principal, jetzt); err != nil {
		return nil, err
	}
	return unterschiede(a, b), nil
}

func unterschiede(a, b Report) []Unterschied {
	ia, ib := indexZeilen(a), indexZeilen(b)
	var out []Unterschied
	for n := range ia {
		if _, ok := ib[n]; !ok {
			out = append(out, Unterschied{Skill: n, NurA: true})
		}
	}
	for n := range ib {
		if _, ok := ia[n]; !ok {
			out = append(out, Unterschied{Skill: n, NurB: true})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Skill < out[j].Skill })
	return out
}
