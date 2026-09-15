// rechnungen_test.go: SPEC-0428 AC-08, AC-09 und AC-10.
package envreport

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func berichtMit(seq int, zeilen ...Zeile) Report {
	r := bericht(seq)
	r.Zeilen = zeilen
	return r
}

func z(name, version, state string) Zeile {
	return Zeile{Skill: SkillRef{Name: name, Version: version}, Trust: Trust{State: state}}
}

// --- AC-09: die Entwicklung nennt vier Klassen -------------------------

func TestAC09_VierKlassen(t *testing.T) {
	vorher := berichtMit(1,
		z("bleibt", "1.0", "OK"),
		z("entfaellt", "1.0", "OK"),
		z("neue-version", "1.0", "OK"),
		z("kippt", "1.0", "OK"),
	)
	nachher := berichtMit(2,
		z("bleibt", "1.0", "OK"),
		z("neue-version", "2.0", "OK"),
		z("kippt", "1.0", "BROKEN"),
		z("kommt-dazu", "1.0", "OK"),
	)
	aend, err := Entwicklung(vorher, nachher)
	if err != nil {
		t.Fatal(err)
	}
	gefunden := map[Aenderungsart]string{}
	for _, a := range aend {
		gefunden[a.Art] = a.Skill
	}
	will := map[Aenderungsart]string{
		Hinzugekommen: "kommt-dazu",
		Entfallen:     "entfaellt",
		VersionNeu:    "neue-version",
		VertrauenNeu:  "kippt",
	}
	for art, skill := range will {
		if gefunden[art] != skill {
			t.Fatalf("%s: erwartet %q, gefunden %q (alle: %+v)", art, skill, gefunden[art], aend)
		}
	}
	if len(aend) != 4 {
		t.Fatalf("erwartet 4 Aenderungen, sind %d: %+v", len(aend), aend)
	}
	// "bleibt" darf NICHT auftauchen.
	for _, a := range aend {
		if a.Skill == "bleibt" {
			t.Fatal("eine unveraenderte Faehigkeit wurde als Aenderung gemeldet")
		}
	}
}

func TestAC09_VersionUndVertrauenZugleich(t *testing.T) {
	vorher := berichtMit(1, z("x", "1.0", "OK"))
	nachher := berichtMit(2, z("x", "2.0", "BROKEN"))
	aend, _ := Entwicklung(vorher, nachher)
	if len(aend) != 2 {
		t.Fatalf("zwei gleichzeitige Aenderungen ergeben %d Zeilen, erwartet 2: %+v", len(aend), aend)
	}
}

func TestAC09_KeineAenderungKeineZeilen(t *testing.T) {
	r := berichtMit(1, z("x", "1.0", "OK"))
	aend, err := Entwicklung(r, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(aend) != 0 {
		t.Fatalf("identische Berichte ergeben %d Aenderungen: %+v", len(aend), aend)
	}
}

func TestAC09_ZweiUmgebungenSindKeineEntwicklung(t *testing.T) {
	a := berichtMit(1, z("x", "1.0", "OK"))
	b := berichtMit(1, z("x", "1.0", "OK"))
	andere, _ := NeueENV("kup", "alice", "ThinkPad")
	b.ENV = andere.String()
	if _, err := Entwicklung(a, b); !errors.Is(err, ErrFremdeUmgebung) {
		t.Fatalf("zwei Umgebungen als Entwicklung akzeptiert: %v", err)
	}
}

func TestEntwicklungIstStabilSortiert(t *testing.T) {
	vorher := berichtMit(1, z("b", "1", "OK"), z("a", "1", "OK"))
	nachher := berichtMit(2, z("b", "2", "OK"), z("a", "2", "OK"))
	e1, _ := Entwicklung(vorher, nachher)
	e2, _ := Entwicklung(vorher, nachher)
	for i := range e1 {
		if e1[i] != e2[i] {
			t.Fatal("die Reihenfolge ist nicht stabil")
		}
	}
	if e1[0].Skill != "a" {
		t.Fatalf("nicht nach Namen sortiert: %+v", e1)
	}
}

// --- AC-08: Deckung ----------------------------------------------------

func TestAC08_Deckung(t *testing.T) {
	katalog := []string{"a", "b", "nur-katalog"}
	berichte := []Report{
		berichtMit(1, z("a", "1", "OK")),
		berichtMit(2, z("b", "1", "OK"), z("nur-maschine", "1", "OK")),
	}
	d := Decke(katalog, berichte)
	if strings.Join(d.InBeiden, ",") != "a,b" {
		t.Fatalf("InBeiden = %v", d.InBeiden)
	}
	if strings.Join(d.NurImKatalog, ",") != "nur-katalog" {
		t.Fatalf("NurImKatalog = %v", d.NurImKatalog)
	}
	if strings.Join(d.NurBeobachtet, ",") != "nur-maschine" {
		t.Fatalf("NurBeobachtet = %v", d.NurBeobachtet)
	}
}

func TestAC08_DeckungNimmtDieVereinigung(t *testing.T) {
	// Eine Faehigkeit auf EINER Maschine gilt als beobachtet, auch wenn sie
	// auf der anderen fehlt.
	katalog := []string{"a"}
	d := Decke(katalog, []Report{
		berichtMit(1),
		berichtMit(2, z("a", "1", "OK")),
	})
	if len(d.InBeiden) != 1 || d.InBeiden[0] != "a" {
		t.Fatalf("Vereinigung nicht gebildet: %+v", d)
	}
}

// --- Konformitaet ------------------------------------------------------

func TestKonformitaet(t *testing.T) {
	r := berichtMit(1,
		Zeile{Skill: SkillRef{Name: "erlaubt"}, Trust: Trust{State: "OK"}, Policy: Policy{GovernanceFloor: "green"}},
		Zeile{Skill: SkillRef{Name: "boese"}, Trust: Trust{State: "OK"}, Policy: Policy{GovernanceFloor: "red"}},
	)
	v := Pruefe(r, Regelwerk{Soll: []string{"fehlt-hier"}, Verboten: []string{"boese"}, AmpelBoden: "yellow"})
	arten := map[string]bool{}
	for _, x := range v {
		arten[x.Art] = true
	}
	for _, will := range []string{"fehlt", "verboten", "unter-boden"} {
		if !arten[will] {
			t.Fatalf("Verstossart %q nicht gemeldet: %+v", will, v)
		}
	}
}

func TestKonformitaet_UnbeurteiltIstNichtGruen(t *testing.T) {
	r := berichtMit(1, Zeile{Skill: SkillRef{Name: "ohne-ampel"}, Trust: Trust{State: "OK"}})
	v := Pruefe(r, Regelwerk{AmpelBoden: "green"})
	if len(v) != 1 || v[0].Art != "unbeurteilt" {
		t.Fatalf("ungesetzte Ampel nicht als unbeurteilt gemeldet: %+v", v)
	}
	if !strings.Contains(v[0].Info, "not green") {
		t.Fatalf("die Meldung sagt nicht, worum es geht: %q", v[0].Info)
	}
}

func TestKonformitaet_OhneBodenKeineAmpelpruefung(t *testing.T) {
	r := berichtMit(1, Zeile{Skill: SkillRef{Name: "ohne-ampel"}, Trust: Trust{State: "OK"}})
	if v := Pruefe(r, Regelwerk{}); len(v) != 0 {
		t.Fatalf("ohne Boden wurde geprueft: %+v", v)
	}
}

// --- AC-10: der Personenvergleich braucht eine eigene Freigabe ---------

func gueltigeFreigabe() Freigabe {
	return Freigabe{
		Prinzipale: []string{"bob", "alice"},
		Zweck:      "Abgleich der Pflichtskills vor dem Windows-Rollout",
		GueltigBis: time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC),
		Erteiler:   "Diana",
	}
}

func zweiPersonen() (Report, Report) {
	a := berichtMit(1, z("nur-bei-a", "1", "OK"), z("geteilt", "1", "OK"))
	b := berichtMit(1, z("geteilt", "1", "OK"), z("nur-bei-b", "1", "OK"))
	envB, _ := NeueENV("kup", "alice", "ThinkPad")
	b.ENV = envB.String()
	b.Principal = "alice"
	return a, b
}

func TestAC10_OhneFreigabeKeineDaten(t *testing.T) {
	a, b := zweiPersonen()
	jetzt := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	out, err := Vergleiche(a, b, Freigabe{}, jetzt)
	if !errors.Is(err, ErrFreigabeFehlt) {
		t.Fatalf("ohne Freigabe verglichen: %v", err)
	}
	if out != nil {
		t.Fatalf("es wurden trotz fehlender Freigabe Daten geliefert: %+v", out)
	}
}

func TestAC10_MeldungNenntDenRechtsgrundNichtDieDaten(t *testing.T) {
	a, b := zweiPersonen()
	jetzt := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	_, err := Vergleiche(a, b, Freigabe{}, jetzt)
	msg := err.Error()
	for _, geheim := range []string{"nur-bei-a", "nur-bei-b", "geteilt"} {
		if strings.Contains(msg, geheim) {
			t.Fatalf("die Fehlermeldung verraet Daten: %q", msg)
		}
	}
	if !strings.Contains(msg, "authorization") {
		t.Fatalf("die Meldung nennt den Rechtsgrund nicht: %q", msg)
	}
}

func TestAC10_FreigabeMussBeidePersonenNennen(t *testing.T) {
	a, b := zweiPersonen()
	f := gueltigeFreigabe()
	f.Prinzipale = []string{"bob"} // alice fehlt
	_, err := Vergleiche(a, b, f, time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC))
	if !errors.Is(err, ErrFreigabeFehlt) {
		t.Fatalf("halbe Freigabe akzeptiert: %v", err)
	}
}

func TestAC10_UnbefristeteFreigabeIstKeine(t *testing.T) {
	a, b := zweiPersonen()
	f := gueltigeFreigabe()
	f.GueltigBis = time.Time{}
	if _, err := Vergleiche(a, b, f, time.Now().UTC()); !errors.Is(err, ErrFreigabeFehlt) {
		t.Fatalf("unbefristete Freigabe akzeptiert: %v", err)
	}
}

func TestAC10_AbgelaufeneFreigabeZaehltNicht(t *testing.T) {
	a, b := zweiPersonen()
	f := gueltigeFreigabe()
	spaeter := f.GueltigBis.Add(24 * time.Hour)
	if _, err := Vergleiche(a, b, f, spaeter); !errors.Is(err, ErrFreigabeAbgelaufen) {
		t.Fatalf("abgelaufene Freigabe akzeptiert: %v", err)
	}
}

func TestAC10_FreigabeOhneZweckOderErteilerIstKeine(t *testing.T) {
	a, b := zweiPersonen()
	jetzt := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	ohneZweck := gueltigeFreigabe()
	ohneZweck.Zweck = ""
	if _, err := Vergleiche(a, b, ohneZweck, jetzt); !errors.Is(err, ErrFreigabeFehlt) {
		t.Fatalf("Freigabe ohne Zweck akzeptiert: %v", err)
	}
	ohneErteiler := gueltigeFreigabe()
	ohneErteiler.Erteiler = ""
	if _, err := Vergleiche(a, b, ohneErteiler, jetzt); !errors.Is(err, ErrFreigabeFehlt) {
		t.Fatalf("Freigabe ohne Erteiler akzeptiert: %v", err)
	}
}

func TestAC10_MitFreigabeGehtEs(t *testing.T) {
	a, b := zweiPersonen()
	out, err := Vergleiche(a, b, gueltigeFreigabe(), time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("gueltige Freigabe abgelehnt: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("erwartet 2 Unterschiede, sind %d: %+v", len(out), out)
	}
}

// Derselbe Mensch auf zwei Maschinen ist KEIN Personenvergleich.
func TestSelbstvergleichBrauchtKeineFreigabe(t *testing.T) {
	a := berichtMit(1, z("x", "1", "OK"))
	b := berichtMit(1, z("y", "1", "OK"))
	envB, _ := NeueENV("kup", "bob", "Intel-MBP")
	b.ENV = envB.String()
	if _, err := Vergleiche(a, b, Freigabe{}, time.Now().UTC()); err != nil {
		t.Fatalf("der Vergleich zweier eigener Maschinen verlangte eine Freigabe: %v", err)
	}
}

// --- Der Befund vom 2026-09-13: die Emoji-Form ------------------------

// Auf einer echten Maschine tragen drei von 16 Faehigkeiten mit gesetzter
// Stufe die Emoji-Form. govlevel.Normalize loest sie nicht auf. Sie als
// Unterschreitung zu melden waere ein Fehlalarm.
func TestUnbekannteAmpelformIstUnbeurteiltUndKeinVerstoss(t *testing.T) {
	r := berichtMit(1, Zeile{
		Skill:  SkillRef{Name: "braindump-sync"},
		Trust:  Trust{State: "OK"},
		Policy: Policy{GovernanceFloor: "\U0001F7E1"}, // gelber Kreis
	})
	v := Pruefe(r, Regelwerk{AmpelBoden: "green"})
	if len(v) != 1 {
		t.Fatalf("erwartet genau einen Befund, sind %d: %+v", len(v), v)
	}
	if v[0].Art != "unbeurteilt" {
		t.Fatalf("Emoji-Stufe als %q gemeldet, erwartet unbeurteilt", v[0].Art)
	}
	if !strings.Contains(v[0].Info, "canonical vocabulary") {
		t.Fatalf("die Meldung nennt den Grund nicht: %q", v[0].Info)
	}
}

func TestAmpelIstSchreibungsunabhaengig(t *testing.T) {
	r := berichtMit(1, Zeile{
		Skill:  SkillRef{Name: "x"},
		Trust:  Trust{State: "OK"},
		Policy: Policy{GovernanceFloor: "  GREEN "},
	})
	if v := Pruefe(r, Regelwerk{AmpelBoden: "green"}); len(v) != 0 {
		t.Fatalf("GREEN mit Leerzeichen nicht erkannt: %+v", v)
	}
}
