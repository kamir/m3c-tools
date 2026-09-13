// store_test.go: SPEC-0428 AC-05, AC-06, AC-07 und die fuenf Grenzen.
//
// Die Grenzen werden als NEGATIVPROBEN geprueft. Eine Grenze, die nur im
// Gutfall mitlaeuft, ist keine: geprueft werden muss, dass sie HAELT, wenn
// jemand sie ueberschreitet.
package envreport

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func consent(principal string) Einwilligung {
	return Einwilligung{
		Principal: principal,
		Erteilt:   time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		Art:       "selbst",
		Beleg:     "Onboarding-Gespraech 2026-09-01, Protokoll ER1 abc123",
	}
}

func bericht(seq int) Report {
	e, _ := NeueENV("kup", "kamir", "MacBook-Pro-von-Mirko")
	return Report{
		ENV:             e.String(),
		Principal:       "kamir",
		Seq:             seq,
		TakenAt:         time.Date(2026, 9, 13, 8, 0, 0, 0, time.UTC).Add(time.Duration(seq) * time.Hour),
		Posture:         PostureOK,
		AufbewahrungBis: time.Date(2027, 9, 13, 0, 0, 0, 0, time.UTC),
		Zeilen:          []Zeile{{Skill: SkillRef{Name: "durchdenken"}, Trust: Trust{State: "OK"}}},
	}
}

// --- AC-05: die acht Marken --------------------------------------------

func TestAC05_AchtMarken(t *testing.T) {
	r := bericht(1)
	tags := Marken(r, "kup___skillenv", "anker-001")
	will := []string{
		"skill-env-report",
		"env:kup/kamir/",
		"principal:kamir",
		"report-seq:1",
		"report-digest:sha256:",
		"taken-at:2026-09-13",
		"posture:ok",
		"link/parent/kup___skillenv/anker-001",
	}
	if len(tags) != len(will) {
		t.Fatalf("erwartet %d Marken, sind %d: %v", len(will), len(tags), tags)
	}
	joined := strings.Join(tags, " ")
	for _, w := range will {
		if !strings.Contains(joined, w) {
			t.Fatalf("Marke fehlt: %s\n  in: %v", w, tags)
		}
	}
}

func TestAC05_MarkenTragenNieDenKlarnamen(t *testing.T) {
	r := bericht(1)
	for _, tag := range Marken(r, "kup___skillenv", "anker-001") {
		if strings.Contains(tag, "MacBook") {
			t.Fatalf("Klarname in Marke: %s", tag)
		}
	}
}

// --- AC-06: der zweite Bericht ueberschreibt den ersten NICHT ----------

func TestAC06_AblageIstAnhaengend(t *testing.T) {
	s := NewMemStore("kup___skillenv")
	a1, err := s.Ablegen(bericht(1), consent("kamir"))
	if err != nil {
		t.Fatal(err)
	}
	a2, err := s.Ablegen(bericht(2), consent("kamir"))
	if err != nil {
		t.Fatal(err)
	}
	liste, _ := s.Liste(bericht(1).ENV)
	if len(liste) != 2 {
		t.Fatalf("nach zwei Ablagen liegen %d Berichte, erwartet 2", len(liste))
	}
	if a1.DocID == a2.DocID {
		t.Fatal("der zweite Bericht hat den ersten ueberschrieben")
	}
	if liste[0].Seq != 1 || liste[1].Seq != 2 {
		t.Fatalf("Reihenfolge falsch: %+v", liste)
	}
}

func TestAC06_GleicheSeqWirdAbgelehntStattUeberschrieben(t *testing.T) {
	s := NewMemStore("kup___skillenv")
	if _, err := s.Ablegen(bericht(1), consent("kamir")); err != nil {
		t.Fatal(err)
	}
	_, err := s.Ablegen(bericht(1), consent("kamir"))
	if !errors.Is(err, ErrSchonVorhanden) {
		t.Fatalf("doppelte Seq: %v, erwartet ErrSchonVorhanden", err)
	}
	liste, _ := s.Liste(bericht(1).ENV)
	if len(liste) != 1 {
		t.Fatalf("nach dem abgelehnten Schreiben liegen %d Berichte", len(liste))
	}
}

func TestSeqKommtAusDerAblage(t *testing.T) {
	s := NewMemStore("kup___skillenv")
	env := bericht(1).ENV
	if n, _ := s.NaechsteSeq(env); n != 1 {
		t.Fatalf("erste Nummer ist %d, erwartet 1", n)
	}
	if _, err := s.Ablegen(bericht(1), consent("kamir")); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.NaechsteSeq(env); n != 2 {
		t.Fatalf("zweite Nummer ist %d, erwartet 2", n)
	}
}

// --- AC-07: Luecken ueber den Store ------------------------------------

func TestAC07_LueckeUeberDenStore(t *testing.T) {
	s := NewMemStore("kup___skillenv")
	env := bericht(1).ENV
	for _, n := range []int{1, 2, 4} {
		if _, err := s.Ablegen(bericht(n), consent("kamir")); err != nil {
			t.Fatal(err)
		}
	}
	l, err := Luecken(s, env, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 1 || l[0] != 3 {
		t.Fatalf("Luecken = %v, erwartet [3]", l)
	}
	// Eine als geloescht bekannte Nummer ist keine Luecke (AC-11-Naht).
	l2, _ := Luecken(s, env, map[int]bool{3: true})
	if len(l2) != 0 {
		t.Fatalf("Loeschung als Luecke gemeldet: %v", l2)
	}
}

// --- Grenze 1: der Host ist gehasht ------------------------------------

func TestGrenze1_KlartextHostWirdAbgelehnt(t *testing.T) {
	r := bericht(1)
	r.ENV = "env:kup/kamir/MacBook-Pro-von-Mirko"
	err := PruefeAblage(r, consent("kamir"), time.Now().UTC())
	if !errors.Is(err, ErrHostImKlartext) {
		t.Fatalf("Klartext-Host durchgelassen: %v", err)
	}
}

// --- Grenze 2: kein Quelltext verlaesst die Maschine -------------------

func TestGrenze2_UeberlangerFreitextWirdAbgelehnt(t *testing.T) {
	r := bericht(1)
	r.Zeilen[0].Trust.Reason = strings.Repeat("x", 513)
	err := PruefeAblage(r, consent("kamir"), time.Now().UTC())
	if !errors.Is(err, ErrQuelltextImRumpf) {
		t.Fatalf("Quelltext durchgelassen: %v", err)
	}
}

func TestGrenze2_KurzerGrundBleibtErlaubt(t *testing.T) {
	r := bericht(1)
	r.Zeilen[0].Trust.Reason = "no sibling .skb"
	if err := PruefeAblage(r, consent("kamir"), time.Now().UTC()); err != nil {
		t.Fatalf("normaler Grund abgelehnt: %v", err)
	}
}

// --- Grenze 3: Einwilligung --------------------------------------------

func TestGrenze3_OhneEinwilligungKeineAblage(t *testing.T) {
	s := NewMemStore("kup___skillenv")
	_, err := s.Ablegen(bericht(1), Einwilligung{})
	if !errors.Is(err, ErrEinwilligungFehlt) {
		t.Fatalf("ohne Einwilligung geschrieben: %v", err)
	}
}

func TestGrenze3_FremdeEinwilligungZaehltNicht(t *testing.T) {
	s := NewMemStore("kup___skillenv")
	_, err := s.Ablegen(bericht(1), consent("jemand-anders"))
	if !errors.Is(err, ErrEinwilligungFehlt) {
		t.Fatalf("Einwilligung einer anderen Person akzeptiert: %v", err)
	}
}

func TestGrenze3_EinwilligungOhneBelegIstKeine(t *testing.T) {
	e := consent("kamir")
	e.Beleg = ""
	if err := e.Gueltig("kamir", time.Now().UTC()); !errors.Is(err, ErrEinwilligungFehlt) {
		t.Fatalf("Einwilligung ohne Beleg akzeptiert: %v", err)
	}
}

func TestGrenze3_UnbekannteArtWirdAbgelehnt(t *testing.T) {
	e := consent("kamir")
	e.Art = "angenommen"
	if err := e.Gueltig("kamir", time.Now().UTC()); !errors.Is(err, ErrEinwilligungFehlt) {
		t.Fatalf("unbekannte Einwilligungsart akzeptiert: %v", err)
	}
}

func TestGrenze3_EinsetzungMitBenachrichtigungZaehlt(t *testing.T) {
	e := consent("kamir")
	e.Art = "eingesetzt"
	e.Beleg = "Anordnung 2026-09-01, Benachrichtigung per Mail am selben Tag"
	if err := e.Gueltig("kamir", time.Now().UTC()); err != nil {
		t.Fatalf("Einsetzung mit Benachrichtigung abgelehnt: %v", err)
	}
}

func TestGrenze3_ZukuenftigeEinwilligungZaehltNicht(t *testing.T) {
	e := consent("kamir")
	e.Erteilt = time.Now().UTC().Add(48 * time.Hour)
	if err := e.Gueltig("kamir", time.Now().UTC()); !errors.Is(err, ErrEinwilligungFehlt) {
		t.Fatalf("in der Zukunft erteilte Einwilligung akzeptiert: %v", err)
	}
}

// --- Grenze 4: Aufbewahrungsfrist --------------------------------------

func TestGrenze4_OhneFristKeineAblage(t *testing.T) {
	s := NewMemStore("kup___skillenv")
	r := bericht(1)
	r.AufbewahrungBis = time.Time{}
	_, err := s.Ablegen(r, consent("kamir"))
	if !errors.Is(err, ErrFristFehlt) {
		t.Fatalf("ohne Aufbewahrungsfrist geschrieben: %v", err)
	}
}

// --- Grenze 5: der Store liest nie ueber Personen hinweg ---------------

func TestGrenze5_ListeIstAufEineUmgebungBeschraenkt(t *testing.T) {
	s := NewMemStore("kup___skillenv")
	if _, err := s.Ablegen(bericht(1), consent("kamir")); err != nil {
		t.Fatal(err)
	}
	andereENV, _ := NeueENV("kup", "eric", "ThinkPad")
	r := bericht(1)
	r.ENV = andereENV.String()
	r.Principal = "eric"
	if _, err := s.Ablegen(r, consent("eric")); err != nil {
		t.Fatal(err)
	}
	meine, _ := s.Liste(bericht(1).ENV)
	if len(meine) != 1 {
		t.Fatalf("die Liste einer Umgebung zeigt %d Berichte, erwartet 1", len(meine))
	}
	if meine[0].ENV != bericht(1).ENV {
		t.Fatal("die Liste hat eine fremde Umgebung geliefert")
	}
}

// Die Schnittstelle darf keine Methode haben, die ueber Personen hinweg liest.
// Dieser Test ist eine Zusicherung ueber die FORM des Vertrags, nicht ueber
// eine Ausfuehrung: waechst Store um ein AlleBerichte(), faellt er auf.
func TestGrenze5_StoreHatKeineUebergreifendeLesemethode(t *testing.T) {
	var s Store = NewMemStore("x")
	switch any(s).(type) {
	case interface{ Alle() ([]Abgelegt, error) }:
		t.Fatal("Store hat eine uebergreifende Lesemethode bekommen; Grenze 5 verlangt eine eigene Freigabe")
	case interface {
		ListeAlle() ([]Abgelegt, error)
	}:
		t.Fatal("Store hat eine uebergreifende Lesemethode bekommen; Grenze 5 verlangt eine eigene Freigabe")
	}
}

// --- Der Anker ---------------------------------------------------------

func TestAnkerIstJeUmgebungStabil(t *testing.T) {
	s := NewMemStore("kup___skillenv")
	env := bericht(1).ENV
	a, _ := s.Anker(env)
	b, _ := s.Anker(env)
	if a != b {
		t.Fatalf("der Anker wechselt: %s != %s", a, b)
	}
	andere, _ := NeueENV("kup", "eric", "ThinkPad")
	c, _ := s.Anker(andere.String())
	if c == a {
		t.Fatal("zwei Umgebungen teilen einen Anker")
	}
}
