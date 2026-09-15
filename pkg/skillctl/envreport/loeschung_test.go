// loeschung_test.go: SPEC-0428 AC-11 und AC-12, plus die Fensterkorrektur.
package envreport

import (
	"errors"
	"testing"
	"time"
)

func befuellt(t *testing.T, seqs ...int) *MemStore {
	t.Helper()
	s := NewMemStore("kup___skillenv")
	for _, n := range seqs {
		if _, err := s.Ablegen(bericht(n), consent("bob")); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// --- Die Fensterkorrektur ----------------------------------------------

// Der Befund, der T-05 ausgeloest hat: die erste Fassung meldete nach einem
// rechtmaessigen Aufbewahrungslauf den verfallenen Anfang als Luecke.
func TestFenster_VerfallenerAnfangIstKeineLuecke(t *testing.T) {
	if got := FehlendeSeq([]int{3, 4, 5}, nil); len(got) != 0 {
		t.Fatalf("verfallener Anfang als Luecke gemeldet: %v", got)
	}
}

func TestFenster_EchteLueckeInnerhalbBleibtSichtbar(t *testing.T) {
	got := FehlendeSeq([]int{3, 5, 6}, nil)
	if len(got) != 1 || got[0] != 4 {
		t.Fatalf("echte Luecke im Fenster: %v, erwartet [4]", got)
	}
}

func TestFenster_BeschreibtWasBleibt(t *testing.T) {
	f := FensterAus([]int{3, 5, 6}, nil)
	if f.Von != 3 || f.Bis != 6 || f.Anzahl != 3 {
		t.Fatalf("Fenster falsch: %+v", f)
	}
	if len(f.Luecken) != 1 || f.Luecken[0] != 4 {
		t.Fatalf("Luecken falsch: %+v", f)
	}
}

func TestFenster_LeerIstLeer(t *testing.T) {
	f := FensterAus(nil, nil)
	if f.Von != 0 || f.Bis != 0 || f.Anzahl != 0 || len(f.Luecken) != 0 {
		t.Fatalf("leeres Fenster meldet etwas: %+v", f)
	}
}

// --- AC-12: Aufbewahrungsfrist -----------------------------------------

func TestAC12_OhneFristKeinBericht(t *testing.T) {
	r := bericht(1)
	r.AufbewahrungBis = time.Time{}
	if err := r.Validate(); !errors.Is(err, ErrFristFehlt) {
		t.Fatalf("Bericht ohne Frist angenommen: %v", err)
	}
}

func TestAbgelaufenFindetNurUeberschrittene(t *testing.T) {
	jetzt := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	alt := bericht(1)
	alt.AufbewahrungBis = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	neu := bericht(2) // Frist 2027-09-13
	raus := Abgelaufen([]Report{alt, neu}, jetzt)
	if len(raus) != 1 || raus[0] != 1 {
		t.Fatalf("Abgelaufen = %v, erwartet [1]", raus)
	}
}

// --- Aufbewahrungslauf --------------------------------------------------

func TestAufbewahrungslaufEntferntUndMeldetDasFenster(t *testing.T) {
	s := befuellt(t, 1, 2, 3)
	env := bericht(1).ENV
	jetzt := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	alt1, alt2 := bericht(1), bericht(2)
	alt1.AufbewahrungBis = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	alt2.AufbewahrungBis = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)

	erg, err := Aufbewahrungslauf(s, env, []Report{alt1, alt2, bericht(3)}, jetzt)
	if err != nil {
		t.Fatal(err)
	}
	if len(erg.Entfernt) != 2 {
		t.Fatalf("entfernt = %v, erwartet zwei", erg.Entfernt)
	}
	if erg.Bleibt.Anzahl != 1 || erg.Bleibt.Von != 3 {
		t.Fatalf("Fenster nach dem Lauf: %+v", erg.Bleibt)
	}
	// Und die entscheidende Zusicherung: keine Luecke gemeldet.
	if len(erg.Bleibt.Luecken) != 0 {
		t.Fatalf("nach einem rechtmaessigen Lauf werden Luecken gemeldet: %v", erg.Bleibt.Luecken)
	}
}

// --- AC-11: Loeschung ---------------------------------------------------

func TestAC11_LoeschungEntferntAllesUndMeldetKeineLuecke(t *testing.T) {
	s := befuellt(t, 1, 2, 3)
	env := bericht(1).ENV
	erg, err := LoeschePrinzipal(s, "bob", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if erg.Entfernt != 3 || erg.Umgebungen != 1 {
		t.Fatalf("Loeschergebnis: %+v", erg)
	}
	rest, _ := s.Liste(env)
	if len(rest) != 0 {
		t.Fatalf("nach der Loeschung liegen noch %d Berichte", len(rest))
	}
	// AC-11 ausdruecklich: die Luecken-Meldung schweigt.
	l, err := Luecken(s, env, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 0 {
		t.Fatalf("nach der Loeschung werden Luecken gemeldet: %v", l)
	}
}

func TestAC11_LoeschungFindetAlleUmgebungenDerPerson(t *testing.T) {
	s := NewMemStore("kup___skillenv")
	if _, err := s.Ablegen(bericht(1), consent("bob")); err != nil {
		t.Fatal(err)
	}
	zweite, _ := NeueENV("kup", "bob", "Intel-MBP")
	r := bericht(1)
	r.ENV = zweite.String()
	if _, err := s.Ablegen(r, consent("bob")); err != nil {
		t.Fatal(err)
	}
	erg, err := LoeschePrinzipal(s, "bob", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if erg.Umgebungen != 2 || erg.Entfernt != 2 {
		t.Fatalf("nicht alle Umgebungen erfasst: %+v", erg)
	}
}

func TestAC11_LoeschungLaesstFremdeUnberuehrt(t *testing.T) {
	s := NewMemStore("kup___skillenv")
	if _, err := s.Ablegen(bericht(1), consent("bob")); err != nil {
		t.Fatal(err)
	}
	fremd, _ := NeueENV("kup", "alice", "ThinkPad")
	r := bericht(1)
	r.ENV = fremd.String()
	r.Principal = "alice"
	if _, err := s.Ablegen(r, consent("alice")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoeschePrinzipal(s, "bob", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	rest, _ := s.Liste(fremd.String())
	if len(rest) != 1 {
		t.Fatalf("die Loeschung hat fremde Berichte getroffen: %d uebrig", len(rest))
	}
}

// Das Loeschergebnis darf kein Verzeichnis des Geloeschten sein.
func TestAC11_ErgebnisTraegtKeineInhalte(t *testing.T) {
	s := befuellt(t, 1, 2)
	erg, err := LoeschePrinzipal(s, "bob", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	// Der Typ hat genau vier Felder, und keines davon ist ein Bericht.
	_ = erg.Principal
	_ = erg.Umgebungen
	_ = erg.Entfernt
	_ = erg.Zeitpunkt
	switch any(erg).(type) {
	case interface{ Berichte() []Report }:
		t.Fatal("das Loeschergebnis traegt die geloeschten Berichte")
	}
}

func TestLoeschungOhneLoescherIstEinFehler(t *testing.T) {
	if _, err := LoeschePrinzipal(nil, "bob", time.Now().UTC()); !errors.Is(err, ErrKeinLoescher) {
		t.Fatalf("Loeschung ohne Loescher: %v", err)
	}
}

func TestMemStoreErfuelltLoescher(t *testing.T) {
	var _ Loescher = (*MemStore)(nil)
}
