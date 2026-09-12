// envreport_test.go: die Abnahmekriterien AC-01 bis AC-04 aus SPEC-0428
// und AC-03 bis AC-05 aus SPEC-0427 als Tests.
package envreport

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func gueltigerBericht() Report {
	return Report{
		ENV:             "env:kup/kamir/0123456789abcdef",
		Principal:       "kamir",
		Seq:             1,
		TakenAt:         time.Date(2026, 9, 13, 8, 0, 0, 0, time.UTC),
		Posture:         PostureOK,
		AufbewahrungBis: time.Date(2027, 9, 13, 0, 0, 0, 0, time.UTC),
		Zeilen: []Zeile{{
			Skill: SkillRef{Name: "durchdenken", Tier: "user", Digest: "sha256:aa"},
			Trust: Trust{State: "OK"},
		}},
	}
}

// --- SPEC-0427 AC-03: Rundlauf ueber die ENV-Adresse ---------------------

func TestAC03_ENVRundlauf(t *testing.T) {
	for i := 0; i < 100; i++ {
		e, err := NeueENV("kup", "kamir", "MacBook-Pro-von-Mirko-"+string(rune('a'+i%26)))
		if err != nil {
			t.Fatalf("NeueENV: %v", err)
		}
		zurueck, err := ParseENV(e.String())
		if err != nil {
			t.Fatalf("ParseENV(%q): %v", e.String(), err)
		}
		if zurueck != e {
			t.Fatalf("Rundlauf verloren: %+v != %+v", zurueck, e)
		}
	}
}

// --- SPEC-0427 AC-04: fuenf ungueltige Formen, jede nennt den Grund ------

func TestAC04_UngueltigeAdressenNennenDenGrund(t *testing.T) {
	faelle := []struct {
		name string
		in   string
		will error
	}{
		{"fehlender Mandant", "env:", ErrPrinzipalFehlt},
		{"fehlender Prinzipal", "env:kup", ErrPrinzipalFehlt},
		{"fehlender Host", "env:kup/kamir", ErrHostFehlt},
		{"zu viele Segmente", "env:kup/kamir/host/extra", ErrZuVieleTeile},
		{"leeres Segment", "env:kup//abc", ErrLeeresSegment},
	}
	for _, f := range faelle {
		t.Run(f.name, func(t *testing.T) {
			_, err := ParseENV(f.in)
			if !errors.Is(err, f.will) {
				t.Fatalf("ParseENV(%q) = %v, erwartet %v", f.in, err, f.will)
			}
		})
	}
	if _, err := ParseENV("kup/kamir/abc"); !errors.Is(err, ErrKeinPrefix) {
		t.Fatalf("Adresse ohne Prefix muss ErrKeinPrefix liefern, war %v", err)
	}
}

// --- SPEC-0427 AC-05: der Host erscheint NIE im Klartext -----------------

func TestAC05_HostErscheintNieImKlartext(t *testing.T) {
	const klarname = "MacBook-Pro-von-Mirko"
	e, err := NeueENV("kup", "kamir", klarname)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(e.String(), klarname) {
		t.Fatalf("Klarname in der Adresse: %s", e.String())
	}
	if strings.Contains(strings.ToLower(e.String()), strings.ToLower(klarname)) {
		t.Fatalf("Klarname (case-insensitiv) in der Adresse: %s", e.String())
	}
	// Und der Bericht, der sie traegt, ebenso wenig.
	r := gueltigerBericht()
	r.ENV = e.String()
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), klarname) {
		t.Fatalf("Klarname im serialisierten Bericht")
	}
}

func TestHostHashIstMandantengebunden(t *testing.T) {
	// Derselbe Rechner unter zwei Mandanten darf NICHT denselben Hash tragen,
	// sonst waere die Adresse ueber Mandantengrenzen hinweg verkettbar.
	if HashHost("kup", "host-1") == HashHost("scalytics", "host-1") {
		t.Fatal("Hash ist nicht mandantengebunden")
	}
	// Gross- und Kleinschreibung des Rechnernamens darf keinen Unterschied machen.
	if HashHost("kup", "Host-1") != HashHost("kup", "host-1") {
		t.Fatal("Hash ist nicht schreibungsunabhaengig")
	}
}

// --- SPEC-0428 AC-01: Pflichtfelder, und die Meldung nennt das fehlende --

func TestAC01_PflichtfelderNennenDasFehlendeFeld(t *testing.T) {
	faelle := []struct {
		name   string
		kaputt func(*Report)
		will   error
	}{
		{"ohne env", func(r *Report) { r.ENV = "" }, ErrENVFehlt},
		{"ohne taken_at", func(r *Report) { r.TakenAt = time.Time{} }, ErrTakenAtFehlt},
		{"ohne report_seq", func(r *Report) { r.Seq = 0 }, ErrSeqFehlt},
		{"ohne Aufbewahrungsfrist", func(r *Report) { r.AufbewahrungBis = time.Time{} }, ErrFristFehlt},
		{"unbekannte posture", func(r *Report) { r.Posture = "vielleicht" }, ErrPostureUnbek},
		{"Zeile ohne Namen", func(r *Report) { r.Zeilen[0].Skill.Name = "" }, ErrZeileOhneName},
	}
	for _, f := range faelle {
		t.Run(f.name, func(t *testing.T) {
			r := gueltigerBericht()
			f.kaputt(&r)
			err := r.Validate()
			if !errors.Is(err, f.will) {
				t.Fatalf("Validate() = %v, erwartet %v", err, f.will)
			}
		})
	}
	if err := gueltigerBericht().Validate(); err != nil {
		t.Fatalf("gueltiger Bericht abgelehnt: %v", err)
	}
}

// --- SPEC-0428 AC-02: ein Feld ausserhalb posture.snapshot wird abgelehnt -

func TestAC02_FremdesFeldWirdAbgelehnt(t *testing.T) {
	ok := []byte(`{"skill":{"name":"a"},"trust":{"state":"OK"}}`)
	if err := PruefeRumpf(ok); err != nil {
		t.Fatalf("gueltige Zeile abgelehnt: %v", err)
	}
	fremd := []byte(`{"skill":{"name":"a"},"trust":{"state":"OK"},"mastery":"fluent"}`)
	err := PruefeRumpf(fremd)
	if !errors.Is(err, ErrFremdesFeld) {
		t.Fatalf("fremdes Feld nicht abgelehnt: %v", err)
	}
	if !strings.Contains(err.Error(), "mastery") {
		t.Fatalf("Meldung nennt das Feld nicht: %v", err)
	}
}

func TestAC02_AlleViereBloeckeSindErlaubt(t *testing.T) {
	voll := []byte(`{"skill":{"name":"a"},"trust":{"state":"OK"},"quality":{"flags":["x"]},"policy":{"mandated":true}}`)
	if err := PruefeRumpf(voll); err != nil {
		t.Fatalf("vollstaendige Zeile abgelehnt: %v", err)
	}
}

// --- SPEC-0428 AC-04: gleicher Inhalt, gleicher Digest, andere Seq -------

func TestAC04_DigestIgnoriertSeqUndZeitpunkt(t *testing.T) {
	lauf1 := gueltigerBericht()
	lauf2 := gueltigerBericht()
	lauf2.Seq = 2
	lauf2.TakenAt = lauf1.TakenAt.Add(3 * time.Hour)
	if lauf1.Digest() != lauf2.Digest() {
		t.Fatalf("Digest haengt am Zeitpunkt oder an der Seq:\n  %s\n  %s", lauf1.Digest(), lauf2.Digest())
	}
	if lauf1.Seq == lauf2.Seq {
		t.Fatal("die Erhebung muss zaehlbar bleiben")
	}
}

func TestAC04_DigestAendertSichBeiInhalt(t *testing.T) {
	vorher := gueltigerBericht()
	nachher := gueltigerBericht()
	nachher.Zeilen[0].Trust.State = "BROKEN"
	if vorher.Digest() == nachher.Digest() {
		t.Fatal("ein geaenderter Vertrauenszustand aendert den Digest nicht")
	}
	dazu := gueltigerBericht()
	dazu.Zeilen = append(dazu.Zeilen, Zeile{Skill: SkillRef{Name: "rag"}, Trust: Trust{State: "OK"}})
	if vorher.Digest() == dazu.Digest() {
		t.Fatal("eine zusaetzliche Faehigkeit aendert den Digest nicht")
	}
}

func TestDigestIstReihenfolgeunabhaengig(t *testing.T) {
	a := gueltigerBericht()
	a.Zeilen = append(a.Zeilen, Zeile{Skill: SkillRef{Name: "rag"}, Trust: Trust{State: "OK"}})
	b := gueltigerBericht()
	b.Zeilen = []Zeile{
		{Skill: SkillRef{Name: "rag"}, Trust: Trust{State: "OK"}},
		a.Zeilen[0],
	}
	if a.Digest() != b.Digest() {
		t.Fatal("die Reihenfolge der Zeilen aendert den Digest")
	}
}
