// collect_test.go: SPEC-0428 AC-03, AC-04 und AC-07.
package envreport

import (
	"reflect"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/audit"
)

func auditReport(v ...audit.Verdict) audit.Report {
	return audit.Report{Verdicts: v, Total: len(v)}
}

func opts(seq int) Optionen {
	e, _ := NeueENV("kup", "bob", "MacBook-Pro-von-Bob")
	return Optionen{
		ENV:             e,
		Principal:       "bob",
		Jetzt:           time.Date(2026, 9, 13, 9, 0, 0, 0, time.UTC),
		AufbewahrungBis: time.Date(2027, 9, 13, 0, 0, 0, 0, time.UTC),
		Seq:             FesteSeq(seq),
		Einwilligung:    consent("bob"),
	}
}

// --- AC-03: jede Faehigkeit aus dem Audit steht im Bericht ---------------

func TestAC03_JedeFaehigkeitStehtImBericht(t *testing.T) {
	ar := auditReport(
		audit.Verdict{Name: "durchdenken", Tier: "user", State: audit.StateOK, BundleDigest: "sha256:aa", GovernanceLevel: "yellow"},
		audit.Verdict{Name: "rag", Tier: "user", State: audit.StateUnverified},
		audit.Verdict{Name: "browse", Tier: "plugin", State: audit.StateOK, GovernanceLevel: "green"},
	)
	rep, err := AusAudit(ar, opts(1))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Zeilen) != 3 {
		t.Fatalf("erwartet 3 Zeilen, sind %d", len(rep.Zeilen))
	}
	gesehen := map[string]Zeile{}
	for _, z := range rep.Zeilen {
		gesehen[z.Skill.Name] = z
	}
	for _, n := range []string{"durchdenken", "rag", "browse"} {
		if _, ok := gesehen[n]; !ok {
			t.Fatalf("%s fehlt im Bericht", n)
		}
	}
	if gesehen["durchdenken"].Trust.State != "OK" {
		t.Fatalf("Vertrauenszustand nicht uebernommen: %+v", gesehen["durchdenken"].Trust)
	}
	if gesehen["durchdenken"].Skill.Digest != "sha256:aa" {
		t.Fatal("Digest nicht uebernommen")
	}
	if gesehen["durchdenken"].Skill.Tier != "user" {
		t.Fatal("Tier nicht uebernommen")
	}
}

// Ein ungesetzter Ampelwert bleibt ungesetzt (SPEC-0427 E3).
func TestUngesetzteAmpelWirdNichtGruen(t *testing.T) {
	ar := auditReport(audit.Verdict{Name: "x", State: audit.StateOK, GovernanceLevel: ""})
	rep, err := AusAudit(ar, opts(1))
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Zeilen[0].Policy.GovernanceFloor; got != "" {
		t.Fatalf("ungesetzte Ampel wurde zu %q gemacht", got)
	}
}

// --- Die Gesamtlage wird abgeleitet, nicht geraten -----------------------

func TestLageWirdAbgeleitet(t *testing.T) {
	faelle := []struct {
		name  string
		state audit.State
		will  Posture
	}{
		{"alles ok", audit.StateOK, PostureOK},
		{"unverified ist drift", audit.StateUnverified, PostureDrift},
		{"below_min ist drift", audit.StateBelowMin, PostureDrift},
		{"broken ist contaminated", audit.StateBroken, PostureContaminated},
	}
	for _, f := range faelle {
		t.Run(f.name, func(t *testing.T) {
			rep, err := AusAudit(auditReport(audit.Verdict{Name: "x", State: f.state}), opts(1))
			if err != nil {
				t.Fatal(err)
			}
			if rep.Posture != f.will {
				t.Fatalf("posture = %q, erwartet %q", rep.Posture, f.will)
			}
		})
	}
}

func TestLeereUmgebungIstOkUndNichtDrift(t *testing.T) {
	rep, err := AusAudit(auditReport(), opts(1))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Posture != PostureOK {
		t.Fatalf("leere Umgebung = %q, erwartet ok", rep.Posture)
	}
}

func TestBrokenSchlaegtDrift(t *testing.T) {
	rep, err := AusAudit(auditReport(
		audit.Verdict{Name: "a", State: audit.StateUnverified},
		audit.Verdict{Name: "b", State: audit.StateBroken},
	), opts(1))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Posture != PostureContaminated {
		t.Fatalf("posture = %q, erwartet contaminated", rep.Posture)
	}
}

// --- AC-04: zwei Laeufe ohne Aenderung ----------------------------------

func TestAC04_ZweiLaeufeGleicherDigestAndereSeq(t *testing.T) {
	ar := auditReport(
		audit.Verdict{Name: "durchdenken", State: audit.StateOK, BundleDigest: "sha256:aa"},
		audit.Verdict{Name: "rag", State: audit.StateOK, BundleDigest: "sha256:bb"},
	)
	o1 := opts(1)
	o2 := opts(2)
	o2.Jetzt = o1.Jetzt.Add(2 * time.Hour)

	lauf1, err := AusAudit(ar, o1)
	if err != nil {
		t.Fatal(err)
	}
	lauf2, err := AusAudit(ar, o2)
	if err != nil {
		t.Fatal(err)
	}
	if lauf1.Digest() != lauf2.Digest() {
		t.Fatalf("gleicher Maschinenzustand, verschiedener Digest:\n  %s\n  %s", lauf1.Digest(), lauf2.Digest())
	}
	if lauf1.Seq == lauf2.Seq {
		t.Fatal("die Erhebung ist nicht zaehlbar")
	}
	if !lauf2.TakenAt.After(lauf1.TakenAt) {
		t.Fatal("der zweite Lauf ist nicht spaeter")
	}
}

// Die Reihenfolge, in der der Audit liefert, darf nichts aendern.
func TestErhebungIstReihenfolgeunabhaengig(t *testing.T) {
	a := auditReport(
		audit.Verdict{Name: "a", State: audit.StateOK},
		audit.Verdict{Name: "b", State: audit.StateOK},
	)
	b := auditReport(
		audit.Verdict{Name: "b", State: audit.StateOK},
		audit.Verdict{Name: "a", State: audit.StateOK},
	)
	ra, _ := AusAudit(a, opts(1))
	rb, _ := AusAudit(b, opts(1))
	if ra.Digest() != rb.Digest() {
		t.Fatal("die Lieferreihenfolge des Audits aendert den Digest")
	}
}

// --- Pflichtangaben der Erhebung selbst ----------------------------------

func TestErhebungOhneFristWirdAbgelehnt(t *testing.T) {
	o := opts(1)
	o.AufbewahrungBis = time.Time{}
	if _, err := AusAudit(auditReport(), o); err == nil {
		t.Fatal("Erhebung ohne Aufbewahrungsfrist wurde angenommen")
	}
}

func TestErhebungOhneSeqQuelleWirdAbgelehnt(t *testing.T) {
	o := opts(1)
	o.Seq = nil
	if _, err := AusAudit(auditReport(), o); err == nil {
		t.Fatal("Erhebung ohne SeqQuelle wurde angenommen")
	}
}

// --- AC-07: Luecken sind erkennbar, Loeschungen sind keine ---------------

func TestAC07_LueckenWerdenGemeldet(t *testing.T) {
	if got := FehlendeSeq([]int{1, 2, 4, 5}, nil); !reflect.DeepEqual(got, []int{3}) {
		t.Fatalf("Luecke nicht gemeldet: %v", got)
	}
	if got := FehlendeSeq([]int{1, 2, 3}, nil); got != nil {
		t.Fatalf("Luecke erfunden: %v", got)
	}
	if got := FehlendeSeq(nil, nil); got != nil {
		t.Fatalf("leere Folge meldet Luecken: %v", got)
	}
	if got := FehlendeSeq([]int{1, 5}, nil); !reflect.DeepEqual(got, []int{2, 3, 4}) {
		t.Fatalf("mehrere Luecken: %v", got)
	}
}

func TestAC11_EineLoeschungIstKeineLuecke(t *testing.T) {
	// Nach einer rechtmaessigen Loeschung von 2 und 3 darf die Meldung schweigen.
	if got := FehlendeSeq([]int{1, 4}, map[int]bool{2: true, 3: true}); got != nil {
		t.Fatalf("Loeschung als Luecke gemeldet: %v", got)
	}
	// Eine echte Luecke NEBEN einer Loeschung wird weiter gemeldet.
	if got := FehlendeSeq([]int{1, 5}, map[int]bool{2: true}); !reflect.DeepEqual(got, []int{3, 4}) {
		t.Fatalf("echte Luecke verschluckt: %v", got)
	}
}
