// er1store_test.go: der Netzschreibpfad, mit einem Uploader-Doppel geprueft.
//
// Wichtig an diesen Tests: sie belegen, dass NICHTS gesendet wird, wenn eine
// Grenze faellt. Ein Test, der nur das Gutschreiben prueft, laesst offen, ob
// die Grenze vor oder nach dem Netzaufruf greift, und das ist der ganze
// Unterschied.
package envreport

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeUp struct {
	calls []struct{ Body, Tags, Ctx, Name string }
	fail  error
}

func (f *fakeUp) UploadText(body, filename, tags, contentType, ctxID string) (string, error) {
	if f.fail != nil {
		return "", f.fail
	}
	f.calls = append(f.calls, struct{ Body, Tags, Ctx, Name string }{body, tags, ctxID, filename})
	return "doc-" + filename, nil
}

type fakeLs struct {
	items   []RohPosten
	koerper map[string]string
}

func (f *fakeLs) LadeRumpf(ctxID, docID string) (string, error) {
	if b, ok := f.koerper[docID]; ok {
		return b, nil
	}
	return "", errors.New("kein Rumpf fuer " + docID)
}

func (f *fakeLs) ListByTags(ctxID string, tags []string) ([]RohPosten, error) {
	var out []RohPosten
	for _, p := range f.items {
		alle := true
		for _, want := range tags {
			hat := false
			for _, t := range p.Tags {
				if t == want {
					hat = true
					break
				}
			}
			if !hat {
				alle = false
				break
			}
		}
		if alle {
			out = append(out, p)
		}
	}
	return out, nil
}

func store(up *fakeUp, ls *fakeLs) *ER1Store {
	return &ER1Store{
		ContextID: "kup___skillenv", Up: up, Ls: ls,
		Jetzt: func() time.Time { return time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC) },
	}
}

func TestER1_AblageSchreibtAnkerUndBericht(t *testing.T) {
	up, ls := &fakeUp{}, &fakeLs{}
	a, err := store(up, ls).Ablegen(bericht(1), consent("bob"))
	if err != nil {
		t.Fatal(err)
	}
	if len(up.calls) != 2 {
		t.Fatalf("erwartet 2 Schreibvorgaenge (Anker + Bericht), waren %d", len(up.calls))
	}
	if !strings.Contains(up.calls[0].Tags, "skill-env-anchor") {
		t.Fatalf("erster Schreibvorgang ist kein Anker: %s", up.calls[0].Tags)
	}
	if !strings.Contains(up.calls[1].Tags, "skill-env-report") {
		t.Fatalf("zweiter Schreibvorgang ist kein Bericht: %s", up.calls[1].Tags)
	}
	if !strings.Contains(up.calls[1].Tags, "link/parent/kup___skillenv/") {
		t.Fatalf("der Bericht haengt nicht am Anker: %s", up.calls[1].Tags)
	}
	if a.DocID == "" || a.Seq != 1 {
		t.Fatalf("Rueckgabe unvollstaendig: %+v", a)
	}
}

// Der Kern: faellt eine Grenze, wird NICHT gesendet.
func TestER1_KeinNetzaufrufWennEineGrenzeFaellt(t *testing.T) {
	faelle := []struct {
		name string
		r    func() Report
		e    Einwilligung
	}{
		{"ohne Einwilligung", func() Report { return bericht(1) }, Einwilligung{}},
		{"fremde Einwilligung", func() Report { return bericht(1) }, consent("wer-anders")},
		{"Klartext-Host", func() Report {
			r := bericht(1)
			r.ENV = "env:kup/bob/MacBook-Pro-von-Bob"
			return r
		}, consent("bob")},
		{"ohne Aufbewahrungsfrist", func() Report {
			r := bericht(1)
			r.AufbewahrungBis = time.Time{}
			return r
		}, consent("bob")},
		{"Quelltext im Rumpf", func() Report {
			r := bericht(1)
			r.Zeilen[0].Trust.Reason = strings.Repeat("y", 600)
			return r
		}, consent("bob")},
	}
	for _, f := range faelle {
		t.Run(f.name, func(t *testing.T) {
			up, ls := &fakeUp{}, &fakeLs{}
			if _, err := store(up, ls).Ablegen(f.r(), f.e); err == nil {
				t.Fatal("die Ablage wurde angenommen")
			}
			if len(up.calls) != 0 {
				t.Fatalf("es wurde trotz gefallener Grenze gesendet: %d Aufrufe", len(up.calls))
			}
		})
	}
}

func TestER1_ZweiterBerichtUeberschreibtNicht(t *testing.T) {
	up := &fakeUp{}
	ls := &fakeLs{items: []RohPosten{{DocID: "doc-alt", Tags: []string{
		"skill-env-report", "env:kup/bob/" + HashHost("kup", "MacBook-Pro-von-Bob"),
		"report-seq:1",
	}}}}
	s := store(up, ls)
	// seq 1 liegt schon: abgelehnt, und nichts gesendet.
	_, err := s.Ablegen(bericht(1), consent("bob"))
	if !errors.Is(err, ErrSchonVorhanden) {
		t.Fatalf("doppelte Seq: %v", err)
	}
	if len(up.calls) != 0 {
		t.Fatalf("es wurde trotz vorhandener Seq gesendet: %d", len(up.calls))
	}
	// seq 2 geht durch.
	if _, err := s.Ablegen(bericht(2), consent("bob")); err != nil {
		t.Fatalf("seq 2 abgelehnt: %v", err)
	}
}

func TestER1_AnkerWirdWiederverwendet(t *testing.T) {
	up := &fakeUp{}
	ls := &fakeLs{items: []RohPosten{{DocID: "anker-vorhanden", Tags: []string{
		"skill-env-anchor", "env:kup/bob/" + HashHost("kup", "MacBook-Pro-von-Bob"),
	}}}}
	s := store(up, ls)
	id, err := s.Anker(bericht(1).ENV)
	if err != nil {
		t.Fatal(err)
	}
	if id != "anker-vorhanden" {
		t.Fatalf("Anker neu angelegt statt wiederverwendet: %s", id)
	}
	if len(up.calls) != 0 {
		t.Fatal("ein vorhandener Anker wurde neu geschrieben")
	}
}

func TestER1_NaechsteSeqKommtAusDerAblage(t *testing.T) {
	ls := &fakeLs{items: []RohPosten{
		{DocID: "a", Tags: []string{"skill-env-report", "env:kup/bob/" + HashHost("kup", "MacBook-Pro-von-Bob"), "report-seq:1"}},
		{DocID: "b", Tags: []string{"skill-env-report", "env:kup/bob/" + HashHost("kup", "MacBook-Pro-von-Bob"), "report-seq:2"}},
	}}
	n, err := store(&fakeUp{}, ls).NaechsteSeq(bericht(1).ENV)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("naechste Nummer ist %d, erwartet 3", n)
	}
}

// Der geschriebene Rumpf traegt keinen Klarnamen und ist gueltiges JSON.
func TestER1_RumpfIstJSONUndOhneKlarnamen(t *testing.T) {
	up := &fakeUp{}
	if _, err := store(up, &fakeLs{}).Ablegen(bericht(1), consent("bob")); err != nil {
		t.Fatal(err)
	}
	rumpf := up.calls[1].Body
	if strings.Contains(rumpf, "MacBook") {
		t.Fatal("der Klarname des Rechners steht im geschriebenen Rumpf")
	}
	var zurueck Report
	if err := json.Unmarshal([]byte(rumpf), &zurueck); err != nil {
		t.Fatalf("der Rumpf ist kein gueltiges JSON: %v", err)
	}
	if zurueck.Digest() != bericht(1).Digest() {
		t.Fatal("der geschriebene Rumpf ergibt einen anderen Digest")
	}
}

func TestER1_OhneContextIDKeinSchreiben(t *testing.T) {
	s := &ER1Store{Up: &fakeUp{}, Ls: &fakeLs{}}
	if _, err := s.Ablegen(bericht(1), consent("bob")); err == nil {
		t.Fatal("ohne ContextID geschrieben")
	}
}

// Der ER1Store erfuellt denselben Vertrag wie der MemStore.
func TestER1_ErfuelltDenStoreVertrag(t *testing.T) {
	var _ Store = (*ER1Store)(nil)
	var _ Store = (*MemStore)(nil)
	var _ SeqQuelle = (*ER1Store)(nil)
	var _ SeqQuelle = (*MemStore)(nil)
}

// --- T-03: die Leseseite prueft, statt zu glauben ------------------------

func signierterRumpf(t *testing.T, priv ed25519.PrivateKey, mutieren func(*Report)) string {
	t.Helper()
	r := bericht(1)
	if err := Signiere(RohSchluessel(priv), &r, "id:bob@m3c"); err != nil {
		t.Fatal(err)
	}
	if mutieren != nil {
		mutieren(&r) // NACH dem Signieren: genau der Angriff, um den es geht
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestT03_UnveraenderterPostenLiestSichZurueck(t *testing.T) {
	pub, priv := schluessel(t)
	ls := &fakeLs{koerper: map[string]string{"doc-1": signierterRumpf(t, priv, nil)}}
	r, err := store(&fakeUp{}, ls).Hole("doc-1", pub)
	if err != nil {
		t.Fatalf("gueltiger Posten abgelehnt: %v", err)
	}
	if r.Seq != 1 {
		t.Fatalf("falscher Bericht geladen: %+v", r.Seq)
	}
}

func TestT03_NachtraeglichGeaenderterRumpfWirdAbgelehnt(t *testing.T) {
	pub, priv := schluessel(t)
	faelle := map[string]func(*Report){
		"Vertrauenszustand gedreht": func(r *Report) { r.Zeilen[0].Trust.State = "BROKEN" },
		"Skill hinzugefuegt": func(r *Report) {
			r.Zeilen = append(r.Zeilen, Zeile{Skill: SkillRef{Name: "x"}, Trust: Trust{State: "OK"}})
		},
		"Prinzipal getauscht":    func(r *Report) { r.Principal = "jemand-anders" },
		"Einwilligung geschoent": func(r *Report) { r.Einwilligung.Beleg = "angeblich zugestimmt" },
	}
	for name, mut := range faelle {
		t.Run(name, func(t *testing.T) {
			ls := &fakeLs{koerper: map[string]string{"doc-1": signierterRumpf(t, priv, mut)}}
			if _, err := store(&fakeUp{}, ls).Hole("doc-1", pub); err == nil {
				t.Fatal("der manipulierte Posten wurde angenommen")
			}
		})
	}
}

func TestT03_OhneSchluesselWirdDieSchwaechereAuskunftGemeldet(t *testing.T) {
	_, priv := schluessel(t)
	ls := &fakeLs{koerper: map[string]string{"doc-1": signierterRumpf(t, priv, nil)}}
	r, err := store(&fakeUp{}, ls).Hole("doc-1", nil)
	if !errors.Is(err, ErrSignaturUngeprueft) {
		t.Fatalf("ohne Schluessel: %v, erwartet ErrSignaturUngeprueft", err)
	}
	if r.Seq != 1 {
		t.Fatal("der Bericht wurde trotz Einschraenkung nicht geliefert")
	}
}

func TestT03_AltpostenOhneEinwilligungWirdAbgelehnt(t *testing.T) {
	pub, _ := schluessel(t)
	alt := `{"env":"env:kup/bob/0123456789abcdef","principal":"bob","report_seq":1,` +
		`"taken_at":"2026-09-13T08:00:00Z","posture":"drift",` +
		`"aufbewahrung_bis":"2027-09-13T00:00:00Z","zeilen":[]}`
	ls := &fakeLs{koerper: map[string]string{"alt": alt}}
	_, err := store(&fakeUp{}, ls).Hole("alt", pub)
	if !errors.Is(err, ErrEinwilligungNichtImRumpf) {
		t.Fatalf("Altposten: %v, erwartet ErrEinwilligungNichtImRumpf", err)
	}
}
