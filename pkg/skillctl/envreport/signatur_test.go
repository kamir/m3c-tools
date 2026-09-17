// signatur_test.go: die Abnahmekriterien von E-I (PO-Review 2026-09-13).
//
// Der Kern ist die Negativprobe. Ein Test, der nur zeigt, dass eine gueltige
// Signatur verifiziert, belegt nichts: er laeuft auch gruen, wenn die
// Pruefung immer true sagt.
package envreport

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func schluessel(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// --- T-01: Signatur ------------------------------------------------------

func TestT01_SignierterBerichtVerifiziert(t *testing.T) {
	pub, priv := schluessel(t)
	r := gueltigerBericht()
	if err := Signiere(RohSchluessel(priv), &r, "id:bob@m3c"); err != nil {
		t.Fatal(err)
	}
	if r.Signatur == "" || r.SignerID != "id:bob@m3c" {
		t.Fatalf("Signatur oder Signierer fehlt: %+v", r.SignerID)
	}
	if err := PruefeSignatur(pub, r); err != nil {
		t.Fatalf("gueltige Signatur abgelehnt: %v", err)
	}
}

// Die entscheidende Probe: EIN geaendertes Zeichen bricht die Signatur.
func TestT01_EinGeaendertesZeichenBrichtDieSignatur(t *testing.T) {
	pub, priv := schluessel(t)
	faelle := []struct {
		name    string
		aendern func(*Report)
	}{
		{"Skillname", func(r *Report) { r.Zeilen[0].Skill.Name = "durchdenkeN" }},
		{"Vertrauenszustand", func(r *Report) { r.Zeilen[0].Trust.State = "BROKEN" }},
		{"Digest einer Zeile", func(r *Report) { r.Zeilen[0].Skill.Digest = "sha256:ab" }},
		{"Prinzipal", func(r *Report) { r.Principal = "jemand-anders" }},
		{"Lage", func(r *Report) { r.Posture = PostureOK }},
		{"Aufbewahrungsfrist", func(r *Report) { r.AufbewahrungBis = r.AufbewahrungBis.AddDate(9, 0, 0) }},
		{"Einwilligungsbeleg", func(r *Report) { r.Einwilligung.Beleg = "etwas anderes" }},
		{"eine Zeile entfernt", func(r *Report) { r.Zeilen = nil }},
	}
	for _, f := range faelle {
		t.Run(f.name, func(t *testing.T) {
			r := gueltigerBericht()
			r.Posture = PostureDrift // damit der Lage-Fall etwas aendert
			if err := Signiere(RohSchluessel(priv), &r, "id:bob@m3c"); err != nil {
				t.Fatal(err)
			}
			f.aendern(&r)
			if err := PruefeSignatur(pub, r); err == nil {
				t.Fatalf("Aenderung an %q blieb unbemerkt", f.name)
			}
		})
	}
}

// Fehlende Signatur und falsche Signatur sind verschiedene Fehler.
func TestT01_FehlendUndFalschSindVerschieden(t *testing.T) {
	pub, priv := schluessel(t)
	r := gueltigerBericht()
	if err := PruefeSignatur(pub, r); err != ErrSignaturFehlt {
		t.Fatalf("ohne Signatur: %v, erwartet ErrSignaturFehlt", err)
	}
	if err := Signiere(RohSchluessel(priv), &r, "id:bob@m3c"); err != nil {
		t.Fatal(err)
	}
	fremd, _ := schluessel(t)
	if err := PruefeSignatur(fremd, r); err != ErrSignaturUngueltig {
		t.Fatalf("fremder Schluessel: %v, erwartet ErrSignaturUngueltig", err)
	}
}

// Die Signatur ueberlebt den Weg durch JSON, sonst nuetzt sie in ER1 nichts.
func TestT01_SignaturUeberlebtDenRundlauf(t *testing.T) {
	pub, priv := schluessel(t)
	r := gueltigerBericht()
	if err := Signiere(RohSchluessel(priv), &r, "id:bob@m3c"); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var zurueck Report
	if err := json.Unmarshal(b, &zurueck); err != nil {
		t.Fatal(err)
	}
	if err := PruefeSignatur(pub, zurueck); err != nil {
		t.Fatalf("Signatur ueberlebt den Rundlauf nicht: %v", err)
	}
}

// Die Signatur deckt Seq und Zeitpunkt ab, der Digest nicht. Das ist die
// Arbeitsteilung und kein Versehen.
func TestT01_SignaturUnterscheidetWasDerDigestGleichLaesst(t *testing.T) {
	pub, priv := schluessel(t)
	a := gueltigerBericht()
	b := gueltigerBericht()
	b.Seq = 2
	b.TakenAt = a.TakenAt.Add(time.Hour)
	if a.Digest() != b.Digest() {
		t.Fatal("Vorbedingung verletzt: der Digest sollte gleich sein")
	}
	if err := Signiere(RohSchluessel(priv), &a, "id:bob@m3c"); err != nil {
		t.Fatal(err)
	}
	sigA := a.Signatur
	if err := Signiere(RohSchluessel(priv), &b, "id:bob@m3c"); err != nil {
		t.Fatal(err)
	}
	if sigA == b.Signatur {
		t.Fatal("zwei Posten mit gleichem Inhalt tragen dieselbe Signatur")
	}
	if err := PruefeSignatur(pub, b); err != nil {
		t.Fatal(err)
	}
}

func TestT01_SignierenBrauchtEinenSignierer(t *testing.T) {
	_, priv := schluessel(t)
	r := gueltigerBericht()
	if err := Signiere(RohSchluessel(priv), &r, ""); err == nil {
		t.Fatal("ohne Signierer-Kennung signiert")
	}
}

// --- T-02 und T-04: die Einwilligung im Rumpf ----------------------------

func TestT02_AblageBettetDieEinwilligungEin(t *testing.T) {
	s := NewMemStore("kup___skillenv")
	r := bericht(1)
	r.Einwilligung = nil // die Ablage muss sie selbst setzen
	if _, err := s.Ablegen(r, consent("bob")); err != nil {
		t.Fatal(err)
	}
}

func TestT02_DerParameterSchlaegtEinAbweichendesFeld(t *testing.T) {
	// Zwei Quellen fuer denselben Rechtsgrund waeren eine zu viel: der
	// Parameter gewinnt, und zwar auch dann, wenn das Feld guenstiger aussieht.
	s := NewMemStore("kup___skillenv")
	r := bericht(1)
	gut := consent("bob")
	r.Einwilligung = &gut
	if _, err := s.Ablegen(r, Einwilligung{}); err == nil {
		t.Fatal("das eingebettete Feld hat den leeren Parameter geschlagen")
	}
}

func TestT04_BerichtOhneEinwilligungIstUngueltig(t *testing.T) {
	r := gueltigerBericht()
	r.Einwilligung = nil
	err := r.Validate()
	if err != ErrEinwilligungNichtImRumpf {
		t.Fatalf("Validate() = %v, erwartet ErrEinwilligungNichtImRumpf", err)
	}
}

func TestT04_EingebetteteEinwilligungMussZumPrinzipalPassen(t *testing.T) {
	r := gueltigerBericht()
	fremd := consent("jemand-anders")
	r.Einwilligung = &fremd
	if err := r.Validate(); err == nil {
		t.Fatal("Bericht mit fremder Einwilligung angenommen")
	}
}

// Der Altposten in ER1 traegt keine Einwilligung. Er wird nicht nachtraeglich
// geheilt, er wird erkannt.
func TestT04_AltpostenWirdErkanntUndNichtGeheilt(t *testing.T) {
	alt := []byte(`{"env":"env:kup/bob/0123456789abcdef","principal":"bob",` +
		`"report_seq":1,"taken_at":"2026-09-13T08:00:00Z","posture":"drift",` +
		`"aufbewahrung_bis":"2027-09-13T00:00:00Z","zeilen":[]}`)
	var r Report
	if err := json.Unmarshal(alt, &r); err != nil {
		t.Fatal(err)
	}
	err := r.Validate()
	if err != ErrEinwilligungNichtImRumpf {
		t.Fatalf("Altposten: %v, erwartet ErrEinwilligungNichtImRumpf", err)
	}
	if !strings.Contains(err.Error(), "consent") {
		t.Fatalf("die Meldung nennt den Gegenstand nicht: %q", err)
	}
}
