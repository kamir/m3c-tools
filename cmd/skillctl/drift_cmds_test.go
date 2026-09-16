package main

import (
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// Die Urteile von `skillctl drift`, an der reinen Funktion geprueft.
//
// Der Anlass steht im Kopf von drift_cmds.go: am 2026-09-15 wurden zwei
// Maschinen von Hand ueber 110 Pruefsummen verglichen. Ein Vergleich, den
// niemand wiederholen kann, ist kein Tor, sondern eine Anekdote.

func lokal(kind, name, digest string) driftRow {
	return driftRow{Name: name, Kind: kind, Local: digest}
}

func fern(kind, name, digest string) registry.SkillView {
	return registry.SkillView{Kind: kind, Name: name, LatestDigest: "sha256:" + digest}
}

func urteil(t *testing.T, rows []driftRow, kind, name string) string {
	t.Helper()
	for _, r := range rows {
		if r.Kind == kind && r.Name == name {
			return r.State
		}
	}
	t.Fatalf("keine Zeile fuer %s:%s", kind, name)
	return ""
}

func TestDriftUrteile(t *testing.T) {
	local := map[string]driftRow{
		"skill:gleich":       lokal(skillbundle.KindSkill, "gleich", "aaaaaaaaaaaa"),
		"skill:abweichend":   lokal(skillbundle.KindSkill, "abweichend", "bbbbbbbbbbbb"),
		"skill:ohneNachweis": lokal(skillbundle.KindSkill, "ohneNachweis", driftUnvouched),
		"skill:unbekannt":    lokal(skillbundle.KindSkill, "unbekannt", "cccccccccccc"),
		"agent:derAgent":     lokal(skillbundle.KindAgent, "derAgent", "dddddddddddd"),
	}
	remote := map[string]registry.SkillView{
		"skill:gleich":       fern(skillbundle.KindSkill, "gleich", "aaaaaaaaaaaa"),
		"skill:abweichend":   fern(skillbundle.KindSkill, "abweichend", "999999999999"),
		"skill:ohneNachweis": fern(skillbundle.KindSkill, "ohneNachweis", "aaaaaaaaaaaa"),
		"skill:nurImKatalog": fern(skillbundle.KindSkill, "nurImKatalog", "eeeeeeeeeeee"),
		"agent:derAgent":     fern(skillbundle.KindAgent, "derAgent", "dddddddddddd"),
	}
	rows := compareDrift(local, remote)

	for _, tc := range []struct{ kind, name, want string }{
		{skillbundle.KindSkill, "gleich", driftCurrent},
		{skillbundle.KindSkill, "abweichend", driftStale},
		{skillbundle.KindSkill, "unbekannt", driftUncataloged},
		{skillbundle.KindSkill, "nurImKatalog", driftMissing},
		{skillbundle.KindAgent, "derAgent", driftCurrent},
	} {
		if got := urteil(t, rows, tc.kind, tc.name); got != tc.want {
			t.Errorf("%s:%s -> %q, erwartet %q", tc.kind, tc.name, got, tc.want)
		}
	}

	if len(rows) != 6 {
		t.Errorf("%d Zeilen, erwartet 6 (5 lokale plus 1 nur im Katalog)", len(rows))
	}
}

// TestOhneNachweisGiltNieAlsAktuell ist die tragende Zusicherung.
//
// Ein Artefakt ohne Herkunftsnachweis KOENNTE zufaellig stimmen. Es als
// "aktuell" zu melden hiesse, eine Uebereinstimmung zu behaupten, die nichts
// belegt. Genau diese Art von zuversichtlicher Meldung ohne Wissen hat am
// 2026-09-15 mehrfach in die Irre gefuehrt.
func TestOhneNachweisGiltNieAlsAktuell(t *testing.T) {
	local := map[string]driftRow{
		"skill:x": lokal(skillbundle.KindSkill, "x", driftUnvouched),
	}
	remote := map[string]registry.SkillView{
		"skill:x": fern(skillbundle.KindSkill, "x", "aaaaaaaaaaaa"),
	}
	if got := urteil(t, compareDrift(local, remote), skillbundle.KindSkill, "x"); got != driftUnvouched {
		t.Fatalf("ohne Nachweis wurde als %q gemeldet, erwartet %q", got, driftUnvouched)
	}
}

// TestArtTrenntGleichnamige: ein Skill und ein Agent desselben Namens sind
// zwei Artefakte und duerfen sich nicht ueberschreiben (SPEC-0432 AC-6).
func TestArtTrenntGleichnamige(t *testing.T) {
	local := map[string]driftRow{
		"skill:helper": lokal(skillbundle.KindSkill, "helper", "aaaaaaaaaaaa"),
		"agent:helper": lokal(skillbundle.KindAgent, "helper", "bbbbbbbbbbbb"),
	}
	remote := map[string]registry.SkillView{
		"skill:helper": fern(skillbundle.KindSkill, "helper", "aaaaaaaaaaaa"),
		"agent:helper": fern(skillbundle.KindAgent, "helper", "999999999999"),
	}
	rows := compareDrift(local, remote)
	if len(rows) != 2 {
		t.Fatalf("%d Zeilen, erwartet 2", len(rows))
	}
	if got := urteil(t, rows, skillbundle.KindSkill, "helper"); got != driftCurrent {
		t.Errorf("der Skill helper -> %q", got)
	}
	if got := urteil(t, rows, skillbundle.KindAgent, "helper"); got != driftStale {
		t.Errorf("der Agent helper -> %q", got)
	}
}
