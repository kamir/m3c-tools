// verified_producer_test.go: BUG-0253 seq 3, der Abnahmebeleg.
//
// Bis zum 2026-09-14 meldete `skillctl audit` auf dieser Maschine 0 OK von
// 101, und konnte es nicht anders: der Scanner suchte das Buendel neben dem
// Skillordner (der Installierer legt es hinein) und verlangte eine detached
// Signatur (die kein Installationspfad schreibt). Der Zustand `verified`
// hatte keinen Erzeuger.
//
// Dieser Test baut GENAU das Ergebnis eines Trust-Mode-Installs nach, so wie
// registry.ConfirmInstall es hinterlaesst (das verifizierte .skb im
// Zielordner, daneben der Provenance-Abzug .m3c-provenance.json), und geht
// dann den vollen Urteilsweg: scanner.Scan, AnnotateTrust, audit.Compute.
//
// Der Beleg ist nicht "der Scanner findet etwas", sondern "der AUDIT sagt
// OK". Das ist der Unterschied zwischen einer gefundenen Datei und einem
// Vertrauensurteil.
package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
	"github.com/kamir/m3c-tools/pkg/skillctl/scanner"
)

// installiertWie baut den Zustand nach, den ein Trust-Mode-Install erzeugt.
func installiertWie(t *testing.T, name, govLevel string, mitAbzug bool) string {
	t.Helper()
	home := t.TempDir()
	skills := filepath.Join(home, ".claude", "skills")
	dir := filepath.Join(skills, name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	fm := "---\nname: " + name + "\ndescription: Testskill fuer den Abnahmebeleg\n"
	if govLevel != "" {
		fm += "governance_level: " + govLevel + "\n"
	}
	fm += "---\n\nKoerper.\n"
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(fm), 0o644); err != nil {
		t.Fatal(err)
	}
	// Das verifizierte Buendel, INNEN und 0600: so stasht install.go.
	if err := os.WriteFile(filepath.Join(dir, name+"-0.0.0.skb"), []byte("PK\x03\x04 verifiziertes Buendel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if mitAbzug {
		// Der Abzug, den der Trust-Mode-Pfad schreibt.
		abzug := `{"schema_version":"1.0.0","trust_roots_fingerprint":"sha256:testfp",` +
			`"bundle_digest":"sha256:test","installed_at":"2026-09-14T12:00:00Z"}`
		if err := os.WriteFile(filepath.Join(dir, ".m3c-provenance.json"), []byte(abzug), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return skills
}

func urteil(t *testing.T, skillsDir string, minimum MinimumLevel) Report {
	t.Helper()
	sc := &scanner.Scanner{
		Roots:     []scanner.ScanRoot{{Path: skillsDir, Tier: scanner.TierUser}},
		WithTrust: true,
	}
	inv, err := sc.Scan()
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return Compute(inv, minimum)
}

// --- Der Abnahmebeleg ----------------------------------------------------

func TestSeq3_NachTrustModeInstallMeldetAuditOK(t *testing.T) {
	skills := installiertWie(t, "rollback", "green", true)
	r := urteil(t, skills, MinGreen)

	if r.Total != 1 {
		t.Fatalf("erwartet genau eine Faehigkeit, gefunden %d", r.Total)
	}
	got := r.Verdicts[0]
	if got.State != StateOK {
		t.Fatalf("Urteil = %s (%s), erwartet OK.\n"+
			"Das ist der Abnahmebeleg von BUG-0253 seq 3: vor der Aenderung war 0 OK von 101 moeglich.",
			got.State, got.Reason)
	}
	if r.Counts[StateOK] != 1 {
		t.Fatalf("Zaehlwerk meldet %d OK", r.Counts[StateOK])
	}
	if r.ExitCode != 0 {
		t.Fatalf("Exit-Code %d, erwartet 0", r.ExitCode)
	}
}

// Ohne den Abzug bleibt es BROKEN: der Beleg ist der Abzug, nicht der Ordner.
func TestSeq3_OhneAbzugKeinOK(t *testing.T) {
	skills := installiertWie(t, "rollback", "green", false)
	r := urteil(t, skills, MinGreen)
	if r.Verdicts[0].State == StateOK {
		t.Fatal("OK ohne jeden Beleg gemeldet")
	}
}

// Die Ampel wird weiter geprueft: ein Abzug hebt den Boden nicht auf.
func TestSeq3_AbzugHebtDenAmpelbodenNichtAuf(t *testing.T) {
	skills := installiertWie(t, "rollback", "red", true)
	r := urteil(t, skills, MinGreen)
	if r.Verdicts[0].State != StateBelowMin {
		t.Fatalf("Urteil = %s, erwartet BELOW_MIN: ein Provenance-Abzug belegt "+
			"einen gelaufenen Installationspfad, er ersetzt keine Governance-Entscheidung",
			r.Verdicts[0].State)
	}
}

// Eine ungesetzte Stufe bleibt unter jedem gesetzten Boden (SPEC-0427 E3).
func TestSeq3_UngesetzteAmpelBleibtUnterDemBoden(t *testing.T) {
	skills := installiertWie(t, "rollback", "", true)
	r := urteil(t, skills, MinGreen)
	if r.Verdicts[0].State == StateOK {
		t.Fatal("ohne gesetzte Ampel OK gemeldet; unbeurteilt ist nicht gruen")
	}
}

// Ohne Boden genuegt der Abzug: das ist der Normalfall eines Nutzers, der
// keine Mindeststufe gesetzt hat.
func TestSeq3_OhneBodenGenuegtDerAbzug(t *testing.T) {
	skills := installiertWie(t, "rollback", "", true)
	r := urteil(t, skills, MinimumLevel(""))
	if r.Verdicts[0].State != StateOK {
		t.Fatalf("Urteil = %s (%s), erwartet OK ohne gesetzten Boden",
			r.Verdicts[0].State, r.Verdicts[0].Reason)
	}
}

var _ = model.SkillTypeClaudeCodeSkill // Paket bewusst referenziert
