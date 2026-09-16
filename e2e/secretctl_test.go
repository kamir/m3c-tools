package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// End-to-End fuer secretctl (SPEC-0438), durch das ECHTE Binary.
//
// Dieses Werkzeug hat genau eine Zusage, die es nie brechen darf: es nennt
// Orte und Fingerabdruecke, aber niemals einen Wert. Diese Zusage ist im Typ
// `Secret` verankert (String, GoString, MarshalJSON und MarshalYAML liefern
// alle "<redacted>"), und sie ist damit gegen den haeufigsten Unfall gesichert:
// ein %v im falschen Moment.
//
// Ein Einheitentest kann diesen Typ pruefen. Er kann NICHT pruefen, ob irgendwo
// auf dem Weg vom Halteort zur Tabelle doch der rohe String durchgereicht wird.
// Genau dafuer ist dieser Test da: er gibt dem Befehl einen wiedererkennbaren
// Wert und durchsucht die vollstaendige Ausgabe danach.
//
// Der Anlass ist nicht theoretisch. Am 2026-09-15 ist in DIESER Sitzung ein
// ER1-Schluessel im Sitzungsprotokoll gelandet, weil eine Pipe mit einem
// Here-Dokument kollidierte. Die Regel "niemals ausgeben" ist billig zu
// formulieren und leicht zu verletzen, also wird sie gemessen.

// derWert ist absichtlich auffaellig: gaebe ihn irgendein Pfad aus, faellt er
// in jeder Ausgabe sofort auf.
const derWert = "m3cer1_GEHEIM_DIESER_WERT_DARF_NIE_ERSCHEINEN"

// registryMit baut ein HOME mit einer Registry und einem Halteort vom Typ
// `file`, der derWert traegt. Kein Netz, kein GCP, keine Keychain.
func registryMit(t *testing.T, rollen string, extraHalter string) (home, regPfad string) {
	t.Helper()
	home = t.TempDir()
	wertDatei := filepath.Join(home, "dienst.env")
	if err := os.WriteFile(wertDatei,
		[]byte("HARMLOS=ja\nER1_API_KEY="+derWert+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	regPfad = filepath.Join(home, "secrets.yaml")
	inhalt := `schema: m3c-secret-registry/v1
secrets:
  - name: e2e-geheimnis
    summary: Pruefstueck, kein echter Wert
    source:
      kind: gcp-secret-manager
      project: e2e-projekt-gibt-es-nicht
      secret: e2e-geheimnis
` + rollen + `    holders:
      - id: datei-auf-dieser-maschine
        kind: file
        path: ` + wertDatei + `
        key: ER1_API_KEY
` + extraHalter + `    probe:
      kind: http
      url: https://127.0.0.1:1/health
      header: X-API-KEY
      expect_ok: 200
      expect_revoked: 401
`
	if err := os.WriteFile(regPfad, []byte(inhalt), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, regPfad
}

// inventar ruft den Befehl mit der Reihenfolge, die er annimmt.
//
// BUG-0450: Flaggen muessen VOR dem Namen stehen. `secretctl inventory <name>
// --registry <pfad>` scheitert mit einer Verwendungszeile, weil Go's flag-Paket
// beim ersten Nicht-Flag anhaelt. Im selben Repo nimmt `skillctl publish <name>
// --kind agent` dieselbe Reihenfolge an, weil publish_cmds.go sie umsortiert.
//
// Der Helfer steht hier, damit die Reihenfolge an EINER Stelle festliegt: wird
// BUG-0450 behoben, aendert sich genau diese Zeile und kein Test.
func inventar(t *testing.T, home, reg string, args ...string) *CLIResult {
	t.Helper()
	voll := append([]string{"inventory", "--registry", reg}, args...)
	return RunTool(t, "secretctl", []string{"HOME=" + home}, voll...)
}

const gueltigeRollen = `    roles:
      - id: dienst-anmeldung
        was: Clients weisen sich damit aus
        bei_rotation: alle Clients brauchen den neuen Wert
`

// TestE2E_InventarNenntNieDenWert ist AC-6 von SPEC-0438, durch das echte
// Binary und ueber die volle Ausgabe.
func TestE2E_InventarNenntNieDenWert(t *testing.T) {
	home, reg := registryMit(t, gueltigeRollen, "")
	r := inventar(t, home, reg, "e2e-geheimnis")

	// Der Befehl MUSS durchlaufen, sonst prueft der Test nur eine
	// Fehlermeldung auf Abwesenheit des Wertes, was jede Fehlermeldung
	// bestehen wuerde.
	if r.ExitCode != 0 && !strings.Contains(r.Stdout, "datei-auf-dieser-maschine") {
		t.Fatalf("das Inventar kam nicht bis zur Ortstabelle (%d):\n%s", r.ExitCode, r.Stdout)
	}
	AssertNotContains(t, r, derWert)

	// Die Gegenprobe: der Ort wird genannt. Ein Befehl, der gar nichts sagt,
	// besteht die Schwaerzungspruefung ebenfalls und ist trotzdem nutzlos.
	if !strings.Contains(r.Stdout, "datei-auf-dieser-maschine") {
		t.Errorf("der Halteort fehlt in der Ausgabe:\n%s", r.Stdout)
	}
}

// TestE2E_InventarZeigtEinenFingerabdruck: die Schwaerzung darf nicht dadurch
// bestehen, dass gar nichts ueber den Wert gesagt wird. Ein Fingerabdruck ist
// die brauchbare Antwort.
func TestE2E_InventarZeigtEinenFingerabdruck(t *testing.T) {
	home, reg := registryMit(t, gueltigeRollen, "")
	r := inventar(t, home, reg, "e2e-geheimnis")
	AssertNotContains(t, r, derWert)
	if !strings.Contains(r.Stdout, "FINGERABDRUCK") {
		t.Fatalf("keine Fingerabdruckspalte:\n%s", r.Stdout)
	}
	// Zwoelf Hexziffern in einer Zeile, die den Halteort nennt.
	var gefunden bool
	for _, zeile := range strings.Split(r.Stdout, "\n") {
		if !strings.Contains(zeile, "datei-auf-dieser-maschine") {
			continue
		}
		for _, feld := range strings.Fields(zeile) {
			if len(feld) == 12 && strings.Trim(feld, "0123456789abcdef") == "" {
				gefunden = true
			}
		}
	}
	if !gefunden {
		t.Errorf("die Zeile des Halteorts nennt keinen Fingerabdruck:\n%s", r.Stdout)
	}
}

// TestE2E_RegistryOhneRollenWirdAbgewiesen ist die teuerste Lehre des
// 2026-09-15 als Tuersteher: das Inventar fand alle fuenfzehn Halteorte und
// keine einzige Folge. Die Rotation hat dann jedes Geraetetoken entwertet.
//
// Eine Registry ohne Rollen ist deshalb keine halbe Registry, sondern eine, die
// die Frage "was geht davon kaputt" nicht stellen kann.
func TestE2E_RegistryOhneRollenWirdAbgewiesen(t *testing.T) {
	home, reg := registryMit(t, "", "")
	r := inventar(t, home, reg, "e2e-geheimnis")
	if r.ExitCode == 0 {
		t.Fatalf("eine Registry ohne Rollen wurde angenommen:\n%s", r.Stdout)
	}
	if !strings.Contains(r.Stdout, "roles") && !strings.Contains(r.Stdout, "Rolle") &&
		!strings.Contains(r.Stdout, "names no roles") {
		t.Errorf("die Meldung sagt nicht, dass die Rollen fehlen:\n%s", r.Stdout)
	}
}

// TestE2E_RolleOhneFolgeWirdAbgewiesen: eine Rolle ohne bei_rotation ist ein
// Etikett und keine Warnung (SPEC-0438 §8b).
func TestE2E_RolleOhneFolgeWirdAbgewiesen(t *testing.T) {
	ohneFolge := `    roles:
      - id: dienst-anmeldung
        was: Clients weisen sich damit aus
`
	home, reg := registryMit(t, ohneFolge, "")
	r := inventar(t, home, reg, "e2e-geheimnis")
	if r.ExitCode == 0 {
		t.Fatalf("eine Rolle ohne bei_rotation wurde angenommen:\n%s", r.Stdout)
	}
	if !strings.Contains(r.Stdout, "bei_rotation") {
		t.Errorf("die Meldung nennt das fehlende Feld nicht:\n%s", r.Stdout)
	}
}

// TestE2E_UnbekanntesGeheimnisNenntDieBekannten: der Fehlerfall, den ein Mensch
// wirklich trifft, ist ein Tippfehler im Namen.
func TestE2E_UnbekanntesGeheimnisNenntDieBekannten(t *testing.T) {
	home, reg := registryMit(t, gueltigeRollen, "")
	r := inventar(t, home, reg, "e2e-gehaimnis")
	if r.ExitCode == 0 {
		t.Fatalf("ein unbekannter Name wurde angenommen:\n%s", r.Stdout)
	}
	if !strings.Contains(r.Stdout, "e2e-geheimnis") {
		t.Errorf("die Meldung nennt die bekannten Namen nicht:\n%s", r.Stdout)
	}
	AssertNotContains(t, r, derWert)
}
