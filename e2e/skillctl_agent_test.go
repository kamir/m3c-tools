package e2e

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// End-to-End für die Agentenverteilung (SPEC-0432), durch das ECHTE Binary.
//
// Diese Tests laufen ohne Netz. Sie decken die Hälfte ab, die ohne Katalog
// auskommt: Packen, Ablehnen, die Gestalt des Bündels. Die andere Hälfte
// (Zulassen, Attestieren, Holen) braucht einen Katalog und ist dort zu Hause,
// wo einer steht.
//
// Warum das trotzdem E2E ist und nicht bloß ein weiterer Einheitentest: es geht
// durch Flaggenlesen, Profilauflösung, Pfadauflösung und Packer. Genau an
// diesen Nähten saßen am 2026-09-15 drei Fehler, die kein Einheitentest fand.

// eigenesArbeitsverzeichnis isoliert einen Test.
//
// Der Packer schreibt nach ./<name>@<version>.skb, also in das
// Arbeitsverzeichnis des Prozesses. Ohne Isolierung schreiben alle Tests in
// dasselbe Verzeichnis, und ein Test, der vor seinem Aufraeumen abbricht,
// hinterlaesst eine Datei, die der naechste fuer seine eigene haelt. Genau das
// ist beim ersten Lauf passiert: ein Fehlalarm aus geteiltem Zustand.
func eigenesArbeitsverzeichnis(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
}

// signierfaehigesHome legt einen Wegwerf-Signierschluessel an und liefert die
// Umgebung, mit der publish ihn findet.
//
// Zwei Gruende, warum das kein Beiwerk ist:
//
//  1. --dry-run laesst den POST aus, packt aber und laedt DANN den Schluessel.
//     Ein frisches HOME hat keinen, also scheitert der Befehl mit Ausstieg 1,
//     NACHDEM das Buendel schon geschrieben ist. Ein Test ohne Schluessel misst
//     den fehlenden Schluessel statt des Packers.
//  2. Der Schluessel ist ein Wegwerfschluessel im Temp-HOME, nie der des
//     Betreibers. Ein Test, der den echten Signierschluessel braucht, laeuft
//     nur dort, wo dieser liegt, und ist damit kein Test, sondern eine
//     Gewohnheit.
//
// SIGNING_KEY_LOCATION statt --key, damit der Test die echte Pfadaufloesung
// mitnimmt und nicht an ihr vorbei.
func signierfaehigesHome(t *testing.T, home string) []string {
	t.Helper()
	stamm := filepath.Join(home, ".config", "m3c", "e2e")
	if err := os.MkdirAll(filepath.Dir(stamm), 0o700); err != nil {
		t.Fatal(err)
	}
	r := RunTool(t, "skillctl", []string{"HOME=" + home}, "keygen", "--out", stamm)
	if r.ExitCode != 0 {
		t.Fatalf("keygen fehlgeschlagen (%d):\n%s", r.ExitCode, r.Stdout)
	}
	return []string{"HOME=" + home, "SIGNING_KEY_LOCATION=" + stamm + ".priv"}
}

// agentHome baut ein HOME mit genau einem Agenten darin.
func agentHome(t *testing.T, name string) string {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, ".claude", "agents")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "---\nname: " + name + "\ndescription: e2e-Vorlage\n---\n\nTu das Ding.\n"
	if err := os.WriteFile(filepath.Join(dir, name+".md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return home
}

func archivEintraege(t *testing.T, pfad string) ([]string, map[string]any) {
	t.Helper()
	f, err := os.Open(pfad)
	if err != nil {
		t.Fatalf("oeffnen %s: %v", pfad, err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	var namen []string
	var manifest map[string]any
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		namen = append(namen, h.Name)
		if h.Name == "bundle.json" {
			raw, _ := io.ReadAll(tr)
			_ = json.Unmarshal(raw, &manifest)
		}
	}
	return namen, manifest
}

// TestE2E_AgentPackenErzeugtGenauEineDatei ist AC-14 durch den echten Befehl.
func TestE2E_AgentPackenErzeugtGenauEineDatei(t *testing.T) {
	eigenesArbeitsverzeichnis(t)
	home := agentHome(t, "e2e-agent")
	umgebung := signierfaehigesHome(t, home)

	r := RunTool(t, "skillctl", umgebung,
		"publish", "e2e-agent", "--kind", "agent", "--version", "1.0.0", "--dry-run")
	if r.ExitCode != 0 {
		t.Fatalf("Ausstieg %d, Ausgabe:\n%s", r.ExitCode, r.Stdout)
	}

	skb := "e2e-agent@1.0.0.skb"
	if _, err := os.Stat(skb); err != nil {
		t.Fatalf("kein Buendel unter %s: %v\nAusgabe:\n%s", skb, err, r.Stdout)
	}

	namen, manifest := archivEintraege(t, skb)
	var inhalt []string
	for _, n := range namen {
		if n != "bundle.json" && n != "CHECKSUMS" {
			inhalt = append(inhalt, n)
		}
	}
	if len(inhalt) != 1 || inhalt[0] != "e2e-agent.md" {
		t.Fatalf("Archivinhalt %v, erwartet genau [e2e-agent.md]", inhalt)
	}
	if manifest["kind"] != "agent" {
		t.Errorf("kind = %v, erwartet agent", manifest["kind"])
	}
	if manifest["schema"] != "m3c-skill-bundle/v2" {
		t.Errorf("schema = %v, erwartet m3c-skill-bundle/v2", manifest["schema"])
	}
}

// TestE2E_SkillBuendelTraegtKeineArt ist die Gegenprobe und die eigentliche
// Zusicherung von SPEC-0432: fuer Skills aendert sich kein Byte.
func TestE2E_SkillBuendelTraegtKeineArt(t *testing.T) {
	eigenesArbeitsverzeichnis(t)
	home := t.TempDir()
	dir := filepath.Join(home, ".claude", "skills", "e2e-skill")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# e2e\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	umgebung := signierfaehigesHome(t, home)
	r := RunTool(t, "skillctl", umgebung,
		"publish", "e2e-skill", "--version", "1.0.0", "--dry-run")
	if r.ExitCode != 0 {
		t.Fatalf("Ausstieg %d:\n%s", r.ExitCode, r.Stdout)
	}
	skb := "e2e-skill@1.0.0.skb"
	if _, err := os.Stat(skb); err != nil {
		t.Fatalf("kein Buendel: %v\n%s", err, r.Stdout)
	}
	_, manifest := archivEintraege(t, skb)
	if _, da := manifest["kind"]; da {
		t.Errorf("ein Skillbuendel traegt ein kind-Feld: %v", manifest["kind"])
	}
	if manifest["schema"] != "m3c-skill-bundle/v1" {
		t.Errorf("schema = %v, erwartet v1", manifest["schema"])
	}
}

// TestE2E_UnbekannteArtWirdAbgewiesen ist AC-12: fail closed, und zwar OHNE
// dass eine Datei liegen bleibt.
func TestE2E_UnbekannteArtWirdAbgewiesen(t *testing.T) {
	eigenesArbeitsverzeichnis(t)
	home := agentHome(t, "e2e-agent")
	umgebung := signierfaehigesHome(t, home)
	r := RunTool(t, "skillctl", umgebung,
		"publish", "e2e-agent", "--kind", "Agent", "--version", "1.0.0", "--dry-run")
	if r.ExitCode == 0 {
		t.Fatalf("die Art \"Agent\" wurde angenommen:\n%s", r.Stdout)
	}
	if !strings.Contains(r.Stdout, "no bundle written") {
		t.Errorf("die Meldung sagt nicht, dass nichts geschrieben wurde:\n%s", r.Stdout)
	}
	if _, err := os.Stat("e2e-agent@1.0.0.skb"); err == nil {
		t.Fatal("trotz Ablehnung wurde ein Buendel geschrieben")
	}
}

// TestE2E_FehlendeAgentendateiNenntDenPfad prueft den kaputten Zustand, den ein
// Mensch wirklich trifft: die Meldung muss den erwarteten Ort nennen, sonst
// sucht er.
func TestE2E_FehlendeAgentendateiNenntDenPfad(t *testing.T) {
	eigenesArbeitsverzeichnis(t)
	home := t.TempDir()
	r := RunTool(t, "skillctl", []string{"HOME=" + home},
		"publish", "gibt-es-nicht", "--kind", "agent", "--version", "1.0.0", "--dry-run")
	if r.ExitCode == 0 {
		t.Fatalf("ein fehlender Agent wurde angenommen:\n%s", r.Stdout)
	}
	for _, erwartet := range []string{"gibt-es-nicht.md", "--agent-file"} {
		if !strings.Contains(r.Stdout, erwartet) {
			t.Errorf("die Meldung nennt %q nicht:\n%s", erwartet, r.Stdout)
		}
	}
}

// Zwei Tests statt einem, weil `drift` aus zwei verschiedenen Gruenden
// scheitern kann und der erste Entwurf nur so AUSSAH, als pruefe er den
// zweiten.
//
// Der erste Entwurf hiess "OhneKatalog", setzte ER1_API_KEY leer und meldete
// gruen. Der Mutationstest hat ihn entlarvt: der Katalogzweig liess sich auf
// `return 0` aendern, ohne dass der Test anschlug. Er stieg naemlich schon
// vorher aus, bei der Anmeldedatenpruefung, und hat den Katalog nie gesehen.
//
// Dazu kam ein zweiter Fehler in derselben Zeile: --er1-target local zeigt auf
// https://127.0.0.1:8081, und das ist der laufende Container aims-core-local.
// Der Test sprach also mit einem echten Dienst und haette auf einer Maschine
// ohne diesen Container etwas anderes gemessen als hier.

// TestE2E_DriftOhneAnmeldedatenScheitert ist der erste Ausstieg, benannt nach
// dem, was er wirklich prueft.
func TestE2E_DriftOhneAnmeldedatenScheitert(t *testing.T) {
	eigenesArbeitsverzeichnis(t)
	r := RunTool(t, "skillctl", []string{
		"HOME=" + t.TempDir(),
		"ER1_API_KEY=",
		"ER1_DEVICE_TOKEN=",
		"M3C_ER1_KEYCHAIN=off", // sonst zieht der Befehl den echten Schluessel des Betreibers
	}, "drift", "--er1-target", totePforte)
	if r.ExitCode == 0 {
		t.Fatalf("drift meldete Erfolg ohne Anmeldedaten:\n%s", r.Stdout)
	}
	if !strings.Contains(r.Stdout, "ER1_API_KEY") {
		t.Errorf("die Meldung sagt nicht, was fehlt:\n%s", r.Stdout)
	}
}

// totePforte ist ein Port, auf dem nichts lauschen kann: Port 1 ist
// privilegiert und in keinem unserer Dienste vergeben. Ein fester Fremdhost
// waere Netz im Test; 127.0.0.1:1 ist eine sofortige, netzfreie Abweisung.
const totePforte = "https://127.0.0.1:1"

// TestE2E_DriftOhneErreichbarenKatalogMeldetNichtGruen erreicht den Katalogzweig
// wirklich: die Anmeldedaten sind da, die Gegenseite ist es nicht.
//
// Das ist die Zusicherung, auf die es ankommt. Ein Driftdetektor, der bei
// fehlender Gegenseite "aktuell" meldet, ist schlimmer als keiner, weil er die
// Frage beantwortet, ohne sie gestellt zu haben.
func TestE2E_DriftOhneErreichbarenKatalogMeldetNichtGruen(t *testing.T) {
	eigenesArbeitsverzeichnis(t)
	r := RunTool(t, "skillctl", []string{
		"HOME=" + t.TempDir(),
		"ER1_API_KEY=e2e-kein-echter-schluessel",
	}, "drift", "--er1-target", totePforte)
	if r.ExitCode == 0 {
		t.Fatalf("drift meldete Erfolg ohne erreichbaren Katalog:\n%s", r.Stdout)
	}
	if !strings.Contains(r.Stdout, "drift:") {
		t.Errorf("die Meldung ist dem Befehl nicht zuzuordnen:\n%s", r.Stdout)
	}
	if strings.Contains(r.Stdout, driftAktuell) {
		t.Errorf("drift behauptet Aktualitaet, obwohl es nicht vergleichen konnte:\n%s", r.Stdout)
	}
}

// driftAktuell spiegelt die Befundzeile aus cmd/skillctl/drift_cmds.go. Als
// Konstante, damit eine Umbenennung dort hier auffaellt statt still den Test zu
// entwaffnen.
const driftAktuell = "aktuell"
