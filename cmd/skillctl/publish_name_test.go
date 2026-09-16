package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Der Name wird zu einem Pfad, an zwei Stellen: die gepackte Datei heisst
// ./<name>@<version>.skb, und beim Packen eines Agenten wird nach
// <staging>/<name>.md geschrieben.
//
// Gefunden hat das nicht ein Mensch, sondern die Taint-Analyse des gosec-Tors
// (G703), nachdem der Agentenpfad hinzukam. Gemessen vor der Reparatur:
// `publish "../../ausbruch" --kind agent` meldete
// "packed: ../../ausbruch@1.0.0.skb", schrieb also zwei Ebenen ueber dem
// Arbeitsverzeichnis.

func TestPublishWeistPfadausbruchImNamenAb(t *testing.T) {
	boese := []string{
		"../../ausbruch",
		"../nachbar",
		"/absolut",
		"unter/verzeichnis",
		"..",
	}
	for _, name := range boese {
		t.Run(name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			code := runPublish([]string{name, "--version", "1.0.0",
				"--identity", "id:pruefer@test", "--dry-run"}, &out, &errBuf)
			if code != 2 {
				t.Fatalf("Name %q wurde mit Ausstieg %d angenommen, erwartet 2\n%s%s",
					name, code, out.String(), errBuf.String())
			}
		})
	}
}

// Die Gegenprobe. Ohne sie wuerde eine Pruefung, die JEDEN Namen abweist,
// ebenfalls bestehen und waere wertlos.
func TestPublishNimmtGewoehnlicheNamenAn(t *testing.T) {
	for _, name := range []string{"plm-track", "skill.mit.punkt", "mit_unterstrich", "a1"} {
		t.Run(name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			code := runPublish([]string{name, "--version", "1.0.0",
				"--identity", "id:pruefer@test", "--dry-run"}, &out, &errBuf)
			if code == 2 {
				t.Fatalf("gewoehnlicher Name %q wurde als Verwendungsfehler abgewiesen:\n%s%s",
					name, out.String(), errBuf.String())
			}
		})
	}
}

// Und der Beleg, auf den es wirklich ankommt: nach der Ablehnung liegt nichts
// ausserhalb des Arbeitsverzeichnisses. Ein Ausstiegscode allein sagt nicht,
// ob vorher schon geschrieben wurde.
func TestPublishSchreibtBeiAblehnungNichtsNachDraussen(t *testing.T) {
	arbeit := t.TempDir()
	oben := filepath.Dir(arbeit)
	vorher, _ := os.ReadDir(oben)
	t.Chdir(arbeit)

	var out, errBuf bytes.Buffer
	_ = runPublish([]string{"../ausbruch", "--version", "1.0.0",
		"--identity", "id:pruefer@test", "--dry-run"}, &out, &errBuf)

	nachher, _ := os.ReadDir(oben)
	if len(nachher) != len(vorher) {
		var neu []string
		for _, e := range nachher {
			if strings.Contains(e.Name(), "ausbruch") {
				neu = append(neu, e.Name())
			}
		}
		t.Fatalf("es wurde ausserhalb des Arbeitsverzeichnisses geschrieben: %v", neu)
	}
}
