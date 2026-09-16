package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Ein Quelltextwaechter, kein E2E-Test, und er steht hier bewusst mit dieser
// Ansage.
//
// Warum er noetig ist, ergab sich aus einem Mutationstest: bricht man
// Secret.String() auf `return string(s)`, bleiben ALLE E2E-Tests gruen. Das ist
// kein Mangel der Tests, sondern eine Aussage ueber den Bestand: kein einziger
// Ausgabepfad formatiert heute ein Secret. Die Schwaerzung im Typ schuetzt
// gegen einen Fehler, den noch niemand gemacht hat, und genau deshalb kann ihn
// kein Test durch das Binary ausloesen.
//
// Was sich pruefen laesst, ist die Stelle davor: `Reveal()` ist die einzige
// Tuer aus dem Typ heraus. Solange diese Tuer nur dort steht, wo der Wert
// wirklich hin muss, ist die Schwaerzung nicht umgehbar.
//
// Positivliste, nicht Verdachtssuche: aufgezaehlt wird, was erlaubt IST. Eine
// Suche nach verdaechtigen Mustern findet den naechsten Fall nicht, weil der
// naechste Fall anders aussieht.
func TestQuellwaechter_RevealNurAnErlaubterStelle(t *testing.T) {
	// Datei -> Zweck. Jeder Eintrag ist eine bewusste Entscheidung.
	erlaubt := map[string]string{
		// Der Wert MUSS in den Kopf der Probe, sonst kann niemand fragen, ob
		// der Dienst ihn annimmt. Das ist die Aufgabe des Werkzeugs.
		"read.go": "Wert als HTTP-Kopf der Probe",
		// Die Definition selbst.
		"secret.go": "Definition von Reveal",
	}

	dir := filepath.Join(RepoRoot(t), "cmd", "secretctl")
	eintraege, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	gefunden := map[string][]string{}
	for _, e := range eintraege {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		roh, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for i, zeile := range strings.Split(string(roh), "\n") {
			if !strings.Contains(zeile, ".Reveal()") && !strings.Contains(zeile, "func (s Secret) Reveal") {
				continue
			}
			// Ein Kommentar, der Reveal erwaehnt, ist keine Benutzung.
			if strings.HasPrefix(strings.TrimSpace(zeile), "//") {
				continue
			}
			gefunden[e.Name()] = append(gefunden[e.Name()],
				strings.TrimSpace(zeile)+"  (Zeile "+itoa(i+1)+")")
		}
	}

	for datei, stellen := range gefunden {
		if _, ok := erlaubt[datei]; !ok {
			t.Errorf("Reveal() in %s, das ist nicht auf der Positivliste.\n"+
				"  %s\n"+
				"Wenn der Wert dort wirklich hin muss, traegt die Liste in diesem Test\n"+
				"den Zweck ein. Dieser Eintrag IST die Entscheidung, und der Test ist\n"+
				"die Stelle, an der ein Mensch sie noch einmal liest.",
				datei, strings.Join(stellen, "\n  "))
		}
	}

	// Gegenprobe: der Waechter muss die bekannte Stelle auch wirklich sehen.
	// Ohne sie wuerde ein umbenanntes Reveal den Test still entwaffnen, und ein
	// Waechter, der nichts mehr findet, meldet fuer immer gruen.
	if len(gefunden["read.go"]) == 0 {
		t.Errorf("der Waechter findet die bekannte Reveal-Stelle in read.go nicht mehr. " +
			"Entweder ist sie weg (dann diesen Test anpassen) oder der Waechter ist blind.")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
