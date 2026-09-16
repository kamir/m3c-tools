package main

import (
	"bytes"
	"strings"
	"testing"
)

// Die Identitaet wird nicht geraten (Entscheidung vom 2026-09-16).
//
// Vorgeschichte, weil sie die Form des Tests bestimmt: der Vorgabewert war
// zuerst id:kamir@m3c, spaeter id:bob@m3c, also in beiden Faellen der Name
// einer ANDEREN Person als der, die gerade veroeffentlicht. Wer ihn stehen
// liess, stempelte einen fremden Namen in ein signiertes Ereignis, und die
// Gegenseite lehnte spaeter mit der Begruendung ab, die Identitaet sei nicht
// gepinnt, obwohl sie korrekt gepinnt war. Die Meldung zeigte auf die falsche
// Stelle.
//
// Das Runbook hat davor gewarnt und dabei den ALTEN Wert genannt. Die
// Umbenennung hat die Warnung damit wirkungslos gemacht, ohne sie anzufassen:
// wer sie las und in der Hilfe einen anderen Wert sah, schloss folgerichtig,
// sie betreffe ihn nicht.
//
// Der eigentliche Grund, warum das unbemerkt wandern konnte: **kein einziger
// Test hat den Vorgabewert je geprueft.** Genau das holt diese Datei nach. Sie
// prueft nicht, WELCHER Wert dort steht, sondern dass ueberhaupt keiner
// geraten wird; ein Test auf einen bestimmten Namen waere beim naechsten
// Umbenennen wieder still falsch geworden.

func TestPublishVerweigertOhneIdentitaet(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runPublish([]string{"irgendein-skill", "--version", "1.0.0", "--dry-run"}, &out, &errBuf)

	if code != 2 {
		t.Fatalf("Ausstieg %d, erwartet 2 (Verwendungsfehler)\nAusgabe:\n%s%s", code, out.String(), errBuf.String())
	}
	ganze := out.String() + errBuf.String()
	// Die Meldung muss die Flagge nennen UND ein Beispiel geben. Eine Meldung,
	// die nur "fehlt" sagt, laesst den Menschen raten, und Raten ist genau das,
	// was hier abgestellt wird.
	for _, erwartet := range []string{"--identity", "id:"} {
		if !strings.Contains(ganze, erwartet) {
			t.Errorf("die Meldung nennt %q nicht:\n%s", erwartet, ganze)
		}
	}
}

// Die Gegenprobe: mit Identitaet darf der Befehl NICHT an dieser Pruefung
// haengenbleiben. Ohne sie wuerde ein Test, der alles mit Ausstieg 2 abweist,
// ebenfalls bestehen und waere wertlos.
func TestPublishLaeuftMitIdentitaetWeiter(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runPublish([]string{"gibt-es-sicher-nicht", "--version", "1.0.0",
		"--identity", "id:pruefer@test", "--dry-run"}, &out, &errBuf)

	if code == 2 {
		t.Fatalf("mit --identity wurde trotzdem ein Verwendungsfehler gemeldet:\n%s%s",
			out.String(), errBuf.String())
	}
}
