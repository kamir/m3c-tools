// pull_context_test.go: BUG-0254.
//
// Der dokumentierte Aufruf `--er1-context skills` traf nichts, meldete
// "done" und endete mit 0. Die Doku behauptete das Gegenteil: die
// Abnahmeliste sagt seit BUG-0165 ausdruecklich, der nackte Name werde
// praefixiert. Sie beschrieb eine Absicht, die der Pull-Pfad nie umgesetzt
// hatte; publish und room taten es laengst.
package main

import (
	"os"
	"strings"
	"testing"
)

func TestBUG0254_NackterKontextWirdPraefixiert(t *testing.T) {
	t.Setenv("ER1_USER_ID", "107677460544181387647")
	got := ownerPrefixedContext("skills")
	if got != "107677460544181387647___skills" {
		t.Fatalf("ownerPrefixedContext(\"skills\") = %q, erwartet den praefixierten Namen.\n"+
			"Genau diese Aufloesung fehlte im Pull-Pfad, waehrend die Doku sie zusicherte.", got)
	}
}

func TestBUG0254_VollerKontextBleibtUnveraendert(t *testing.T) {
	t.Setenv("ER1_USER_ID", "107677460544181387647")
	voll := "107677460544181387647___skillenv"
	if got := ownerPrefixedContext(voll); got != voll {
		t.Fatalf("ein bereits vollstaendiger Kontext wurde veraendert: %q", got)
	}
}

// Ohne aufloesbaren Besitzer bleibt der nackte Name stehen. Der Aufrufer
// muss das bemerken koennen, statt gegen einen erfundenen Kontext zu laufen.
func TestBUG0254_OhneBesitzerBleibtErNackt(t *testing.T) {
	t.Setenv("ER1_USER_ID", "")
	t.Setenv("ER1_CONTEXT_ID", "")
	got := ownerPrefixedContext("skills")
	if strings.Contains(got, "___") {
		t.Skip("auf dieser Maschine ist ein Geraetetoken hinterlegt; der Besitzer kam daher")
	}
	if got != "skills" {
		t.Fatalf("ohne aufloesbaren Besitzer: %q", got)
	}
}

// Der Nulltreffer-Code ist registriert und nicht frei geraten.
func TestBUG0254_NullTrefferCodeIstRegistriert(t *testing.T) {
	if os.Getenv("SKIP") != "" {
		t.Skip()
	}
	// exitcode.PullNoMatches.Number wird im Pull-Pfad zurueckgegeben; der
	// Register-Selbstlauf (pkg/skillctl/exitcode) prueft die Eindeutigkeit.
	// Hier wird nur festgehalten, dass es NICHT 0 und NICHT 1 ist: 0 waere
	// der stille Erfolg, den der Befund beschreibt, und 1 waere von einem
	// echten Abruffehler nicht zu unterscheiden.
	n := pullNoMatchesCode()
	if n == 0 {
		t.Fatal("Nulltreffer meldet Erfolg; genau das war BUG-0254")
	}
	if n == 1 {
		t.Fatal("Nulltreffer ist von einem Abruffehler nicht zu unterscheiden")
	}
}
