// loeschung.go: Loeschung und Aufbewahrungsfrist (SPEC-0428 T-05).
//
// Zwei Vorgaenge, die man nicht verwechseln darf:
//
//	Aufbewahrungslauf  entfernt, was seine Frist ueberschritten hat.
//	                   Routine, laeuft von selbst, betrifft alte Berichte.
//	Loeschung          entfernt ALLES zu einem Prinzipal, auf Verlangen.
//	                   Ein Rechtsvorgang, kein Aufraeumen.
//
// Beide hinterlassen KEIN Verzeichnis darueber, was entfernt wurde. Ein
// Loeschprotokoll ueber eine Person waere selbst ein Personendatum, und zwar
// eines, das die Loeschung ueberlebt. Dass die Luecken-Meldung trotzdem nicht
// falsch anschlaegt, loest FehlendeSeq ueber das Fenster und nicht ueber ein
// Protokoll (siehe collect.go).
package envreport

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

var (
	ErrKeinLoescher            = errors.New("store cannot delete; erasure needs a deleting store")
	ErrLoeschungUnvollstaendig = errors.New("erasure incomplete: reports remain after the sweep")
)

// Loescher ist ein Store, der auch entfernen kann. Getrennt vom Store, weil
// Loeschen ein anderes Recht ist als Schreiben.
type Loescher interface {
	Store
	// Entferne loescht EINEN Bericht. Der Store meldet, ob es ihn gab.
	Entferne(env string, seq int) error
	// Umgebungen nennt die Umgebungen EINES Prinzipals. Sie ist die einzige
	// Stelle, an der ueber Umgebungen hinweg gelesen wird, und sie ist auf
	// genau einen Prinzipal beschraenkt: die Loeschung muss alles finden,
	// sonst waere sie keine.
	Umgebungen(principal string) ([]string, error)
}

// Abgelaufen nennt die Berichte, deren Aufbewahrungsfrist ueberschritten ist.
//
// Es braucht den geladenen Bericht, weil die Frist im Bericht steht und nicht
// in der Marke: eine Frist, die man aus dem Index ablesen kann, ohne den
// Bericht zu oeffnen, waere eine zweite Wahrheit.
func Abgelaufen(berichte []Report, jetzt time.Time) []int {
	var raus []int
	for _, r := range berichte {
		if !r.AufbewahrungBis.IsZero() && jetzt.After(r.AufbewahrungBis) {
			raus = append(raus, r.Seq)
		}
	}
	sort.Ints(raus)
	return raus
}

// AufbewahrungsErgebnis berichtet, was ein Lauf getan hat.
type AufbewahrungsErgebnis struct {
	ENV      string
	Entfernt []int
	Bleibt   Fenster
}

// Aufbewahrungslauf entfernt die abgelaufenen Berichte EINER Umgebung.
func Aufbewahrungslauf(l Loescher, env string, berichte []Report, jetzt time.Time) (AufbewahrungsErgebnis, error) {
	if l == nil {
		return AufbewahrungsErgebnis{}, ErrKeinLoescher
	}
	raus := Abgelaufen(berichte, jetzt)
	for _, seq := range raus {
		if err := l.Entferne(env, seq); err != nil {
			return AufbewahrungsErgebnis{}, fmt.Errorf("retention sweep %s seq %d: %w", env, seq, err)
		}
	}
	rest, err := l.Liste(env)
	if err != nil {
		return AufbewahrungsErgebnis{}, err
	}
	seqs := make([]int, 0, len(rest))
	for _, a := range rest {
		seqs = append(seqs, a.Seq)
	}
	return AufbewahrungsErgebnis{ENV: env, Entfernt: raus, Bleibt: FensterAus(seqs, nil)}, nil
}

// LoeschErgebnis berichtet, was eine Loeschung getan hat. Es nennt Zahlen und
// Umgebungen, aber keine Berichtsinhalte: der Beleg, dass geloescht wurde,
// darf nicht das sein, was geloescht werden sollte.
type LoeschErgebnis struct {
	Principal  string
	Umgebungen int
	Entfernt   int
	Zeitpunkt  time.Time
}

// LoeschePrinzipal entfernt ALLE Berichte eines Prinzipals (AC-11).
//
// Kettensicher heisst hier: der Vorgang prueft nach, statt zu melden. Erst
// wenn jede Umgebung des Prinzipals leer zurueckliest, gilt die Loeschung als
// vollzogen; sonst gibt sie einen Fehler. Ein Loeschvorgang, der nur behauptet
// zu loeschen, ist der schlimmste Fall dieser ganzen Klasse, weil er eine
// Zusage erzeugt, auf die sich jemand verlaesst.
func LoeschePrinzipal(l Loescher, principal string, jetzt time.Time) (LoeschErgebnis, error) {
	if l == nil {
		return LoeschErgebnis{}, ErrKeinLoescher
	}
	envs, err := l.Umgebungen(principal)
	if err != nil {
		return LoeschErgebnis{}, err
	}
	erg := LoeschErgebnis{Principal: principal, Umgebungen: len(envs), Zeitpunkt: jetzt.UTC()}
	for _, env := range envs {
		items, err := l.Liste(env)
		if err != nil {
			return LoeschErgebnis{}, err
		}
		for _, a := range items {
			if err := l.Entferne(env, a.Seq); err != nil {
				return LoeschErgebnis{}, fmt.Errorf("erase %s seq %d: %w", env, a.Seq, err)
			}
			erg.Entfernt++
		}
	}
	// Nachpruefen statt melden.
	for _, env := range envs {
		rest, err := l.Liste(env)
		if err != nil {
			return LoeschErgebnis{}, err
		}
		if len(rest) > 0 {
			return LoeschErgebnis{}, fmt.Errorf("%w: %s still holds %d",
				ErrLoeschungUnvollstaendig, env, len(rest))
		}
	}
	return erg, nil
}
