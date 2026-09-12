// env.go: die ENV-Adresse aus SPEC-0427 E2.
//
// Eine geregelte Faehigkeitsumgebung ist ein benanntes Tripel
//
//	env:<mandant>/<prinzipal>/<host>
//
// Weder die Maschine allein noch der Mensch allein ist die richtige Einheit.
// Ein Mensch arbeitet auf mehreren Maschinen, und dieselbe Maschine kann unter
// verschiedenen Auflagen laufen. Der Bestand belegt die erste Haelfte direkt:
// im ER1-Kontext ...___skills erscheint derselbe Autor unter zwei Hostnamen
// (MacBook-Pro-von-Mirko mit 102 Posten, MBP-von-Mirko mit 17), weil der
// Rechnername sich geaendert hat, und nichts verbindet die beiden heute.
//
// Der Host wird GEHASHT gefuehrt (SPEC-0351 Abschnitt 5.1, SPEC-0427 E2). Die
// Aufloesung auf den Klarnamen ist eine eigene Freigabe und kein Nebenprodukt
// des Lesezugriffs; deshalb gibt es hier keine Funktion, die aus einer Adresse
// den Klarnamen zurueckgewinnt. Das ist Absicht und keine Luecke: ein Hash, den
// dasselbe Paket wieder aufloesen kann, ist keiner.
package envreport

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// HostHashLen ist die Laenge des Host-Hashes in Hex-Zeichen. 16 Zeichen sind
// 64 Bit: genug, damit zwei Maschinen eines Mandanten nicht kollidieren, und
// kurz genug, dass eine Adresse lesbar bleibt.
const HostHashLen = 16

// Prefix ist das Schema jeder ENV-Adresse.
const Prefix = "env:"

var (
	ErrKeinPrefix     = errors.New("ENV-Adresse beginnt nicht mit \"env:\"")
	ErrMandantFehlt   = errors.New("ENV-Adresse ohne Mandant")
	ErrPrinzipalFehlt = errors.New("ENV-Adresse ohne Prinzipal")
	ErrHostFehlt      = errors.New("ENV-Adresse ohne Host")
	ErrZuVieleTeile   = errors.New("ENV-Adresse hat mehr als drei Segmente")
	ErrLeeresSegment  = errors.New("ENV-Adresse hat ein leeres Segment")
)

// ENV ist die aufgeloeste Adresse. HostHash ist bereits gehasht; ein
// Klarname wird in diesem Typ nie gehalten.
type ENV struct {
	Mandant   string
	Prinzipal string
	HostHash  string
}

// NeueENV baut eine Adresse aus Klarwerten und hasht dabei den Host.
// Der Mandant geht als Salz in den Hash ein, damit derselbe Rechner unter
// zwei Mandanten nicht denselben Hash traegt: sonst waere die Adresse ueber
// Mandantengrenzen hinweg verkettbar, und genau das soll sie nicht sein.
func NeueENV(mandant, prinzipal, hostKlartext string) (ENV, error) {
	mandant = strings.TrimSpace(mandant)
	prinzipal = strings.TrimSpace(prinzipal)
	hostKlartext = strings.TrimSpace(hostKlartext)
	switch {
	case mandant == "":
		return ENV{}, ErrMandantFehlt
	case prinzipal == "":
		return ENV{}, ErrPrinzipalFehlt
	case hostKlartext == "":
		return ENV{}, ErrHostFehlt
	}
	if strings.ContainsAny(mandant+prinzipal, "/ ") {
		return ENV{}, fmt.Errorf("Mandant und Prinzipal duerfen weder / noch Leerzeichen enthalten")
	}
	return ENV{Mandant: mandant, Prinzipal: prinzipal, HostHash: HashHost(mandant, hostKlartext)}, nil
}

// HashHost bildet den Klarnamen eines Rechners auf seinen Adress-Hash ab.
// Getrennt exportiert, damit ein Aufrufer pruefen kann, ob eine gegebene
// Adresse zu SEINEM Rechner gehoert, ohne dass die Adresse den Namen preisgibt.
func HashHost(mandant, hostKlartext string) string {
	sum := sha256.Sum256([]byte(mandant + "\x00" + strings.ToLower(strings.TrimSpace(hostKlartext))))
	return hex.EncodeToString(sum[:])[:HostHashLen]
}

// String serialisiert die Adresse. Der Klarname erscheint hier nie.
func (e ENV) String() string {
	return Prefix + e.Mandant + "/" + e.Prinzipal + "/" + e.HostHash
}

// ParseENV liest eine serialisierte Adresse zurueck.
func ParseENV(s string) (ENV, error) {
	if !strings.HasPrefix(s, Prefix) {
		return ENV{}, ErrKeinPrefix
	}
	teile := strings.Split(strings.TrimPrefix(s, Prefix), "/")
	if len(teile) > 3 {
		return ENV{}, ErrZuVieleTeile
	}
	if len(teile) < 3 {
		// Welches Segment fehlt, ist die nuetzlichere Auskunft als "zu wenige".
		switch len(teile) {
		case 1:
			return ENV{}, ErrPrinzipalFehlt
		default:
			return ENV{}, ErrHostFehlt
		}
	}
	for _, t := range teile {
		if strings.TrimSpace(t) == "" {
			return ENV{}, ErrLeeresSegment
		}
	}
	return ENV{Mandant: teile[0], Prinzipal: teile[1], HostHash: teile[2]}, nil
}
