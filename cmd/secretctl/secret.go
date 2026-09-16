package main

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Secret is a value that must never reach an output stream (SPEC-0438 §6,
// AC-6).
//
// It is a TYPE and not a convention on purpose. A convention holds until
// someone adds a debug line at three in the morning; a type that renders as
// "<redacted>" holds through fmt, %v, %s, log, and json.Marshal without anyone
// having to remember. The occasion for this is in the same session as the spec:
// a value that was piped and here-documented into the same stdin ended up as
// text in a session transcript.
//
// The value is reachable only through Reveal(), which is greppable. If a code
// review sees Reveal() near an output call, that is the whole review.
type Secret string

// String is what fmt, %v and %s reach for. It never yields the value.
func (s Secret) String() string { return "<redacted>" }

// GoString covers %#v, which bypasses String().
func (s Secret) GoString() string { return "<redacted>" }

// MarshalJSON covers the path a struct takes when it is logged as JSON.
func (s Secret) MarshalJSON() ([]byte, error) { return json.Marshal("<redacted>") }

// MarshalYAML covers the same for the registry format.
func (s Secret) MarshalYAML() (any, error) { return "<redacted>", nil }

// Reveal returns the value. The only way, and deliberately conspicuous.
func (s Secret) Reveal() string { return string(s) }

// Empty reports whether nothing is held. Useful without revealing.
func (s Secret) Empty() bool { return len(s) == 0 }

// fingerprintSalz trennt den Namensraum und ist bewusst oeffentlich: der
// Fingerabdruck muss ueber Maschinen hinweg VERGLEICHBAR sein, also darf nichts
// Geheimes und nichts Zufaelliges hineingehen. Die Sicherheit kommt hier nicht
// aus dem Salz, sondern aus dem Aufwand.
var fingerprintSalz = []byte("m3c-secretctl-fingerprint-v1")

// fingerprintRunden ist der Arbeitsfaktor. Eine Inventur fasst ein gutes
// Dutzend Halteorte an, da faellt das nicht auf; ein Rateangriff muss ihn pro
// Kandidat bezahlen.
const fingerprintRunden = 200_000

// Fingerprint is how two values are compared and reported: the first 12
// characters of a DELIBERATELY SLOW derivation.
//
// Every comparison in this tool runs over fingerprints, never over the values,
// so that a diff, a log line or a failing assertion cannot carry the secret.
//
// Warum nicht einfach sha256, wie es hier zuerst stand: der alte Kommentar
// sagte, zwoelf Zeichen seien "far too little to reconstruct one". Das stimmt
// fuer die Rueckrechnung und verfehlt die Richtung, auf die es ankommt. Wer den
// Fingerabdruck sieht, rekonstruiert nichts, er RAET und BESTAETIGT: Kandidat
// hashen, zwoelf Zeichen vergleichen, fertig. Mit sha256 kostet ein Versuch
// nichts, und ein Fingerabdruck steht in Ausgaben, Protokollen und
// Bildschirmfotos.
//
// Gefunden hat das die CodeQL-Pruefung beim Zusammenfuehren der Zweige
// (go/weak-sensitive-data-hashing, hoch). Der Befund ist richtig, auch wenn die
// Regel von Passwoertern spricht: ein API-Schluessel hat mehr Entropie als ein
// Passwort, aber diese Funktion weiss nicht, was man ihr gibt, und das naechste
// Geheimnis kann schwaecher sein.
//
// PBKDF2 kommt aus der Standardbibliothek (Go 1.24+), es kommt also keine neue
// Abhaengigkeit in die Lieferkette, nur um eine Ableitung langsam zu machen.
func (s Secret) Fingerprint() string {
	if s.Empty() {
		return "<leer>"
	}
	abgeleitet, err := pbkdf2.Key(sha256.New, string(s), fingerprintSalz, fingerprintRunden, 16)
	if err != nil {
		// Kann mit festen Parametern nicht eintreten. Sollte es doch, ist ein
		// FEHLENDER Fingerabdruck die richtige Antwort: eine stille
		// Rueckkehr zur schnellen Form waere genau der Fehler, den diese
		// Funktion abstellt.
		return "<fehler>"
	}
	return hex.EncodeToString(abgeleitet)[:12]
}

// SameAs compares two secrets in a way that reads as an intent, not as an
// accident. Not constant time: both sides are values this operator already
// holds, so there is no attacker to time here. The reason to have it at all is
// that `a == b` on two Secrets would be easy to later "fix" into a print.
func (s Secret) SameAs(other Secret) bool {
	return !s.Empty() && !other.Empty() && s == other
}
