package main

import "testing"

func TestFingerabdruckBleibtVergleichbar(t *testing.T) {
	a, b := Secret("derselbe-wert"), Secret("derselbe-wert")
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatal("gleiche Werte, verschiedene Fingerabdruecke: der Vergleich waere kaputt")
	}
	if a.Fingerprint() == Secret("anderer-wert").Fingerprint() {
		t.Fatal("verschiedene Werte, gleicher Fingerabdruck")
	}
	if len(a.Fingerprint()) != 12 {
		t.Fatalf("Laenge %d, erwartet 12", len(a.Fingerprint()))
	}
	if Secret("").Fingerprint() != "<leer>" {
		t.Fatal("leerer Wert soll <leer> melden")
	}
}
