package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const wert = "m3cer1_ein-sehr-geheimer-wert-4711"

// TestSecretNeverPrints is AC-6, and it is the reason the type exists.
//
// A convention ("do not print secrets") holds until someone adds a debug line.
// A type that renders as a placeholder holds through every path that formats
// values, and this test walks them all: the ones a careful person thinks of and
// the ones they do not (%#v bypasses String, json.Marshal ignores it, a struct
// carries its fields into both).
func TestSecretNeverPrints(t *testing.T) {
	s := Secret(wert)

	type umschlag struct {
		Name string
		Wert Secret
	}
	env := umschlag{Name: "er1-api-key", Wert: s}

	jsonBytes, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	yamlBytes, err := yaml.Marshal(env)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}

	var logBuf bytes.Buffer
	log.New(&logBuf, "", 0).Printf("wert=%v struct=%+v", s, env)

	wege := map[string]string{
		"String()": s.String(),
		"%v":       fmt.Sprintf("%v", s),
		// staticcheck schlaegt hier String() vor. Das waere ein anderer Test:
		// String() direkt zu rufen prueft die Methode, %s prueft den WEG, auf
		// dem fmt sie findet. Genau dieser Weg ist es, den jemand aus
		// Versehen nimmt. Den Test der Regel anzupassen hiesse, das Tor an
		// den Fehler anzupassen, den es finden soll.
		//nolint:staticcheck,gosimple // S1025 ist hier der Gegenstand der Pruefung
		"%s":           fmt.Sprintf("%s", s),
		"%q":           fmt.Sprintf("%q", s),
		"%#v":          fmt.Sprintf("%#v", s),
		"%+v Struktur": fmt.Sprintf("%+v", env),
		"%#v Struktur": fmt.Sprintf("%#v", env),
		"json.Marshal": string(jsonBytes),
		"yaml.Marshal": string(yamlBytes),
		"log.Printf":   logBuf.String(),
		"Fingerprint":  s.Fingerprint(),
		"Error-Text":   fmt.Errorf("etwas ging schief bei %v", s).Error(),
	}
	for weg, got := range wege {
		if strings.Contains(got, wert) {
			t.Errorf("%s gibt den Wert preis: %s", weg, got)
		}
	}

	// Die Gegenprobe: der EINE Weg muss ihn liefern, sonst ist der Typ nutzlos.
	if s.Reveal() != wert {
		t.Fatalf("Reveal() liefert den Wert nicht")
	}
}

// TestFingerprintUnterscheidetUndVerraetNicht: der Fingerabdruck muss zwei
// Werte trennen koennen und darf keinen rekonstruierbar machen.
func TestFingerprintUnterscheidetUndVerraetNicht(t *testing.T) {
	a, b := Secret("wert-eins"), Secret("wert-zwei")
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("zwei verschiedene Werte haben denselben Fingerabdruck")
	}
	if a.Fingerprint() != Secret("wert-eins").Fingerprint() {
		t.Error("derselbe Wert ergibt verschiedene Fingerabdruecke")
	}
	if len(a.Fingerprint()) != 12 {
		t.Errorf("Fingerabdruck ist %d Zeichen lang, erwartet 12", len(a.Fingerprint()))
	}
	if Secret("").Fingerprint() != "<leer>" {
		t.Error("ein leerer Wert braucht ein eigenes Wort, keinen Hash von nichts")
	}
}

// TestLeereWerteGeltenNieAlsGleich: SameAs darf zwei Abwesenheiten nicht fuer
// Uebereinstimmung halten. Genau diese Verwechslung haette im Waechter von
// aims-core eine leere Anfrage durchgelassen (SPEC-0438 AC-2).
func TestLeereWerteGeltenNieAlsGleich(t *testing.T) {
	if Secret("").SameAs(Secret("")) {
		t.Error("zwei leere Werte gelten als gleich")
	}
	if Secret("x").SameAs(Secret("")) || Secret("").SameAs(Secret("x")) {
		t.Error("ein leerer Wert gilt als Treffer")
	}
	if !Secret("x").SameAs(Secret("x")) {
		t.Error("zwei gleiche Werte gelten nicht als gleich")
	}
}

func schreibRegistry(t *testing.T, inhalt string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secrets.yaml")
	if err := os.WriteFile(p, []byte(inhalt), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const gute = `schema: m3c-secret-registry/v1
secrets:
  - name: er1-api-key
    summary: Geteilter Dienstschluessel
    source: {kind: gcp-secret-manager, project: semanpix, secret: er1-api-key}
    holders:
      - {id: m4-keychain, kind: macos-keychain, service: aims-core-er1}
      - {id: m4-profil, kind: file, path: ~/.m3c-tools/er1.env, key: ER1_API_KEY}
    probe: {kind: http, url: https://example.invalid/, header: X-API-KEY, expect_ok: 200, expect_revoked: 401}
`

func TestRegistryLaedt(t *testing.T) {
	r, err := LoadRegistry(schreibRegistry(t, gute))
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	e, err := r.Find("er1-api-key")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if len(e.Holders) != 2 {
		t.Fatalf("%d Halteorte, erwartet 2", len(e.Holders))
	}
}

// TestRegistryWeistSammelposten_ab ist AC-3. Ein Eintrag wie "alle Profile"
// beantwortet die Frage, fuer die es die Registry gibt, mit einer Geste, und
// die naechste Rotation scheitert dann an der Kopie, die niemand aufgezaehlt
// hat. Genau so ist BUG-0439 entstanden.
func TestRegistryWeistSammelpostenAb(t *testing.T) {
	for _, sammel := range []string{
		`      - {id: alle-profile, kind: file, path: ~/x.env, key: K}`,
		`      - {id: profile, kind: file, path: ~/.m3c-tools/*.env, key: K}`,
		`      - {id: rest-usw, kind: file, path: ~/y.env, key: K}`,
	} {
		inhalt := strings.Replace(gute,
			`      - {id: m4-profil, kind: file, path: ~/.m3c-tools/er1.env, key: ER1_API_KEY}`,
			sammel, 1)
		if _, err := LoadRegistry(schreibRegistry(t, inhalt)); err == nil {
			t.Errorf("Sammelposten angenommen: %s", strings.TrimSpace(sammel))
		}
	}
}

func TestRegistryWeistUnbrauchbaresAb(t *testing.T) {
	faelle := map[string]string{
		"falsches Schema": strings.Replace(gute, "m3c-secret-registry/v1", "irgendwas/v9", 1),
		"ohne Halteorte": `schema: m3c-secret-registry/v1
secrets:
  - name: leer
    source: {kind: gcp-secret-manager, project: p, secret: s}
    holders: []
`,
		"Halteort ohne Art": `schema: m3c-secret-registry/v1
secrets:
  - name: x
    source: {kind: gcp-secret-manager, project: p, secret: s}
    holders:
      - {id: irgendwo}
`,
		"Schluesselbund ohne Dienst": `schema: m3c-secret-registry/v1
secrets:
  - name: x
    source: {kind: gcp-secret-manager, project: p, secret: s}
    holders:
      - {id: kc, kind: macos-keychain}
`,
		"Datei ohne Schluesselnamen": `schema: m3c-secret-registry/v1
secrets:
  - name: x
    source: {kind: gcp-secret-manager, project: p, secret: s}
    holders:
      - {id: f, kind: file, path: ~/a.env}
`,
	}
	for name, inhalt := range faelle {
		if _, err := LoadRegistry(schreibRegistry(t, inhalt)); err == nil {
			t.Errorf("%s: angenommen, erwartet abgewiesen", name)
		}
	}
}

// TestDoppelteOrteWerdenBemerkt: zwei Eintraege mit derselben Kennung machen
// aus dem Inventar eine Liste, die sich selbst widerspricht.
func TestDoppelteOrteWerdenBemerkt(t *testing.T) {
	inhalt := strings.Replace(gute,
		`      - {id: m4-profil, kind: file, path: ~/.m3c-tools/er1.env, key: ER1_API_KEY}`,
		`      - {id: m4-keychain, kind: file, path: ~/.m3c-tools/er1.env, key: ER1_API_KEY}`, 1)
	if _, err := LoadRegistry(schreibRegistry(t, inhalt)); err == nil {
		t.Error("zwei Halteorte mit derselben Kennung angenommen")
	}
}

// TestSchreibendeBefehleSindNochNichtDa haelt die Grenze fest, die bewusst
// gezogen wurde: die lesende Haelfte laeuft, die schreibende wird unter
// Aufsicht gebaut. Ein Befehl, der still nichts tut, waere schlimmer als einer,
// der sagt, dass es ihn noch nicht gibt.
func TestSchreibendeBefehleSindNochNichtDa(t *testing.T) {
	for _, c := range []string{"new", "stage", "distribute", "retire"} {
		var out, errBuf bytes.Buffer
		if rc := run([]string{c}, &out, &errBuf); rc == 0 {
			t.Errorf("%s meldet Erfolg, obwohl es ihn nicht gibt", c)
		}
		if !strings.Contains(errBuf.String(), "not built yet") {
			t.Errorf("%s sagt nicht, dass es ihn noch nicht gibt: %q", c, errBuf.String())
		}
	}
}
