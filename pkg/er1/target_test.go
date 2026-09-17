package er1

import "testing"

// BUG-0444 und BUG-0445: die Wache entschied per strings.Contains statt am
// geparsten Host, in zwei Dateien und je zwei Zweigen.
//
// Der Test haelt BEIDE Richtungen. Nur die Umgehungen zu pruefen liesse eine
// Reparatur durch, die jedes Ueberspringen verbietet; dann ist die Entwicklung
// gegen ein selbstsigniertes Zertifikat kaputt und niemand merkt es, bis
// jemand sie braucht.
func TestResolveTarget_WacheParstDenHost(t *testing.T) {
	t.Setenv("ER1_API_URL", "")
	t.Setenv("ER1_VERIFY_SSL", "")

	faelle := []struct {
		name       string
		target     string
		wantVerify bool
	}{
		{"Subdomain mit localhost", "https://localhost.angreifer.example/", true},
		{"Subdomain mit 127.0.0.1", "https://127.0.0.1.angreifer.example/", true},
		{"127.0.0.1 im Abfrageteil", "https://angreifer.example/?h=127.0.0.1", true},
		{"localhost im Pfad", "https://angreifer.example/localhost", true},
		{"echtes 127.0.0.1", "https://127.0.0.1:8081", false},
		{"echtes localhost", "https://localhost:8081", false},
		{"echtes ::1", "https://[::1]:8081", false},
		{"gewoehnlicher Host", "https://onboarding.guide", true},
		{"Name prod", "prod", true},
		{"leerer Name ist prod", "", true},
		{"Name local", "local", false},
		{"Leerraum wird getrimmt", "  PROD  ", true},
	}
	for _, f := range faelle {
		t.Run(f.name, func(t *testing.T) {
			_, verify := ResolveTarget(f.target)
			if verify != f.wantVerify {
				t.Fatalf("ResolveTarget(%q) verifySSL = %v, erwartet %v", f.target, verify, f.wantVerify)
			}
		})
	}
}

// Der zweite Zweig trug denselben Fehler, direkt unter dem Kommentar mit der
// richtigen Regel.
func TestResolveTarget_ER1APIURLZweigPruftEbenso(t *testing.T) {
	faelle := []struct {
		name, apiURL, verifyEnv string
		wantVerify              bool
	}{
		{"fremder Host mit localhost darin", "https://localhost.angreifer.example/upload_2", "false", true},
		{"fremder Host mit 127.0.0.1 darin", "https://127.0.0.1.angreifer.example/upload_2", "false", true},
		{"echtes Loopback darf ueberspringen", "https://127.0.0.1:8081/upload_2", "false", false},
		{"Loopback ohne die Bitte prueft", "https://127.0.0.1:8081/upload_2", "true", true},
	}
	for _, f := range faelle {
		t.Run(f.name, func(t *testing.T) {
			t.Setenv("ER1_API_URL", f.apiURL)
			t.Setenv("ER1_VERIFY_SSL", f.verifyEnv)
			_, verify := ResolveTarget("stage")
			if verify != f.wantVerify {
				t.Fatalf("ER1_API_URL=%q ER1_VERIFY_SSL=%q -> verifySSL = %v, erwartet %v",
					f.apiURL, f.verifyEnv, verify, f.wantVerify)
			}
		})
	}
}

// VerifyTLSFor ist die Regel selbst, einzeln gehalten, weil Aufrufer sie auch
// direkt benutzen duerfen.
func TestVerifyTLSFor(t *testing.T) {
	if !VerifyTLSFor("https://angreifer.example", true) {
		t.Fatal("wer pruefen will, muss pruefen duerfen")
	}
	if VerifyTLSFor("https://127.0.0.1:8081", false) {
		t.Fatal("echtes Loopback darf ueberspringen")
	}
	if !VerifyTLSFor("https://localhost.angreifer.example", false) {
		t.Fatal("fremder Host muss fail-closed auf Pruefung zurueck")
	}
}
