package session

import (
	"os"
	"testing"
)

// BUG-0444: die Loopback-Wache in ER1Endpoint entschied per strings.Contains
// statt per geparstem Host. Vier Umgehungen waren damit offen, und an der so
// entschiedenen Verbindung haengen X-API-KEY und Authorization: Bearer.
//
// Der Test haelt BEIDE Richtungen fest. Nur die Umgehungen zu pruefen wuerde
// eine Reparatur durchgehen lassen, die einfach jedes Skip verbietet; dann
// waere die lokale Entwicklung gegen ein selbstsigniertes Zertifikat kaputt,
// und niemand haette es gemerkt, bis jemand sie braucht.
func TestER1Endpoint_LoopbackWacheParstDenHost(t *testing.T) {
	t.Setenv("ER1_API_URL", "")
	t.Setenv("ER1_VERIFY_SSL", "")

	faelle := []struct {
		name       string
		target     string
		wantVerify bool
	}{
		// Die vier Umgehungen aus dem Befund. Alle MUESSEN pruefen.
		{"Subdomain mit localhost", "https://localhost.angreifer.example/", true},
		{"Subdomain mit 127.0.0.1", "https://127.0.0.1.angreifer.example/", true},
		{"127.0.0.1 im Abfrageteil", "https://angreifer.example/?h=127.0.0.1", true},
		{"localhost im Pfad", "https://angreifer.example/localhost", true},
		// Gegenprobe: echte Loopback-Ziele duerfen weiterhin ueberspringen.
		{"echtes 127.0.0.1", "https://127.0.0.1:8081", false},
		{"echtes localhost", "https://localhost:8081", false},
		{"echtes ::1", "https://[::1]:8081", false},
		// Und ein gewoehnlicher Fremdhost prueft ohnehin.
		{"gewoehnlicher Host", "https://onboarding.guide", true},
	}
	for _, f := range faelle {
		t.Run(f.name, func(t *testing.T) {
			_, verify := ER1Endpoint(f.target)
			if verify != f.wantVerify {
				t.Fatalf("ER1Endpoint(%q) verifySSL = %v, erwartet %v", f.target, verify, f.wantVerify)
			}
		})
	}
}

// Derselbe Fehler stand ein zweites Mal in derselben Funktion, im
// ER1_API_URL-Zweig, direkt unter dem Kommentar, der die richtige Regel nennt.
func TestER1Endpoint_ER1APIURLZweigPruftEbenso(t *testing.T) {
	faelle := []struct {
		name       string
		apiURL     string
		verifyEnv  string
		wantVerify bool
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
			_, verify := ER1Endpoint("stage")
			if verify != f.wantVerify {
				t.Fatalf("ER1_API_URL=%q ER1_VERIFY_SSL=%q -> verifySSL = %v, erwartet %v",
					f.apiURL, f.verifyEnv, verify, f.wantVerify)
			}
		})
	}
	_ = os.Unsetenv("ER1_API_URL")
}
