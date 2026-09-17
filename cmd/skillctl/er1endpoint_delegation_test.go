package main

import "testing"

// BUG-0445: er1Endpoint war eine wortgleiche Kopie mit demselben Fehler. Jetzt
// delegiert es. Dieser Test prueft nicht die Regel noch einmal (die haelt
// pkg/er1.TestResolveTarget_WacheParstDenHost), sondern DASS delegiert wird:
// die vier Umgehungen aus dem Befund muessen hier verschwunden sein.
func TestEr1Endpoint_DelegiertUndUmgehungenSindZu(t *testing.T) {
	t.Setenv("ER1_API_URL", "")
	faelle := []struct {
		target     string
		wantVerify bool
	}{
		{"https://localhost.angreifer.example/", true},
		{"https://127.0.0.1.angreifer.example/", true},
		{"https://angreifer.example/?h=127.0.0.1", true},
		{"https://angreifer.example/localhost", true},
		{"https://127.0.0.1:8081", false},
		{"local", false},
		{"prod", true},
	}
	for _, f := range faelle {
		_, verify := er1Endpoint(f.target)
		if verify != f.wantVerify {
			t.Errorf("er1Endpoint(%q) verifySSL = %v, erwartet %v", f.target, verify, f.wantVerify)
		}
	}
}
