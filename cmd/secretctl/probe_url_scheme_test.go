package main

// Challenge-gate LOW-2 (PR #319): eine Probe traegt den lebenden Wert im
// Header. Ueber http:// ginge er bei JEDEM verify im Klartext auf die
// Leitung, wegen eines Tippfehlers in der eigenen secrets.yaml und ohne
// Warnung. Der Lader verweigert das; http bleibt nur fuer Loopback erlaubt,
// namentlich.

import (
	"strings"
	"testing"
)

func TestRegistryWeistKlartextProbeAb(t *testing.T) {
	probeZeile := `    probe: {kind: http, url: https://example.invalid/, header: X-API-KEY, expect_ok: 200, expect_revoked: 401}`

	inhalt := strings.Replace(gute, probeZeile,
		`    probe: {kind: http, url: http://example.invalid/, header: X-API-KEY, expect_ok: 200, expect_revoked: 401}`, 1)
	if inhalt == gute {
		t.Fatal("Fixture-Zeile nicht gefunden; der Test ersetzt ins Leere")
	}
	_, err := LoadRegistry(schreibRegistry(t, inhalt))
	if err == nil {
		t.Fatal("eine http-Probe auf einen fremden Host wurde geladen")
	}
	for _, want := range []string{"http", "https"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Meldung %q nennt %q nicht", err, want)
		}
	}

	// Loopback-http bleibt erlaubt (lokale Dev-Instanz), namentlich.
	inhalt = strings.Replace(gute, probeZeile,
		`    probe: {kind: http, url: http://127.0.0.1:8081/health, header: X-API-KEY, expect_ok: 200, expect_revoked: 401}`, 1)
	if _, err := LoadRegistry(schreibRegistry(t, inhalt)); err != nil {
		t.Fatalf("Loopback-http wurde abgewiesen: %v", err)
	}

	// Gegenprobe: die unveraenderte https-Fixture laedt weiterhin.
	if _, err := LoadRegistry(schreibRegistry(t, gute)); err != nil {
		t.Fatalf("die https-Fixture laedt nicht mehr: %v", err)
	}
}
