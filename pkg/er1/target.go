// target.go: EINE Aufloesung eines ER1-Ziels auf (Basis-URL, TLS-Pruefung).
//
// Warum das hier steht und nicht zweimal woanders (BUG-0444, BUG-0445):
//
// Dieselbe Funktion existierte in zwei Baeumen, `pkg/session.ER1Endpoint` und
// `cmd/skillctl.er1Endpoint`, nahezu wortgleich. Beide entschieden die
// TLS-Pruefung mit `strings.Contains(target, "127.0.0.1")` statt mit dem
// geparsten Host, in BEIDEN Zweigen, die zweite Stelle jeweils direkt unter
// einem Kommentar, der die richtige Regel nennt. Vier Umgehungen, belegt:
// `https://localhost.angreifer.example/` und `https://127.0.0.1.angreifer.example/`
// brauchen dafuer nicht einmal einen Abfrageteil.
//
// BUG-0444 reparierte die eine Kopie. Der Zwilling blieb und wurde erst beim
// naechsten Arbeitsschritt gefunden. Eine dritte korrekte Kopie haette dieselbe
// Geschichte ein viertes Mal ermoeglicht: die Divergenz IST der Fehler, nicht
// nur ihr Inhalt. Deshalb eine Fassung, und die Aufrufer delegieren.
package er1

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// resolveTargetWarnOnce begrenzt die Abweisungsmeldung auf eine pro Prozess.
var resolveTargetWarnOnce sync.Once

// VerifyTLSFor wendet die SEC-M7-Regel auf EINE Basis-URL an: ein Ueberspringen
// der Zertifikatspruefung wird nur fuer einen geparsten Loopback-Host gewaehrt,
// fuer jeden anderen Host wird fail-closed auf Pruefung zurueckgestellt und die
// Abweisung einmal auf stderr genannt.
//
// `wanted` ist, was der Aufrufer wuenscht; der Rueckgabewert ist, was er
// bekommt. Dieselbe Regel wie applyTLSVerificationPolicy, nur auf einer
// einzelnen URL statt auf einer geladenen Config.
func VerifyTLSFor(baseURL string, wanted bool) bool {
	if wanted {
		return true
	}
	if isLoopbackURL(baseURL) {
		return false
	}
	resolveTargetWarnOnce.Do(func() {
		fmt.Fprintf(os.Stderr, "[er1] SECURITY: REFUSING to disable TLS verification for non-loopback base %q; certificate verification stays ON (only 127.0.0.1/localhost may skip it)\n", baseURL)
	})
	return true
}

// ResolveTarget loest einen ER1-Zielnamen auf (ADR-0003-Matrix).
//
//	""  / "prod"   die Produktionsinstanz, immer mit Pruefung
//	"local"        127.0.0.1:8081, Pruefung darf entfallen
//	"http..."      die URL selbst; Pruefung entfaellt nur bei Loopback-HOST
//	sonst          ER1_API_URL, falls gesetzt, sonst prod
//
// Die Pruefentscheidung laeuft IMMER durch VerifyTLSFor. Ein Aufrufer, der
// hier vorbei entscheidet, baut BUG-0444 nach.
func ResolveTarget(target string) (baseURL string, verifySSL bool) {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case "", "prod":
		return "https://onboarding.guide", true
	case "local":
		return "https://127.0.0.1:8081", VerifyTLSFor("https://127.0.0.1:8081", false)
	}
	if strings.HasPrefix(target, "http") {
		base := strings.TrimRight(target, "/")
		return base, VerifyTLSFor(base, false)
	}
	if u := os.Getenv("ER1_API_URL"); u != "" {
		base := strings.TrimRight(strings.TrimSuffix(u, "/upload_2"), "/")
		return base, VerifyTLSFor(base, os.Getenv("ER1_VERIFY_SSL") != "false")
	}
	return "https://onboarding.guide", true
}
