package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// Prüfstand für die beiden anderen Binaries des Repos.
//
// `BinaryPath` baut m3c-tools. skillctl und secretctl waren bis 2026-09-15 in
// keinem einzigen e2e-Test vertreten, obwohl sie die Verteilung von Skills und
// Agenten und den Umgang mit Geheimnissen tragen. Die Befehle waren je einzeln
// getestet; was durch den ECHTEN Befehl geht, war es nicht.
//
// Genau dort saßen an diesem Tag drei Fehler, die kein Einheitentest fand: das
// Regal der Attestierung, das Zielverzeichnis des Plans, und die Reichweite
// einer Flagge. Alle drei an den Nähten ZWISCHEN den Einheiten.

var (
	toolOnce = map[string]*sync.Once{}
	toolPath = map[string]string{}
	toolErr  = map[string]error{}
	toolMu   sync.Mutex
)

// ToolPath baut eines der Binaries des Repos und gibt seinen Pfad zurück.
// Der Bau läuft je Binary genau einmal je Testlauf.
func ToolPath(t *testing.T, name string) string {
	t.Helper()
	toolMu.Lock()
	if _, ok := toolOnce[name]; !ok {
		toolOnce[name] = &sync.Once{}
	}
	once := toolOnce[name]
	toolMu.Unlock()

	once.Do(func() {
		root := RepoRoot(t)
		out := filepath.Join(root, "build", name+"-e2e-test")
		if runtime.GOOS == "windows" {
			out += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", out, "./cmd/"+name)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if b, err := cmd.CombinedOutput(); err != nil {
			toolMu.Lock()
			toolErr[name] = fmt.Errorf("build %s failed: %v\n%s", name, err, b)
			toolMu.Unlock()
			return
		}
		toolMu.Lock()
		toolPath[name] = out
		toolMu.Unlock()
	})

	toolMu.Lock()
	defer toolMu.Unlock()
	if err := toolErr[name]; err != nil {
		t.Fatalf("ToolPath: %v", err)
	}
	return toolPath[name]
}

// RunTool führt eines der Binaries aus. `env` ersetzt die Umgebung NICHT,
// sondern ergänzt sie, wie RunCLIWithEnv es tut.
func RunTool(t *testing.T, name string, env []string, args ...string) *CLIResult {
	t.Helper()
	cmd := exec.Command(ToolPath(t, name), args...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if ok := asExitError(err, &ee); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	// Combined wie bei RunCLIWithEnv: die Assert-Helfer des Pakets lesen
	// Stdout, und CombinedOutput liefert beides verschraenkt.
	return &CLIResult{Stdout: string(out), Combined: string(out), ExitCode: code, Err: err}
}

func asExitError(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

// AssertNotContains ist die Umkehrung von AssertContains und für Geheimnisse
// die wichtigere Richtung: eine Zusicherung, dass etwas NICHT in der Ausgabe
// steht, ist der einzige Weg, die Schwärzungsregel durch das echte Binary zu
// prüfen (SPEC-0438 AC-6).
func AssertNotContains(t *testing.T, r *CLIResult, verboten string) {
	t.Helper()
	if strings.Contains(r.Stdout, verboten) {
		t.Fatalf("die Ausgabe enthaelt, was sie nie enthalten darf.\nAusgabe:\n%s", r.Stdout)
	}
}

// RepoRoot laeuft vom AKTUELLEN Verzeichnis aufwaerts zum Makefile. Sobald ein
// Test per t.Chdir in ein temporaeres Verzeichnis wechselt, gibt es dort keins
// mehr, und der Bau scheitert an einer Stelle, die mit dem Test nichts zu tun
// hat.
//
// init laeuft vor jedem Test und damit vor jedem Wechsel. Es fuellt dasselbe
// sync.Once, das RepoRoot benutzt, also steht die Wurzel danach fest, egal wo
// ein einzelner Test hinlaeuft.
func init() {
	repoRootOnce.Do(func() {
		dir, err := os.Getwd()
		if err != nil {
			return
		}
		for {
			if _, err := os.Stat(filepath.Join(dir, "Makefile")); err == nil {
				repoRootPath = dir
				return
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				return
			}
			dir = parent
		}
	})
}
