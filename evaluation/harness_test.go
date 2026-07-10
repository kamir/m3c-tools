// Package evaluation is the SPEC-0280 trust-layer evaluation harness (E1–E10).
//
// Each E-metric is a Go test (and, where the cost is a single primitive, also a
// Benchmark) that exercises a SHIPPED package (pkg/skillctl/{verify,signing,
// translog,agentid,bodyscan,datascope} + the kit exporter) over a DETERMINISTIC,
// reproducible population (evaluation/internal/synth). Every metric emits one or
// more (metric, number) rows into a process-global sink which the harness writes
// to evaluation/results/RESULTS.csv at the end of the run.
//
// Honesty contract (SPEC-0280 §1 + the user's standard):
//   - no claim without a number;
//   - the population is SYNTHETIC except E4 (real committed corpus) — every row
//     records pop=synthetic|real;
//   - E6 (OIDC/JWKS offline verify) is N/A — deferred (gated P3-P2): it is NOT
//     measured and NOT faked; the harness records it as N/A with the reason.
//
// Run the full measured harness:
//
//	RUN_EVAL=1 go test ./evaluation/ -run 'TestE' -v
//
// Without RUN_EVAL the heavy measurement tests skip (so `go test ./...` stays
// fast in CI); the structural tests still run.
package evaluation

import (
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"testing"
)

// resultRow is one measured number destined for RESULTS.csv.
type resultRow struct {
	Metric string // "E1".."E10"
	Driver string // the sub-driver / variant name
	Name   string // the measured quantity, e.g. "median_ms"
	Value  string // the number (string so we can emit "0" / "N/A" honestly)
	Pop    string // "synthetic" | "real" | "n/a"
	Note   string // human note (method / N / threshold)
}

var (
	sinkMu sync.Mutex
	sink   []resultRow
)

// testingRunEval is true when the measured harness is active (RUN_EVAL set).
// Read once at package init so correctness tests (which run in plain CI) can
// decide whether to also emit a result row.
var testingRunEval = os.Getenv("RUN_EVAL") != ""

// requireEval skips a heavy measurement test unless RUN_EVAL is set. Keeps
// `go test ./...` fast in CI while letting the runner do the real measurement.
func requireEval(t *testing.T) {
	t.Helper()
	if !testingRunEval {
		t.Skip("set RUN_EVAL=1 to run the SPEC-0280 measurement harness")
	}
}

// record appends a measured row to the global sink and logs it. pop defaults to
// "synthetic" (the common case); use recordPop for real/n-a populations.
func record(t *testing.T, metric, driver, name, value, noteFmt string, args ...any) {
	t.Helper()
	recordPop(t, metric, driver, name, value, "synthetic", noteFmt, args...)
}

// recordPop is record with an explicit population label.
func recordPop(t *testing.T, metric, driver, name, value, pop, noteFmt string, args ...any) {
	t.Helper()
	note := fmt.Sprintf(noteFmt, args...)
	sinkMu.Lock()
	sink = append(sink, resultRow{Metric: metric, Driver: driver, Name: name, Value: value, Pop: pop, Note: note})
	sinkMu.Unlock()
	t.Logf("RESULT %s/%s %s=%s [%s] (%s)", metric, driver, name, value, pop, note)
}

// round4 formats a float with 4 decimals (sufficient resolution for ms/µs).
func round4(f float64) string { return fmt.Sprintf("%.4f", f) }

// round6 formats a float with 6 decimals (sub-µs per-invocation overhead, E5).
func round6(f float64) string { return fmt.Sprintf("%.6f", f) }

// round0 formats a float as an integer string.
func round0(f float64) string { return fmt.Sprintf("%.0f", math.Round(f)) }

// TestZZZWriteResults runs LAST (lexical "ZZZ" ordering) and flushes the sink to
// evaluation/results/RESULTS.csv. It is part of the measured run (guarded by
// RUN_EVAL) so a plain `go test ./...` never overwrites committed results.
//
// The name guarantees it sorts after every TestE* metric, so all rows are in the
// sink by the time it runs.
func TestZZZWriteResults(t *testing.T) {
	requireEval(t)
	sinkMu.Lock()
	rows := make([]resultRow, len(sink))
	copy(rows, sink)
	sinkMu.Unlock()

	if len(rows) == 0 {
		t.Skip("no results recorded (run the TestE* metrics in the same `go test` invocation)")
	}

	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Metric != rows[j].Metric {
			return rows[i].Metric < rows[j].Metric
		}
		if rows[i].Driver != rows[j].Driver {
			return rows[i].Driver < rows[j].Driver
		}
		return rows[i].Name < rows[j].Name
	})

	outDir := filepath.Join("results")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir results: %v", err)
	}
	out := filepath.Join(outDir, "RESULTS.csv")
	f, err := os.Create(out)
	if err != nil {
		t.Fatalf("create %s: %v", out, err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	_ = w.Write([]string{"metric", "driver", "measured", "value", "population", "note"})
	for _, r := range rows {
		_ = w.Write([]string{r.Metric, r.Driver, r.Name, r.Value, r.Pop, r.Note})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		t.Fatalf("write csv: %v", err)
	}

	abs, _ := filepath.Abs(out)
	t.Logf("wrote %d result rows to %s (GOOS=%s GOARCH=%s NumCPU=%d %s)",
		len(rows), abs, runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())
}
