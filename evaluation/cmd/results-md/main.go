// Command results-md renders evaluation/results/RESULTS.csv into a committed
// Markdown table (RESULTS.md) the white paper / IEEE paper includes verbatim.
// It also stamps the run environment (GOOS/GOARCH/NumCPU/Go version + an
// optional CPU label from the EVAL_CPU env var) so the paper can cite the
// hardware. Pure stdlib; no nondeterminism beyond the recorded numbers.
package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

func main() {
	root := "evaluation/results"
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	csvPath := filepath.Join(root, "RESULTS.csv")
	mdPath := filepath.Join(root, "RESULTS.md")

	f, err := os.Open(csvPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "results-md: open %s: %v\n", csvPath, err)
		os.Exit(1)
	}
	defer f.Close()

	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "results-md: parse csv: %v\n", err)
		os.Exit(1)
	}
	if len(rows) < 2 {
		fmt.Fprintln(os.Stderr, "results-md: no data rows in RESULTS.csv")
		os.Exit(1)
	}

	header, data := rows[0], rows[1:]
	// Stable sort by metric, driver, measured.
	sort.SliceStable(data, func(i, j int) bool {
		for c := 0; c < 3 && c < len(header); c++ {
			if data[i][c] != data[j][c] {
				return data[i][c] < data[j][c]
			}
		}
		return false
	})

	var b strings.Builder
	b.WriteString("# SPEC-0280 Evaluation Results (E1–E10)\n\n")
	b.WriteString("> Generated from `RESULTS.csv` by `evaluation/cmd/results-md`. Do not hand-edit;\n")
	b.WriteString("> re-run the harness (`RUN_EVAL=1 go test ./evaluation/...`) then regenerate.\n\n")

	cpu := os.Getenv("EVAL_CPU")
	if cpu == "" {
		cpu = "(unrecorded — set EVAL_CPU to stamp the CPU model)"
	}
	b.WriteString("## Run environment\n\n")
	fmt.Fprintf(&b, "- CPU: %s\n", cpu)
	fmt.Fprintf(&b, "- OS/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&b, "- Logical CPUs: %d\n", runtime.NumCPU())
	fmt.Fprintf(&b, "- Go: %s\n", runtime.Version())
	b.WriteString("- Population: **synthetic** for all metrics except **E4** (the real committed SPEC-0246 corpus).\n\n")

	b.WriteString("## Results\n\n")
	b.WriteString("| Metric | Driver | Measured | Value | Population | Note |\n")
	b.WriteString("|--------|--------|----------|-------|------------|------|\n")
	for _, r := range data {
		for len(r) < 6 {
			r = append(r, "")
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n",
			md(r[0]), md(r[1]), md(r[2]), md(r[3]), md(r[4]), md(r[5]))
	}
	b.WriteString("\nE6 is recorded as `N/A — deferred (gated P3-P2)`: the OIDC/JWKS binding ")
	b.WriteString("(SPEC-0277 P2) is not built, so there is no path to measure — no number is fabricated.\n")

	if err := os.WriteFile(mdPath, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "results-md: write %s: %v\n", mdPath, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d rows)\n", mdPath, len(data))
}

// md escapes the pipe character so a note can't break the table.
func md(s string) string { return strings.ReplaceAll(s, "|", "\\|") }
