// Command skillctl-sim runs the trust-plane simulation: a generated corpus of
// multi-principal scenarios, each carrying a SPEC-derived prediction, executed
// against the real skillctl binary and a real git registry.
//
//	skillctl-sim list                 print the corpus and what each scenario predicts
//	skillctl-sim run [-n 100]         execute it and compare theory with reality
//	skillctl-sim run -md report.md    also write the report as a document
//
// Exit: 0 when every claimed prediction held and no invariant was violated,
// 1 otherwise. A run that ends 1 has found either a bug or a wrong specification,
// and the report says which steps disagreed.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"

	"github.com/kamir/m3c-tools/pkg/skillctl/sim"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "list":
		os.Exit(runList(os.Args[2:]))
	case "run":
		os.Exit(runRun(os.Args[2:]))
	case "theory":
		os.Exit(runTheory(os.Args[2:]))
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "skillctl-sim: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: skillctl-sim <list|run> [flags]

  theory               check the SPECIFICATION alone, with no binary involved
  list                 print the generated corpus with its predictions
  run                  execute the corpus against the real binary and compare

Flags (run):
  -n <count>           how many scenarios (0 = the whole corpus)
  -skillctl <path>     the binary under test (default ./build/skillctl, then PATH)
  -jobs <n>            parallel scenarios (default: half the cores)
  -md <file>           also write the report as Markdown`)
}

func runList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	n := fs.Int("n", 0, "how many scenarios to print (0 = all)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	corpus := sim.Generate(*n)
	fmt.Printf("corpus: %d scenarios\n\n", len(corpus))
	for _, sc := range corpus {
		fmt.Printf("%s\n  %s\n", sc.ID, sc.Title)
		for _, st := range sc.Steps {
			claim := ""
			if !st.Expect.Claimed {
				claim = "  [OUT OF MODEL]"
			}
			gate := ""
			if st.Expect.Gate != "" {
				gate = " " + st.Expect.Gate
			}
			fmt.Printf("    %-26s -> %s%s exit=%d%s\n", st.Action, st.Expect.Outcome, gate, st.Expect.Exit, claim)
		}
		fmt.Println()
	}
	return 0
}

func runRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	n := fs.Int("n", 0, "how many scenarios (0 = all)")
	bin := fs.String("skillctl", "", "path to the skillctl binary under test")
	jobs := fs.Int("jobs", runtime.NumCPU()/2, "parallel scenarios")
	mdOut := fs.String("md", "", "write the report as Markdown to this file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	skillctl, err := resolveBinary(*bin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *jobs < 1 {
		*jobs = 1
	}

	root, err := os.MkdirTemp("", "skillctl-sim-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(root)

	corpus := sim.Generate(*n)
	fmt.Printf("running %d scenarios against %s (%d parallel)\n", len(corpus), skillctl, *jobs)

	results := make([]sim.ScenarioResult, len(corpus))
	sem := make(chan struct{}, *jobs)
	var wg sync.WaitGroup
	for i, sc := range corpus {
		wg.Add(1)
		go func(i int, sc sim.Scenario) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = sim.Execute(skillctl, root, sc)
			fmt.Print(".")
		}(i, sc)
	}
	wg.Wait()
	fmt.Println()

	rep := sim.Report{Results: results, BinaryID: sim.BinaryHash(skillctl)}
	rep.Write(os.Stdout)

	if *mdOut != "" {
		if err := os.WriteFile(*mdOut, []byte(rep.Markdown()), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "write report:", err)
			return 1
		}
		fmt.Printf("report written: %s\n", *mdOut)
	}

	_, conflicts, _, _ := rep.Summary()
	if conflicts > 0 || len(rep.Violations()) > 0 {
		return 1
	}
	return 0
}

func resolveBinary(flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if fi, err := os.Stat("build/skillctl"); err == nil && !fi.IsDir() {
		abs, _ := os.Getwd()
		return abs + "/build/skillctl", nil
	}
	if p, err := exec.LookPath("skillctl"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("skillctl-sim: no skillctl found; build one with `make build-skillctl` or pass -skillctl <path>")
}

// runTheory answers the question that has to come first: is the specification
// sound on its own? It needs no skillctl, no registry and no network, because it
// reasons over the state space rather than over a run.
func runTheory(args []string) int {
	fs := flag.NewFlagSet("theory", flag.ContinueOnError)
	n := fs.Int("n", 0, "corpus size to judge coverage against (0 = the whole corpus)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	corpus := sim.Generate(*n)
	rep := sim.CheckTheory(corpus)
	rep.WriteTheory(os.Stdout, corpus)
	rep.WriteUnreachable(os.Stdout)
	if !rep.Sound() {
		fmt.Fprintln(os.Stderr, "the specification did not pass its own check: fix the model before testing any code against it")
		return 1
	}
	return 0
}
