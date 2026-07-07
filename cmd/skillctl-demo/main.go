package main

// skillctl-demo — a self-contained, offline demo binary that shows a CISO the
// skillctl trust plane CONTAINING an attack, live, with the real exit codes.
//
// P0: an interactive CLI that steps three LIVE scenarios (S1, S2A, S5) against
//     the real skillctl in a hermetic sandbox, plus honest roadmap panels.
// P1: an embedded web mirror (SSE) serving the scenario SVGs + a live terminal.
//
// Honesty rule (non-negotiable): LIVE steps run the real skillctl and show its
// real exit code; PARTIAL/ROADMAP panels run nothing and are labelled as such.

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type config struct {
	mode       string
	port       int
	skillctl   string
	noBrowser  bool
	noColor    bool
	noWeb      bool
	kioskDelay time.Duration
	selftest   bool
}

func main() {
	cfg := parseFlags()

	skctl, err := resolveSkillctl(cfg.skillctl)
	if err != nil {
		fmt.Fprintln(os.Stderr, "skillctl-demo: "+err.Error())
		os.Exit(1)
	}

	sb, err := NewSandbox()
	if err != nil {
		fmt.Fprintln(os.Stderr, "skillctl-demo: sandbox: "+err.Error())
		os.Exit(1)
	}
	defer sb.Cleanup()

	// Clean up the sandbox on Ctrl-C too.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		sb.Cleanup()
		os.Exit(0)
	}()

	if cfg.selftest {
		os.Exit(runSelftest(sb, skctl))
	}

	renderer := &CLIRenderer{W: os.Stdout, Color: cfg.noColor == false && isTerminal(os.Stdout)}
	bus := NewBus(renderer)

	// P1: web mirror.
	var srv *Server
	url := ""
	if !cfg.noWeb {
		srv = NewServer(bus, sb, skctl, cfg.mode)
		addr, err := srv.Start(cfg.port)
		if err != nil {
			fmt.Fprintln(os.Stderr, "skillctl-demo: web server: "+err.Error())
		} else {
			url = "http://" + addr
		}
	}

	ready := "sandbox HOME=" + sb.Home + "  ·  skillctl=" + skctl
	if url != "" {
		ready += "  ·  web mirror " + url
	}
	bus.Emit(Event{Kind: "ready", Text: ready})

	if url != "" && !cfg.noBrowser {
		openBrowser(url)
	}

	d := &Driver{sb: sb, run: &Runner{Skillctl: skctl, Home: sb.Home}, bus: bus}
	pause := newPauser(cfg, renderer)
	d.wait = pause

	scenarios := Scenarios()
	if cfg.mode == "kiosk" {
		for {
			runDeck(d, scenarios, pause)
			bus.Emit(Event{Kind: "reset"})
			_ = sb.Reset()
			pause()
		}
	}

	// guided (default): one pass, then hold so the browser mirror stays up.
	runDeck(d, scenarios, pause)
	bus.Emit(Event{Kind: "done", Text: "Every LIVE verdict above is a real skillctl exit code."})
	if url != "" {
		fmt.Fprintln(os.Stdout, "\n  Web mirror still serving at "+url+" — Ctrl-C to exit.")
		select {} // block until Ctrl-C (signal handler cleans up)
	}
}

// runDeck walks every scenario: header, then either the live steps or (for a
// roadmap panel) a pause on the labelled card.
func runDeck(d *Driver, scenarios []Scenario, pause func()) {
	for _, s := range scenarios {
		d.scenario(&s)
		if s.Run != nil {
			pause()
			s.Run(d)
		} else {
			d.note("Roadmap panel — nothing is run here (honesty rule). See the note above.")
		}
		pause()
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.mode, "mode", "guided", "guided (Enter to advance) | kiosk (timed auto-loop)")
	flag.IntVar(&cfg.port, "port", 8765, "web mirror port on 127.0.0.1")
	flag.StringVar(&cfg.skillctl, "skillctl", "", "path to the real skillctl binary (default: ./build/skillctl, next to this binary, or $PATH)")
	flag.BoolVar(&cfg.noBrowser, "no-browser", false, "do not auto-open the browser")
	flag.BoolVar(&cfg.noColor, "no-color", false, "disable ANSI colour in the terminal")
	flag.BoolVar(&cfg.noWeb, "no-web", false, "CLI only; do not start the web mirror")
	flag.DurationVar(&cfg.kioskDelay, "kiosk-delay", 3*time.Second, "auto-advance delay in kiosk mode")
	flag.BoolVar(&cfg.selftest, "selftest", false, "run the LIVE scenarios non-interactively and assert the real exit codes")
	flag.Parse()
	if cfg.mode != "guided" && cfg.mode != "kiosk" {
		cfg.mode = "guided"
	}
	return cfg
}

// newPauser returns the between-step pause: read Enter in guided mode, sleep in
// kiosk mode. Selftest never pauses (it sets its own no-op).
func newPauser(cfg config, r *CLIRenderer) func() {
	if cfg.mode == "kiosk" {
		return func() { time.Sleep(cfg.kioskDelay) }
	}
	in := bufio.NewReader(os.Stdin)
	return func() {
		if r.Color {
			fmt.Fprint(os.Stdout, cDim+"  [Enter] ▸ "+cReset)
		} else {
			fmt.Fprint(os.Stdout, "  [Enter] ▸ ")
		}
		_, _ = in.ReadString('\n')
	}
}

// resolveSkillctl finds the real skillctl binary. Order: explicit flag →
// ./build/skillctl (dev tree) → next to this binary (shipped zip) → $PATH.
func resolveSkillctl(explicit string) (string, error) {
	name := "skillctl"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	var candidates []string
	if explicit != "" {
		candidates = append(candidates, explicit)
	}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "build", name), filepath.Join(cwd, name))
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), name))
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("could not locate %s (pass --skillctl <path>); looked in %s and $PATH", name, strings.Join(candidates, ", "))
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

// isTerminal reports whether f is a character device (best-effort; used to
// auto-disable colour when piped).
func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}
