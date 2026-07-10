package main

// pin_cmds.go — SPEC-0247 §7.3 P1.3: managed-settings pinning.
//
//	skillctl pin generate  → emit the Claude Code managed-settings.json that
//	                         wires the trust gate (SPEC-0247 §7.1) un-deletably.
//	skillctl pin status    → read the platform managed-settings file and report
//	                         whether the gate is pinned (advisory / partial /
//	                         pinned / pinned-strict / tampered).
//	skillctl pin install   → stage the file + print the privileged runbook
//	                         (or, when run as root with --confirm, write it).
//
// Without this, SPEC-0247 §3.2's "a local user can just delete the hook" caveat
// stands and the whole gate is advisory. This verb is the prerequisite (P0.0)
// for SPEC-0317 (skillctl Enterprise). It makes no network calls and performs no
// privileged write unless explicitly run as root with --confirm.
//
// Exit codes (operational, deliberately outside the SPEC-0188 trust range):
//
//	0  ok / pinned
//	1  usage or I/O error
//	2  not pinned (status: absent / partial / tampered)
//	3  needs privilege — a manual sudo step is required (install, non-root)

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/pin"
)

// geteuid is a seam so tests can drive the privileged install branch.
var geteuid = os.Geteuid

const (
	pinExitOK          = 0
	pinExitError       = 1
	pinExitNotPinned   = 2
	pinExitNeedPrivMsg = 3
)

func runPin(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, pinUsage)
		return pinExitError
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "generate", "gen":
		return runPinGenerate(rest, stdout, stderr)
	case "status", "verify":
		return runPinStatus(rest, stdout, stderr)
	case "install":
		return runPinInstall(rest, stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprintln(stdout, pinUsage)
		return pinExitOK
	default:
		fmt.Fprintf(stderr, "skillctl pin: unknown subcommand %q\n\n%s\n", sub, pinUsage)
		return pinExitError
	}
}

const pinUsage = `Usage: skillctl pin <generate|status|install> [flags]

  generate   Print the Claude Code managed-settings.json that pins the trust gate.
             Flags: --binary <path> (default: this skillctl), --strict, --harden, --enterprise, --out <file>
  status     Report whether the gate is pinned in managed settings.
             Flags: --path <file> (override), --json
  install    Stage the file and print the sudo runbook (root+--confirm writes it).
             Flags: --binary <path>, --strict, --harden, --enterprise, --path <target>, --confirm

--strict adds "allowManagedHooksOnly: true" — the full CISO lockdown that also
DISABLES every other user/project hook. Without it the gate is already
un-deletable by non-privileged (non-root) users and its deny is absolute; the
operator's own hooks keep working. Root, or anyone with write access to the
managed-settings directory, can still remove it (SPEC-0247 §3.2/§7.3).
--harden implies --strict and also blocks --dangerously-skip-permissions.`

// defaultBinary is the absolute path of the running skillctl (SPEC-0247 §7.2:
// an absolute path makes a missing binary fail the spawn, not silently vanish).
func defaultBinary() string {
	if exe, err := os.Executable(); err == nil {
		if resolved, err2 := filepath.EvalSymlinks(exe); err2 == nil {
			return resolved
		}
		return exe
	}
	return "skillctl"
}

func runPinGenerate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pin generate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	binary := fs.String("binary", "", "absolute path to skillctl (default: this binary)")
	strict := fs.Bool("strict", false, "add allowManagedHooksOnly:true (disables ALL user hooks)")
	harden := fs.Bool("harden", false, "imply --strict and block --dangerously-skip-permissions")
	enterprise := fs.Bool("enterprise", false, "add skillctlEnterprise:true — enables the R-7.2 offline `locked` state")
	out := fs.String("out", "", "write to file instead of stdout")
	if err := fs.Parse(args); err != nil {
		return pinExitError
	}
	bin := *binary
	if bin == "" {
		bin = defaultBinary()
	}
	b, err := pin.Generate(pin.GenerateOptions{BinaryPath: bin, Strict: *strict, Harden: *harden, Enterprise: *enterprise})
	if err != nil {
		fmt.Fprintf(stderr, "skillctl pin generate: %v\n", err)
		return pinExitError
	}
	if *strict || *harden {
		fmt.Fprintln(stderr, strictWarning)
	}
	if *out != "" {
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			fmt.Fprintf(stderr, "skillctl pin generate: write %s: %v\n", *out, err)
			return pinExitError
		}
		fmt.Fprintf(stderr, "wrote %s\n", *out)
		return pinExitOK
	}
	_, _ = stdout.Write(b)
	return pinExitOK
}

const strictWarning = `WARNING (--strict): allowManagedHooksOnly:true makes Claude Code run ONLY hooks
defined in managed settings. Every other user/project hook (usage telemetry,
formatters, etc.) will STOP running. Include any hooks you still need in the
managed file. The gate is already un-deletable without --strict.`

func runPinStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pin status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pathOverride := fs.String("path", "", "managed-settings path override (default: platform path)")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return pinExitError
	}
	path := *pathOverride
	if path == "" {
		p, err := pin.DefaultManagedSettingsPath()
		if err != nil {
			fmt.Fprintf(stderr, "skillctl pin status: %v\n", err)
			return pinExitError
		}
		path = p
	}

	data, readErr := os.ReadFile(path)
	var res pin.StatusResult
	absent := false
	if readErr != nil {
		if os.IsNotExist(readErr) {
			absent = true
			res = pin.StatusResult{Level: pin.LevelAbsent, Findings: []string{
				"no managed-settings file at " + path + " — the gate is ADVISORY (a user can delete the user-level hook). Run `skillctl pin install`.",
			}}
		} else {
			fmt.Fprintf(stderr, "skillctl pin status: read %s: %v\n", path, readErr)
			return pinExitError
		}
	} else {
		res = pin.Verify(data)
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		out := struct {
			Path string `json:"path"`
			pin.StatusResult
		}{Path: path, StatusResult: res}
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(stderr, "skillctl pin status: %v\n", err)
			return pinExitError
		}
	} else {
		fmt.Fprintf(stdout, "managed settings: %s\n", path)
		fmt.Fprintf(stdout, "gate pinning:     %s\n", res.Level)
		fmt.Fprintf(stdout, "  SessionStart sweep hook: %s\n", yesNo(res.HasSweepHook))
		fmt.Fprintf(stdout, "  PreToolUse verify-hook:  %s\n", yesNo(res.HasVerifyHook))
		if res.Pinned() {
			fmt.Fprintf(stdout, "  allowManagedHooksOnly:   %s\n", yesNo(res.AllowManagedHooksOnly))
			fmt.Fprintf(stdout, "  blocks --dangerously-skip-permissions: %s\n", yesNo(res.DisableBypass))
		}
		for _, f := range res.Findings {
			fmt.Fprintf(stdout, "  - %s\n", f)
		}
	}
	if res.Pinned() {
		return pinExitOK
	}
	_ = absent
	return pinExitNotPinned
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func runPinInstall(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pin install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	binary := fs.String("binary", "", "absolute path to skillctl (default: this binary)")
	strict := fs.Bool("strict", false, "add allowManagedHooksOnly:true (disables ALL user hooks)")
	harden := fs.Bool("harden", false, "imply --strict and block --dangerously-skip-permissions")
	enterprise := fs.Bool("enterprise", false, "add skillctlEnterprise:true — enables the R-7.2 offline `locked` state")
	pathOverride := fs.String("path", "", "target managed-settings path override")
	confirm := fs.Bool("confirm", false, "when run as root, actually write the file")
	if err := fs.Parse(args); err != nil {
		return pinExitError
	}
	bin := *binary
	if bin == "" {
		bin = defaultBinary()
	}
	opts := pin.GenerateOptions{BinaryPath: bin, Strict: *strict, Harden: *harden, Enterprise: *enterprise}
	target := *pathOverride
	if target == "" {
		p, perr := pin.DefaultManagedSettingsPath()
		if perr != nil {
			fmt.Fprintf(stderr, "skillctl pin install: %v\n", perr)
			return pinExitError
		}
		target = p
	}

	// Never blind-overwrite: managed-settings.json is a SHARED policy file that
	// may already carry other managed hooks / permission rules. Read it and MERGE
	// our gate in, preserving everything else. If it exists but we cannot read it
	// (permission), we can only produce a gate-only file the human must merge by
	// hand — never a blind copy.
	existing, readErr := os.ReadFile(target)
	var content []byte
	targetExists := false
	safeToCopy := true
	switch {
	case readErr == nil:
		targetExists = true
		merged, mErr := pin.Merge(existing, opts)
		if mErr != nil {
			fmt.Fprintf(stderr, "skillctl pin install: %v\n", mErr)
			return pinExitError
		}
		content = merged
	case os.IsNotExist(readErr):
		content, _ = pin.Generate(opts)
	default:
		// Exists but unreadable → cannot merge; emit gate-only + warn loudly.
		targetExists = true
		safeToCopy = false
		content, _ = pin.Generate(opts)
	}

	if *strict || *harden {
		fmt.Fprintln(stderr, strictWarning)
	}

	root := geteuid() == 0 // -1 (Windows/unsupported) → not root → runbook path
	if root && *confirm {
		if !safeToCopy {
			fmt.Fprintf(stderr, "skillctl pin install: %s exists but is unreadable — refusing to overwrite; merge manually.\n", target)
			return pinExitError
		}
		return pinRootWrite(target, content, targetExists, existing, stdout, stderr)
	}

	// Non-root (or root without --confirm): stage + emit the runbook. The staged
	// file is the FULL merged result when the target was readable, so a copy is
	// safe; otherwise it is gate-only and MUST be merged by hand.
	staged, serr := stagePinFile(content)
	if serr != nil {
		fmt.Fprintf(stderr, "skillctl pin install: stage: %v\n", serr)
		return pinExitError
	}
	printPinRunbook(stdout, staged, target, targetExists, safeToCopy)
	return pinExitNeedPrivMsg
}

// pinRootWrite performs the privileged install: refuse a symlinked target, back
// up any existing file, write the merged content, then RE-READ the file from
// disk and verify what actually landed (not the in-memory buffer).
func pinRootWrite(target string, content []byte, targetExists bool, existing []byte, stdout, stderr io.Writer) int {
	if fi, err := os.Lstat(target); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		fmt.Fprintf(stderr, "skillctl pin install: %s is a symlink — refusing to write through it.\n", target)
		return pinExitError
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		fmt.Fprintf(stderr, "skillctl pin install: mkdir %s: %v\n", filepath.Dir(target), err)
		return pinExitError
	}
	if targetExists {
		backup := target + ".bak-" + time.Now().UTC().Format("20060102-150405")
		if fi, err := os.Lstat(backup); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			fmt.Fprintf(stderr, "skillctl pin install: backup path %s is a symlink — refusing.\n", backup)
			return pinExitError
		}
		if err := os.WriteFile(backup, existing, 0o644); err != nil {
			fmt.Fprintf(stderr, "skillctl pin install: backup %s: %v\n", backup, err)
			return pinExitError
		}
		fmt.Fprintf(stdout, "backed up existing managed settings → %s\n", backup)
	}
	if err := os.WriteFile(target, content, 0o644); err != nil {
		fmt.Fprintf(stderr, "skillctl pin install: write %s: %v\n", target, err)
		return pinExitError
	}
	// Honest re-verify: read back what actually landed on disk and verify THAT.
	back, rerr := os.ReadFile(target)
	if rerr != nil {
		fmt.Fprintf(stderr, "skillctl pin install: wrote %s but cannot read it back: %v\n", target, rerr)
		return pinExitError
	}
	res := pin.Verify(back)
	fmt.Fprintf(stdout, "installed managed settings at %s (verified on disk: %s)\n", target, res.Level)
	if !res.Pinned() {
		fmt.Fprintln(stderr, "skillctl pin install: post-write verification did NOT read back as pinned — check the target.")
		return pinExitNotPinned
	}
	return pinExitOK
}

// stagePinFile writes content to ~/.claude/skillctl/managed-settings.staged.json
// (0600). It refuses to write through a symlink at that path.
func stagePinFile(content []byte) (string, error) {
	home, err := userHome()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".claude", "skillctl")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	staged := filepath.Join(dir, "managed-settings.staged.json")
	if fi, err := os.Lstat(staged); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s is a symlink — refusing to write through it", staged)
	}
	if err := os.WriteFile(staged, content, 0o600); err != nil {
		return "", err
	}
	// Tighten in case the file pre-existed with looser perms (WriteFile doesn't chmod).
	_ = os.Chmod(staged, 0o600)
	return staged, nil
}

func printPinRunbook(w io.Writer, staged, target string, targetExists, safeToCopy bool) {
	dir := filepath.Dir(target)
	fmt.Fprintln(w, "Staged the managed-settings content at:")
	fmt.Fprintf(w, "  %s\n\n", staged)
	fmt.Fprintln(w, "This is a privileged (🔴 red-governance) step — a human installs it with admin rights.")
	if targetExists && !safeToCopy {
		fmt.Fprintf(w, "\nNOTE: %s already exists but could not be read here, so the staged file\n", target)
		fmt.Fprintln(w, "contains ONLY the gate. Do NOT blindly copy it — MERGE the two SessionStart/")
		fmt.Fprintln(w, "PreToolUse gate hooks into the existing file to avoid destroying other policy.")
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "Then verify:  skillctl pin status")
		return
	}
	if targetExists {
		fmt.Fprintln(w, "(The staged file already MERGES your existing managed settings — other policy is preserved.)")
	}
	fmt.Fprintln(w, "Review the staged file, then run:")
	fmt.Fprintln(w, "")
	if runtime.GOOS == "windows" {
		fmt.Fprintf(w, "  (Admin PowerShell)\n")
		fmt.Fprintf(w, "  New-Item -ItemType Directory -Force -Path \"%s\"\n", dir)
		fmt.Fprintf(w, "  Copy-Item -Force \"%s\" \"%s\"\n", staged, target)
	} else {
		fmt.Fprintf(w, "  sudo mkdir -p %s\n", shellQuote(dir))
		fmt.Fprintf(w, "  sudo cp %s %s\n", shellQuote(staged), shellQuote(target))
		fmt.Fprintf(w, "  sudo chmod 0644 %s\n", shellQuote(target))
	}
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Then verify:  skillctl pin status")
}

func shellQuote(p string) string {
	if strings.ContainsAny(p, " \t'\"") {
		return "'" + strings.ReplaceAll(p, "'", `'\''`) + "'"
	}
	return p
}
