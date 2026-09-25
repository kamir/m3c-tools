// skillctl trust-freeze: capture, approve, verify and compare a signed record
// of what a host looks like (SPEC-0466, with SPEC-0467 to SPEC-0471).
//
//	doctor            what a capture with a profile could collect here
//	capture           write a capture bundle (never a baseline)
//	baseline approve  turn a verified capture into a signed baseline
//	verify            check a bundle offline
//	diff              verify two bundles, compare them, judge the diff
//	report            project a bundle onto the JSON report document
//
// Exit space 0/1/2 (docs/v2/referenz/CLI-VERBS.md): 0 ok, 1 a run that failed
// or a threshold that was exceeded, 2 a usage error. Every JSON output carries
// result_class, so a script can tell the causes of exit 1 apart.
//
// capture never approves: only `baseline approve` reaches the seal package
// (SPEC-0470 TF05-R2, TF05-R6; guarded by a test in this package).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/capture"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/compare"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/policy"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/report"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/seal"
)

// Result classes of the trust-freeze JSON outputs (SPEC-0466 section 5.9).
const (
	tfResultOK           = "ok"
	tfResultUsage        = "usage_error"
	tfResultExecution    = "execution_error"
	tfResultVerification = "verification_failure"
	tfResultDrift        = "drift_threshold_exceeded"
	tfResultIncomplete   = "incomplete_capture"
)

// tfNotImplemented is the one answer for an option this version lacks.
const tfNotImplemented = "not implemented in this version"

// tfPlatformSupport is what doctor states about platform support: full
// support needs real-platform evidence tied to a commit (SPEC-0471 TF06-R7),
// which no build can claim about itself.
const tfPlatformSupport = "not_established"

// tfEvaluatedPolicyFile is where a diff bundle keeps the policy it was judged
// with (SPEC-0469 R5).
const tfEvaluatedPolicyFile = "policy/evaluated-policy.json"

// tfDefaultReportFile is the report file name when --output names a directory
// and --format is json.
const tfDefaultReportFile = "report.json"

// tfReportFormats are the report file formats of `trust-freeze report` and,
// per format, the file name an --output directory gets. One run writes exactly
// one file in exactly one format: a switch that wrote all of them would ask
// the "never overwrite" question three times in one call (FR-0472).
var tfReportFormats = map[string]string{
	"json": tfDefaultReportFile,
	"yaml": "report.yaml",
}

// tfReportFormatNames returns the accepted --format values of report, sorted,
// for the flag help and the rejection message.
func tfReportFormatNames() []string {
	names := make([]string, 0, len(tfReportFormats))
	for name := range tfReportFormats {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// tfMaxReasonFile caps a --reason @file read. The approval itself caps the
// reason far lower; this only bounds the read.
const tfMaxReasonFile = 1 << 20

// tfDeps are the dependencies of the trust-freeze commands. Production uses
// defaultTFDeps; tests inject a fixed clock, a fake host and a temp home.
type tfDeps struct {
	// Clock is the only time source: capture times, approved_at, expiry.
	Clock trustfreeze.Clock
	// Host returns the observed host. Its Clock is replaced by Clock. The
	// same host also names the approving device for `baseline approve`, so
	// both subject ids come from one derivation (HostContext.Subject).
	Host func() probe.HostContext
	// Registry returns the probe registry.
	Registry func() (*probe.Registry, error)
	// HomeRoot resolves the per-user root (homeroot: %USERPROFILE% on
	// Windows, never $HOME there).
	HomeRoot func() (string, error)
	// Version is the skillctl version recorded in capture.json.
	Version string
}

func defaultTFDeps() tfDeps {
	return tfDeps{
		Clock:    trustfreeze.SystemClock{},
		Host:     capture.DefaultHostContext,
		Registry: capture.DefaultRegistry,
		HomeRoot: userHome,
		Version:  version,
	}
}

func (d tfDeps) host() probe.HostContext {
	h := d.Host()
	h.Clock = d.Clock
	return h
}

// runTrustFreeze implements `skillctl trust-freeze`. Ctrl-C and SIGTERM cancel
// the context, which reaches the command runner and its process-group kill,
// so an interrupted capture leaves no tool running.
func runTrustFreeze(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runTrustFreezeWith(ctx, defaultTFDeps(), args, stdout, stderr)
}

// runTrustFreezeWith is the dispatcher with explicit dependencies.
func runTrustFreezeWith(ctx context.Context, d tfDeps, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		tfUsage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "doctor":
		return tfDoctor(ctx, d, args[1:], stdout, stderr)
	case "capture":
		return tfCapture(ctx, d, args[1:], stdout, stderr)
	case "baseline":
		if len(args) < 2 || args[1] != "approve" {
			fmt.Fprintln(stderr, "skillctl trust-freeze baseline: the only subcommand is approve")
			tfUsage(stderr)
			return exitUsage
		}
		return tfApprove(ctx, d, args[2:], stdout, stderr)
	case "verify":
		return tfVerify(ctx, d, args[1:], stdout, stderr)
	case "diff":
		return tfDiff(ctx, d, args[1:], stdout, stderr)
	case "report":
		return tfReport(ctx, d, args[1:], stdout, stderr)
	case "help", "-h", "--help":
		tfUsage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "skillctl trust-freeze: unknown subcommand %q\n\n", args[0])
		tfUsage(stderr)
		return exitUsage
	}
}

func tfUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: skillctl trust-freeze <subcommand> [flags]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Record what a host looks like, approve that record as a signed baseline, and")
	fmt.Fprintln(w, "compare later captures against it. Read-only toward the host; offline.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  doctor            Show what a capture with a profile could collect here, and the")
	fmt.Fprintln(w, "                    per-platform evidence level of every probe. Writes nothing.")
	fmt.Fprintln(w, "  capture           Write a capture bundle (never a baseline).")
	fmt.Fprintln(w, "  baseline approve  Turn a verified capture into a new, signed baseline bundle.")
	fmt.Fprintln(w, "  verify            Check a bundle offline: manifest, digests, approval, signature, trust.")
	fmt.Fprintln(w, "  diff              Verify a baseline and a current bundle, compare them, judge the diff.")
	fmt.Fprintln(w, "  report            Project a capture, baseline or diff bundle onto the JSON report.")
	fmt.Fprintln(w, "  help              Print this text.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Run a subcommand with --help for its flags.")
	fmt.Fprintln(w, "Exit: 0 ok, 1 run failed or threshold exceeded, 2 usage error. JSON output carries")
	fmt.Fprintln(w, "result_class: ok, usage_error, execution_error, verification_failure,")
	fmt.Fprintln(w, "drift_threshold_exceeded, incomplete_capture.")
	fmt.Fprintln(w, "Full platform support is not established; see `skillctl trust-freeze doctor`.")
}

// --- output helpers ----------------------------------------------------------

// tfOut writes the output of one subcommand in text or JSON form.
type tfOut struct {
	name   string
	stdout io.Writer
	stderr io.Writer
	json   bool
}

// tfErrorDoc is the JSON output of a run that produced no result document.
type tfErrorDoc struct {
	ResultClass string `json:"result_class"`
	Command     string `json:"command"`
	Error       string `json:"error"`
}

// emit writes v as canonical, indented JSON.
func (o tfOut) emit(v any) error {
	b, err := trustfreeze.MarshalFile(v)
	if err != nil {
		return err
	}
	_, err = o.stdout.Write(b)
	return err
}

// fail reports an error with its result class and returns code.
func (o tfOut) fail(class string, code int, err error) int {
	if o.json {
		if eerr := o.emit(tfErrorDoc{ResultClass: class, Command: o.name, Error: err.Error()}); eerr != nil {
			fmt.Fprintf(o.stderr, "skillctl trust-freeze %s: cannot encode output: %v\n", o.name, eerr)
		}
	}
	fmt.Fprintf(o.stderr, "skillctl trust-freeze %s: %v\n", o.name, err)
	return code
}

func (o tfOut) usage(err error) int { return o.fail(tfResultUsage, exitUsage, err) }
func (o tfOut) exec(err error) int  { return o.fail(tfResultExecution, exitGeneric, err) }

// result writes a result document (JSON) or runs text, and returns code.
func (o tfOut) result(code int, doc any, text func(io.Writer)) int {
	if o.json {
		if err := o.emit(doc); err != nil {
			fmt.Fprintf(o.stderr, "skillctl trust-freeze %s: cannot encode output: %v\n", o.name, err)
			return exitGeneric
		}
		return code
	}
	text(o.stdout)
	return code
}

// tfFlagSet returns a FlagSet whose errors and usage go to stderr.
func tfFlagSet(name, synopsis string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("trust-freeze "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: skillctl trust-freeze %s\n\n", synopsis)
		fs.PrintDefaults()
	}
	return fs
}

// tfParse parses args. done reports that the caller must return code: 0 for
// --help, 2 for a flag error or a stray positional argument.
func tfParse(fs *flag.FlagSet, args []string) (code int, done bool) {
	code, done, _ = tfParseCause(fs, args)
	return code, done
}

// tfParseCause is tfParse that also returns the cause of a usage error. The
// flag package has already written it, with the usage, to stderr.
func tfParseCause(fs *flag.FlagSet, args []string) (int, bool, error) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK, true, nil
		}
		return exitUsage, true, err
	}
	if fs.NArg() > 0 {
		err := fmt.Errorf("unexpected argument %q", fs.Arg(0))
		fmt.Fprintln(fs.Output(), err)
		fs.Usage()
		return exitUsage, true, err
	}
	return 0, false, nil
}

// tfParseArgs is tfParse for a subcommand. When the command line asks for
// --format json, a usage error found by the flag package (unknown flag,
// malformed value, stray argument) also writes the usage_error document to
// stdout (SPEC-0466 section 5.9): parsing can stop before --format itself is
// read, so the arguments are scanned for it.
func tfParseArgs(fs *flag.FlagSet, name string, args []string, stdout, stderr io.Writer) (int, bool) {
	code, done, err := tfParseCause(fs, args)
	if done && err != nil && tfWantsJSON(args) {
		out := tfOut{name: name, stdout: stdout, stderr: stderr, json: true}
		if eerr := out.emit(tfErrorDoc{ResultClass: tfResultUsage, Command: name, Error: err.Error()}); eerr != nil {
			fmt.Fprintf(stderr, "skillctl trust-freeze %s: cannot encode output: %v\n", name, eerr)
		}
	}
	return code, done
}

// tfParseArgsJSON is tfParseArgs for a subcommand whose status document on
// stdout is always JSON, so a usage error found by the flag package writes the
// usage_error document whatever --format says. report is such a subcommand
// (FR-0472): there --format names the format of the report FILE and says
// nothing about stdout.
func tfParseArgsJSON(fs *flag.FlagSet, name string, args []string, stdout, stderr io.Writer) (int, bool) {
	code, done, err := tfParseCause(fs, args)
	if done && err != nil {
		out := tfOut{name: name, stdout: stdout, stderr: stderr, json: true}
		if eerr := out.emit(tfErrorDoc{ResultClass: tfResultUsage, Command: name, Error: err.Error()}); eerr != nil {
			fmt.Fprintf(stderr, "skillctl trust-freeze %s: cannot encode output: %v\n", name, eerr)
		}
	}
	return code, done
}

// tfWantsJSON reports whether the last --format on the command line (any
// spelling the flag package accepts: -format, --format, with "=" or as two
// arguments) says json. Scanning stops at "--".
func tfWantsJSON(args []string) bool {
	want := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || name != "format" {
			continue
		}
		if !hasValue {
			if i+1 >= len(args) {
				break
			}
			i++
			value = args[i]
		}
		want = value == "json"
	}
	return want
}

// tfFormat checks a --format value: allowed formats are accepted, the
// planned ones answer "not implemented in this version".
func tfFormat(value string, allowed, planned []string) error {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	for _, p := range planned {
		if value == p {
			return fmt.Errorf("--format %s: %s", value, tfNotImplemented)
		}
	}
	return fmt.Errorf("--format %q: want %s", value, strings.Join(append(append([]string{}, allowed...), planned...), ", "))
}

// tfSetFlags returns the names of the flags set on the command line.
func tfSetFlags(fs *flag.FlagSet) map[string]bool {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set
}

// --- doctor ------------------------------------------------------------------

type tfPlatform struct {
	GOOS      string                `json:"goos"`
	GOARCH    string                `json:"goarch"`
	Privilege trustfreeze.Privilege `json:"privilege"`
}

type tfPlannedProbe struct {
	ProbeID    string                  `json:"probe_id"`
	Required   bool                    `json:"required"`
	Registered bool                    `json:"registered"`
	Available  bool                    `json:"available"`
	Status     trustfreeze.ProbeStatus `json:"status,omitempty"`
	Reason     string                  `json:"reason,omitempty"`
	// Tools are the executables the probe named, resolved but never run.
	// Absent when the probe names none (capture.ToolUser).
	Tools []tfToolRow `json:"tools,omitempty"`
}

// tfToolRow is one executable of a probe, resolved with LookPath.
type tfToolRow struct {
	Name string `json:"name"`
	// Status is tfCheckOK or tfToolNotResolved.
	Status string `json:"status"`
	Path   string `json:"path,omitempty"`
	// Class is the runner's error class when the tool did not resolve.
	Class string `json:"class,omitempty"`
}

// tfToolNotResolved is the status of an executable LookPath did not find.
const tfToolNotResolved = "not_resolved"

type tfNotChecked struct {
	Item   string `json:"item"`
	Reason string `json:"reason"`
}

// Statuses of a doctor environment check. A check whose answer doctor could
// not determine stays tfCheckNotChecked and names the reason, instead of
// reporting a result it did not measure.
const (
	tfCheckOK         = "ok"
	tfCheckProblem    = "problem"
	tfCheckNotChecked = "not_checked"
)

// tfDoctorCheck is one environment check of doctor (SPEC-0471 section 11.2).
type tfDoctorCheck struct {
	Item   string `json:"item"`
	Status string `json:"status"`
	// Detail says what was found; set for ok and problem.
	Detail string `json:"detail,omitempty"`
	// Reason is set exactly when Status is not_checked.
	Reason string `json:"reason,omitempty"`
}

type tfDoctorDoc struct {
	ResultClass string                 `json:"result_class"`
	Command     string                 `json:"command"`
	Platform    tfPlatform             `json:"platform"`
	Profile     trustfreeze.ProfileRef `json:"profile"`
	// ExpectedComplete: every required probe passed its support check. A
	// probe that is available can still end partial at capture time.
	ExpectedComplete bool                 `json:"expected_complete"`
	Probes           []tfPlannedProbe     `json:"probes"`
	ExpectedGaps     []string             `json:"expected_gaps"`
	SupportMatrix    []probe.SupportEntry `json:"support_matrix"`
	// PlatformSupport is always "not_established" in this version.
	PlatformSupport string `json:"platform_support"`
	// Checks are the environment checks: the Claude configuration roots, the
	// output location and per-probe tool availability.
	Checks []tfDoctorCheck `json:"checks"`
	// NotChecked repeats every check that could not be determined, so a
	// reader sees the gaps without filtering the checks.
	NotChecked []tfNotChecked `json:"not_checked"`
}

func tfDoctor(ctx context.Context, d tfDeps, args []string, stdout, stderr io.Writer) int {
	fs := tfFlagSet("doctor", "doctor [--profile <name>] [--output <dir>] [--format text|json]", stderr)
	profileName := fs.String("profile", "walking-skeleton", "Built-in profile to plan: "+strings.Join(capture.BuiltinProfileIDs(), ", ")+".")
	output := fs.String("output", "", "Bundle directory a later capture would use (optional). doctor only tests whether it could write there, with one temporary file it removes again; it writes no bundle and creates no directory.")
	format := fs.String("format", "text", "Output format: text or json.")
	if code, done := tfParseArgs(fs, "doctor", args, stdout, stderr); done {
		return code
	}
	out := tfOut{name: "doctor", stdout: stdout, stderr: stderr, json: *format == "json"}
	if err := tfFormat(*format, []string{"text", "json"}, nil); err != nil {
		return out.usage(err)
	}
	prof, err := capture.BuiltinProfile(*profileName)
	if err != nil {
		return out.usage(err)
	}
	reg, err := d.Registry()
	if err != nil {
		return out.exec(err)
	}
	host := d.host()
	doc := tfDoctorDoc{
		ResultClass:      tfResultOK,
		Command:          "doctor",
		Platform:         tfPlatform{GOOS: host.GOOS, GOARCH: host.GOARCH, Privilege: host.Privilege},
		Profile:          prof.Ref(),
		ExpectedComplete: true,
		Probes:           []tfPlannedProbe{},
		ExpectedGaps:     []string{},
		SupportMatrix:    probe.SupportMatrix(reg, prof.ProbeIDs()),
		PlatformSupport:  tfPlatformSupport,
		NotChecked:       []tfNotChecked{},
	}
	if doc.SupportMatrix == nil {
		doc.SupportMatrix = []probe.SupportEntry{}
	}
	planned := capture.Plan(ctx, prof, reg, host)
	for _, pp := range planned {
		row := tfPlannedProbe{
			ProbeID:    pp.ProbeID,
			Required:   pp.Required,
			Registered: pp.Registered,
			Available:  pp.Support.Available,
			Status:     pp.Support.Status,
			Reason:     pp.Support.Reason,
		}
		if !row.Status.Valid() {
			row.Status = ""
		}
		for _, t := range pp.Tools {
			tr := tfToolRow{Name: t.Name, Status: tfCheckOK, Path: t.Path}
			if !t.OK() {
				tr.Status, tr.Class = tfToolNotResolved, t.Class
			}
			row.Tools = append(row.Tools, tr)
		}
		doc.Probes = append(doc.Probes, row)
		if pp.Required && !pp.Support.Available {
			doc.ExpectedComplete = false
			doc.ExpectedGaps = append(doc.ExpectedGaps, pp.ProbeID)
		}
	}
	// The environment checks. doctor reports them, it does not judge: a
	// problem is machine-readable in `checks` and does not change the exit
	// code, exactly as an expected gap does not.
	home, homeErr := d.HomeRoot()
	doc.Checks = []tfDoctorCheck{
		tfCheckClaudeRoots(home, homeErr),
		tfCheckFileRoots(host.GOOS),
		tfCheckOutputLocation(*output),
		tfCheckProbeTools(planned),
	}
	for _, c := range doc.Checks {
		if c.Status == tfCheckNotChecked {
			doc.NotChecked = append(doc.NotChecked, tfNotChecked{Item: c.Item, Reason: c.Reason})
		}
	}
	return out.result(exitOK, doc, func(w io.Writer) {
		fmt.Fprintf(w, "platform: %s/%s, privilege %s\n", doc.Platform.GOOS, doc.Platform.GOARCH, doc.Platform.Privilege)
		fmt.Fprintf(w, "profile: %s v%s (%s)\n", doc.Profile.ID, doc.Profile.Version, doc.Profile.Digest)
		for _, p := range doc.Probes {
			req := "optional"
			if p.Required {
				req = "required"
			}
			state := "available"
			if !p.Available {
				state = string(p.Status)
				if p.Reason != "" {
					state += " (" + p.Reason + ")"
				}
			}
			fmt.Fprintf(w, "  %-32s %-8s %s\n", p.ProbeID, req, state)
		}
		if doc.ExpectedComplete {
			fmt.Fprintln(w, "expected: complete (every required probe is available; a probe can still end partial)")
		} else {
			fmt.Fprintf(w, "expected: incomplete, gaps in %s\n", strings.Join(doc.ExpectedGaps, ", "))
		}
		fmt.Fprintln(w, "evidence level per probe and platform (this build):")
		for _, e := range doc.SupportMatrix {
			ev := "none"
			if len(e.Evidence) > 0 {
				parts := make([]string, 0, len(e.Evidence))
				for _, l := range e.Evidence {
					parts = append(parts, string(l))
				}
				ev = strings.Join(parts, ", ")
			}
			fmt.Fprintf(w, "  %-32s %-8s %-16s %s\n", e.ProbeID, e.Platform, e.State, ev)
		}
		fmt.Fprintln(w, "full platform support is not established: real-platform evidence is recorded")
		fmt.Fprintln(w, "per commit outside the build, never claimed by it.")
		for _, c := range doc.Checks {
			if c.Status == tfCheckNotChecked {
				fmt.Fprintf(w, "not checked: %s (%s)\n", c.Item, c.Reason)
				continue
			}
			fmt.Fprintf(w, "check %s: %s (%s)\n", c.Item, c.Status, c.Detail)
		}
	})
}

// --- doctor checks -----------------------------------------------------------

// tfClaudeRoots are the per-user Claude configuration paths skillctl uses,
// relative to the home root.
var tfClaudeRoots = []string{
	".claude",
	".claude/agents",
	".claude/commands",
	".claude/skills",
	".claude/skillctl",
	".claude/trust-roots.yaml",
}

// tfCheckClaudeRoots resolves the Claude configuration roots below home. The
// home root is the CLI's HomeRoot dependency, which is pkg/skillctl/homeroot
// in production, so doctor names the same root every other skillctl path
// resolves to. Each entry is only Lstat'ed: no file is opened, no link is
// followed and nothing is created. An entry that exists as a symlink, or that
// cannot be read, is a problem, because a per-user trust path that points
// somewhere else is worth seeing before a capture, not after it.
func tfCheckClaudeRoots(home string, homeErr error) tfDoctorCheck {
	c := tfDoctorCheck{Item: "claude_roots"}
	if homeErr != nil {
		c.Status = tfCheckNotChecked
		c.Reason = "the home root did not resolve: " + homeErr.Error()
		return c
	}
	var present, absent, problems []string
	for _, rel := range tfClaudeRoots {
		fi, err := os.Lstat(filepath.Join(home, filepath.FromSlash(rel)))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			absent = append(absent, rel)
		case errors.Is(err, fs.ErrPermission):
			problems = append(problems, rel+" (permission_denied)")
		case err != nil:
			problems = append(problems, rel+" (unreadable)")
		case fi.Mode()&os.ModeSymlink != 0:
			problems = append(problems, rel+" (symlink)")
		case fi.IsDir() || fi.Mode().IsRegular():
			present = append(present, rel)
		default:
			problems = append(problems, rel+" ("+fi.Mode().Type().String()+")")
		}
	}
	c.Status = tfCheckOK
	c.Detail = "root " + home + "; present: " + tfJoinOrNone(present) + "; absent: " + tfJoinOrNone(absent)
	if len(problems) > 0 {
		c.Status = tfCheckProblem
		c.Detail += "; problem: " + strings.Join(problems, ", ")
	}
	return c
}

// tfDoctorProbePattern names the temporary file the output check creates.
const tfDoctorProbePattern = ".skillctl-trust-freeze-doctor-*"

// tfCheckOutputLocation reports whether a capture could write at target,
// without writing a bundle and without creating the target.
//
// What it does, exactly: it picks the directory a capture would work in (the
// target itself when that already is a directory, otherwise its immediate
// parent, because capture creates the target inside it), creates ONE
// temporary file there with os.CreateTemp, closes it and removes it again.
// It never walks further up: a target whose parent does not exist is a
// problem, not a licence to write two levels above what the operator named
// (O-T1). capture requires the parent to exist as well, so the answer is the
// same one a capture would give.
// Access bits are not read instead: they answer for a user's identity, not
// for this process, and a read-only mount, an ACL, a container user mapping
// or Windows each make them disagree with what a write would do. The attempt
// is the only honest answer, and it leaves the directory as it found it.
func tfCheckOutputLocation(target string) tfDoctorCheck {
	c := tfDoctorCheck{Item: "output_location"}
	if strings.TrimSpace(target) == "" {
		c.Status = tfCheckNotChecked
		c.Reason = "no --output given: doctor tests a location only when one is named"
		return c
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		c.Status, c.Detail = tfCheckProblem, "cannot resolve "+target+": "+err.Error()
		return c
	}
	dir, state, err := tfWritableDir(abs)
	if err != nil {
		c.Status, c.Detail = tfCheckProblem, err.Error()
		return c
	}
	if err := tfProbeWritable(dir); err != nil {
		c.Status, c.Detail = tfCheckProblem, state+"; not writable: "+err.Error()
		return c
	}
	c.Status = tfCheckOK
	c.Detail = state + "; that directory is writable (one temporary file created and removed, no bundle written)"
	return c
}

// tfWritableDir returns the directory to test for abs and a description of
// what abs is today.
func tfWritableDir(abs string) (dir, state string, err error) {
	fi, statErr := os.Lstat(abs)
	switch {
	case statErr == nil && fi.IsDir():
		entries, rdErr := os.ReadDir(abs)
		if rdErr != nil {
			return "", "", fmt.Errorf("%s exists but cannot be read: %w", abs, rdErr)
		}
		if len(entries) == 0 {
			return abs, abs + " exists and is empty", nil
		}
		return abs, fmt.Sprintf("%s exists and holds %d entries, so capture needs --force and takes it only for a capture bundle", abs, len(entries)), nil
	case statErr == nil && fi.Mode().IsRegular():
		return "", "", fmt.Errorf("%s exists and is a file, not a directory", abs)
	case statErr == nil && fi.Mode()&os.ModeSymlink != 0:
		// A bundle is verified without following links, so a symlinked target
		// could never verify afterwards.
		return "", "", fmt.Errorf("%s exists and is a symlink; a bundle directory must be a real directory", abs)
	case statErr == nil:
		return "", "", fmt.Errorf("%s exists and is not a directory (%s)", abs, fi.Mode().Type())
	case !errors.Is(statErr, fs.ErrNotExist):
		return "", "", fmt.Errorf("%s cannot be read: %w", abs, statErr)
	}
	// The target does not exist. capture creates it inside its parent, and
	// creates no ancestor, so the parent is the only directory this check may
	// touch.
	parent := filepath.Dir(abs)
	pfi, err := os.Lstat(parent)
	switch {
	case err == nil && pfi.IsDir():
		return parent, abs + " does not exist yet; capture would create it in its parent " + parent, nil
	case err == nil:
		return "", "", fmt.Errorf("%s is not a directory", parent)
	case errors.Is(err, fs.ErrNotExist):
		return "", "", fmt.Errorf("%s does not exist, and neither does its parent %s; capture creates the target but no directory above it, so nothing was touched", abs, parent)
	}
	return "", "", fmt.Errorf("%s cannot be read: %w", parent, err)
}

// tfProbeWritable creates one temporary file in dir and removes it again.
func tfProbeWritable(dir string) error {
	f, err := os.CreateTemp(dir, tfDoctorProbePattern)
	if err != nil {
		return err
	}
	return errors.Join(f.Close(), os.Remove(f.Name()))
}

// tfCheckProbeTools reports per-probe tool availability. capture.Plan
// resolved every executable a probe named through the runner's LookPath and
// ran none of them. A probe that names no executable cannot be checked this
// way; when no probe of the profile names one, the whole check stays
// not_checked with that reason.
func tfCheckProbeTools(planned []capture.PlannedProbe) tfDoctorCheck {
	c := tfDoctorCheck{Item: "tools"}
	var resolved, missing []string
	declaring, silent := 0, 0
	for _, pp := range planned {
		if !pp.ToolsDeclared {
			silent++
			continue
		}
		declaring++
		for _, t := range pp.Tools {
			if t.OK() {
				resolved = append(resolved, pp.ProbeID+":"+t.Name)
				continue
			}
			missing = append(missing, pp.ProbeID+":"+t.Name+" ("+t.Class+")")
		}
	}
	if declaring == 0 {
		c.Status = tfCheckNotChecked
		c.Reason = fmt.Sprintf("none of the %d probe(s) of this profile names the executables it uses; the tools of a run are recorded per probe in probes/<probe-id>.json", silent)
		return c
	}
	c.Status = tfCheckOK
	c.Detail = fmt.Sprintf("%d of %d probe(s) name their executables; resolved: %s", declaring, declaring+silent, tfJoinOrNone(resolved))
	if len(missing) > 0 {
		c.Status = tfCheckProblem
		c.Detail += "; not resolved: " + strings.Join(missing, ", ")
	}
	if silent > 0 {
		c.Detail += fmt.Sprintf("; %d probe(s) name none, so their tools were not checked", silent)
	}
	return c
}

// tfCheckFileRoots reports every file root a capture on this platform may open,
// in one place, and it reads nothing at all.
//
// Two lists, because the code has two (review of T-03b, finding 3). The engine's
// restricted reader refuses any path outside DefaultAllowedRoots, and
// linux.executables hashes program files through its own reader with its own
// roots, which that list does not contain. An operator who has to answer "what
// can this thing open" was previously left to find the second list in the
// manual; doctor now prints both, and says which reader each belongs to.
func tfCheckFileRoots(goos string) tfDoctorCheck {
	c := tfDoctorCheck{Item: "file_roots"}
	reader := capture.DefaultAllowedRoots(goos)
	own := capture.ProbeOwnedRoots(goos)
	if len(reader) == 0 && len(own) == 0 {
		c.Status = tfCheckNotChecked
		c.Reason = "no registered probe reads a file on " + goos
		return c
	}
	c.Status = tfCheckOK
	c.Detail = fmt.Sprintf("restricted reader: %s; hashed through the probe's own reader (linux.executables): %s",
		tfJoinOrNone(reader), tfJoinOrNone(own))
	return c
}

// tfJoinOrNone joins a list, or says "none" for an empty one.
func tfJoinOrNone(list []string) string {
	if len(list) == 0 {
		return "none"
	}
	return strings.Join(list, ", ")
}

// --- capture -----------------------------------------------------------------

type tfCaptureDoc struct {
	ResultClass   string                 `json:"result_class"`
	Command       string                 `json:"command"`
	Kind          trustfreeze.Kind       `json:"kind"`
	BundleID      string                 `json:"bundle_id"`
	ContentDigest string                 `json:"content_digest"`
	Subject       trustfreeze.Subject    `json:"subject"`
	Profile       trustfreeze.ProfileRef `json:"profile"`
	// Actor is the --actor id, absent when the capture named none.
	Actor        string                     `json:"actor,omitempty"`
	Completeness trustfreeze.Completeness   `json:"completeness"`
	Probes       []trustfreeze.ProbeSummary `json:"probes"`
	// Capabilities reports the capability resolution of this capture; absent
	// when this build has no resolver for the platform, so a missing field
	// says that nobody looked (SPEC-0466 section 5.7).
	Capabilities *tfCapabilities `json:"capabilities,omitempty"`
}

// tfCapabilities is the capability resolution summary of a capture. Critical
// names the capabilities whose privilege is root on this host
// (trustfreeze.RootPrivileges), sorted, so a reader of the capture learns who
// holds the host without opening state/capabilities.json (R-T3). It is a
// projection of the resolved list, not a judgement: severities belong to a
// policy, and a policy judges a diff, not a capture.
type tfCapabilities struct {
	Resolver    string   `json:"resolver"`
	Resolved    int      `json:"resolved"`
	Diagnostics int      `json:"diagnostics"`
	Critical    []string `json:"critical"`
}

// tfCriticalCapabilities returns the ids of the capabilities that grant root,
// sorted, and the privilege of each.
func tfCriticalCapabilities(doc *trustfreeze.CapabilitiesDoc) ([]string, map[string]string) {
	ids := []string{}
	priv := map[string]string{}
	for _, c := range doc.Capabilities {
		if trustfreeze.IsRootPrivilege(c.Privilege) {
			ids = append(ids, c.ID)
			priv[c.ID] = c.Privilege
		}
	}
	sort.Strings(ids)
	return ids, priv
}

// tfCapture writes a capture bundle. It never approves and never signs: this
// function must not reach the seal package (TestTrustFreezeCaptureNeverApproves).
func tfCapture(ctx context.Context, d tfDeps, args []string, stdout, stderr io.Writer) int {
	fs := tfFlagSet("capture", "capture --profile <name> --output <dir> [--actor <id>] [--force] [--probe <id>]... [--exclude-probe <id>]... [--timeout <d>] [--format text|json]", stderr)
	profileName := fs.String("profile", "", "Built-in profile to capture with (required): "+strings.Join(capture.BuiltinProfileIDs(), ", ")+".")
	output := fs.String("output", "", "New bundle directory (required). Must not exist or be empty.")
	actor := fs.String("actor", "", "Stable id of the person or automation running this capture (optional). It is recorded as capture.actor and carried into the signed approval, where it is the reviewer's counterpart in the self-approval check. Same character set as --reviewer.")
	force := fs.Bool("force", false, "Replace an existing capture bundle at --output (only a capture bundle that verifies, so no other file is ever removed; never a baseline, the home root or a volume root).")
	var projects, probes, excludes multiFlag
	fs.Var(&projects, "project", "Project root to inventory (repeatable). "+tfNotImplemented+".")
	policyFile := fs.String("policy", "", "Policy file to record with the capture. "+tfNotImplemented+".")
	fs.Var(&probes, "probe", "Run only this probe of the profile (repeatable).")
	fs.Var(&excludes, "exclude-probe", "Skip this probe of the profile (repeatable). It is recorded as unsupported (excluded_by_operator): a skipped required probe makes the capture incomplete, and diff reports every skipped probe as a collection gap.")
	timeout := fs.Duration("timeout", 0, "Timeout per probe run, e.g. 30s (default: the probe's own).")
	format := fs.String("format", "text", "Output format: text or json.")
	if code, done := tfParseArgs(fs, "capture", args, stdout, stderr); done {
		return code
	}
	out := tfOut{name: "capture", stdout: stdout, stderr: stderr, json: *format == "json"}
	if err := tfFormat(*format, []string{"text", "json"}, nil); err != nil {
		return out.usage(err)
	}
	set := tfSetFlags(fs)
	switch {
	case set["project"]:
		return out.usage(fmt.Errorf("--project: %s", tfNotImplemented))
	case set["policy"] || *policyFile != "":
		return out.usage(fmt.Errorf("--policy: %s", tfNotImplemented))
	case *profileName == "":
		return out.usage(errors.New("--profile is required"))
	case *output == "":
		return out.usage(errors.New("--output is required"))
	case *timeout < 0:
		return out.usage(errors.New("--timeout must not be negative"))
	}
	// The actor enters the signed approval (identities.capture_actor), which
	// accepts only this character set, so it is refused here, before anything
	// is written (SPEC-0470 section 4.2). Empty stays allowed: a capture
	// without a named actor keeps no actor at all.
	actorID := strings.TrimSpace(*actor)
	if actorID != "" {
		if err := trustfreeze.ValidateIdentifier(actorID); err != nil {
			return out.usage(fmt.Errorf("--actor: %w", err))
		}
	}
	prof, err := capture.BuiltinProfile(*profileName)
	if err != nil {
		return out.usage(err)
	}
	home, err := d.HomeRoot()
	if err != nil {
		return out.exec(fmt.Errorf("cannot resolve the home root: %w", err))
	}
	red, err := capture.DefaultRedactor(home)
	if err != nil {
		return out.exec(err)
	}
	reg, err := d.Registry()
	if err != nil {
		return out.exec(err)
	}
	res, err := capture.Run(ctx, capture.Options{
		Profile:       prof,
		Registry:      reg,
		Host:          d.host(),
		Redactor:      red,
		Output:        *output,
		Force:         *force,
		HomeRoot:      home,
		ToolVersion:   d.Version,
		Actor:         actorID,
		Probes:        probes,
		ExcludeProbes: excludes,
		ProbeTimeout:  *timeout,
	})
	if err != nil {
		if errors.Is(err, capture.ErrUnknownProbe) || errors.Is(err, capture.ErrUnknownProfile) ||
			errors.Is(err, capture.ErrInvalidProfile) || errors.Is(err, capture.ErrInvalidOptions) {
			return out.usage(err)
		}
		return out.exec(err)
	}
	doc := tfCaptureDoc{
		ResultClass:   tfResultOK,
		Command:       "capture",
		Kind:          res.Manifest.Kind,
		BundleID:      res.Manifest.BundleID,
		ContentDigest: res.Manifest.ContentDigest,
		Subject:       res.Manifest.Subject,
		Profile:       res.Capture.Capture.Profile,
		Actor:         res.Capture.Capture.Actor,
		Completeness:  res.Capture.Completeness,
		Probes:        res.Capture.Probes,
	}
	criticalPrivilege := map[string]string{}
	if c := res.Capabilities; c != nil {
		var critical []string
		critical, criticalPrivilege = tfCriticalCapabilities(c)
		doc.Capabilities = &tfCapabilities{
			Resolver: c.Resolver, Resolved: len(c.Capabilities),
			Diagnostics: len(c.Diagnostics), Critical: critical,
		}
	}
	code := exitOK
	if !res.Complete() {
		doc.ResultClass, code = tfResultIncomplete, exitGeneric
	}
	return out.result(code, doc, func(w io.Writer) {
		fmt.Fprintf(w, "capture bundle written: %s\n", res.Dir)
		fmt.Fprintf(w, "bundle_id: %s\n", doc.BundleID)
		fmt.Fprintf(w, "content_digest: %s\n", doc.ContentDigest)
		fmt.Fprintf(w, "profile: %s v%s (%s)\n", doc.Profile.ID, doc.Profile.Version, doc.Profile.Digest)
		if doc.Actor != "" {
			fmt.Fprintf(w, "actor: %s\n", doc.Actor)
		}
		if c := doc.Capabilities; c != nil {
			fmt.Fprintf(w, "capabilities: %d resolved by %s, %d diagnostic(s), %d that grant root\n",
				c.Resolved, c.Resolver, c.Diagnostics, len(c.Critical))
			for _, id := range c.Critical {
				fmt.Fprintf(w, "  root %-48s %s\n", id, criticalPrivilege[id])
			}
		} else {
			fmt.Fprintln(w, "capabilities: not resolved (this build has no resolver for this platform)")
		}
		for _, p := range doc.Probes {
			line := fmt.Sprintf("  %-32s %s", p.ProbeID, p.Status)
			if p.Reason != "" {
				line += " (" + p.Reason + ")"
			}
			fmt.Fprintln(w, line)
		}
		if code == exitOK {
			fmt.Fprintln(w, "completeness: complete")
		} else {
			fmt.Fprintf(w, "completeness: incomplete, %d gap(s)\n", len(doc.Completeness.Gaps))
			for _, g := range doc.Completeness.Gaps {
				fmt.Fprintf(w, "  gap %s: %s\n", g.ProbeID, g.Reason)
			}
		}
		fmt.Fprintln(w, "this is a capture, not a baseline: approve it with `skillctl trust-freeze baseline approve`")
	})
}

// --- baseline approve --------------------------------------------------------

type tfApproveDoc struct {
	ResultClass string           `json:"result_class"`
	Command     string           `json:"command"`
	Kind        trustfreeze.Kind `json:"kind"`
	*seal.SealResult
}

func tfApprove(ctx context.Context, d tfDeps, args []string, stdout, stderr io.Writer) int {
	fs := tfFlagSet("baseline approve", "baseline approve --capture <dir> --output <dir> --reviewer <id> --change-id <id> --reason <text|@file> --key <file> [--expires-at <rfc3339>] [--self-approval allow|warn|block] [--format text|json]", stderr)
	captureDir := fs.String("capture", "", "Capture bundle to approve (required). It is only read.")
	output := fs.String("output", "", "New baseline directory (required). Must not exist or be empty; a baseline is never overwritten.")
	reviewer := fs.String("reviewer", "", "Reviewer identity (required).")
	changeID := fs.String("change-id", "", "Change or ticket id this approval belongs to (required).")
	reason := fs.String("reason", "", "Why this state is accepted (required). @<file> reads the text from a file; CRLF becomes LF.")
	keyFile := fs.String("key", "", "ed25519 private key file, PEM PKCS#8, mode 0600 (required), e.g. from `skillctl keygen`.")
	expiresAt := fs.String("expires-at", "", "Optional expiry, RFC 3339 (any offset, stored in UTC). The baseline is valid through this instant.")
	selfApproval := fs.String("self-approval", string(seal.SelfApprovalWarn), "What a self-approval (same device or same person) does: allow, warn or block.")
	format := fs.String("format", "text", "Output format: text or json.")
	if code, done := tfParseArgs(fs, "baseline approve", args, stdout, stderr); done {
		return code
	}
	out := tfOut{name: "baseline approve", stdout: stdout, stderr: stderr, json: *format == "json"}
	if err := tfFormat(*format, []string{"text", "json"}, nil); err != nil {
		return out.usage(err)
	}
	switch {
	case *captureDir == "":
		return out.usage(errors.New("--capture is required"))
	case *output == "":
		return out.usage(errors.New("--output is required"))
	case *keyFile == "":
		return out.usage(errors.New("--key is required"))
	}
	mode, err := seal.ParseSelfApprovalMode(*selfApproval)
	if err != nil {
		return out.usage(fmt.Errorf("--self-approval: %w", err))
	}
	// The signing key never becomes approval text (TF05-R8): a --reason file
	// that is the --key file is refused before it is read. Any other text
	// that looks like secret material is refused by the approval check.
	if path, isFile := strings.CutPrefix(*reason, "@"); isFile && path != "" {
		if tfSameFile(path, *keyFile) {
			return out.usage(errors.New("--reason @<file> names the --key file; the private key must never become approval text"))
		}
	}
	reasonText, err := tfReasonText(*reason)
	if err != nil {
		return out.usage(err)
	}
	in := seal.ApprovalInput{Reviewer: *reviewer, ChangeID: *changeID, Reason: reasonText}
	if *expiresAt != "" {
		t, err := time.Parse(time.RFC3339Nano, *expiresAt)
		if err != nil {
			return out.usage(fmt.Errorf("--expires-at: want RFC 3339, e.g. 2026-12-31T23:59:59Z: %w", err))
		}
		in.ExpiresAt = t.UTC()
	}
	// The mandatory approval fields fail here, before the capture or the key
	// is read and long before anything is signed (SPEC-0470 TF05-AC5).
	if err := in.Check(); err != nil {
		return out.usage(err)
	}
	// The approving device, derived exactly as the captured subject is.
	if subj, _, err := d.host().Subject(); err == nil {
		in.ApproverSubjectID = subj.ID
	} else if mode == seal.SelfApprovalBlock {
		return out.exec(fmt.Errorf("self-approval mode block needs the approving device, which is unknown: %w", err))
	} else {
		fmt.Fprintf(stderr, "skillctl trust-freeze baseline approve: warning: approving device unknown, same-device check skipped: %v\n", err)
	}
	home, err := d.HomeRoot()
	if err != nil {
		return out.exec(fmt.Errorf("cannot resolve the home root: %w", err))
	}
	// A flag-named input file that fails to load is a usage error (SPEC-0466
	// section 5.9), like --trusted-key, --trust-policy, --policy and --reason.
	signer, err := seal.NewFileSigner(*keyFile)
	if err != nil {
		return out.usage(fmt.Errorf("--key: %w", err))
	}
	defer signer.Close()
	res, err := seal.Seal(ctx, seal.SealRequest{
		CaptureDir:   *captureDir,
		OutputDir:    *output,
		Approval:     in,
		Signer:       signer,
		Clock:        d.Clock,
		SelfApproval: mode,
		HomeRoot:     home,
	})
	if err != nil {
		switch {
		case errors.Is(err, seal.ErrApprovalInvalid):
			return out.usage(err)
		// A capture that fails any of its checks (integrity, wrong kind,
		// invalid or inconsistent documents) is a verification_failure, as
		// verify calls it (SPEC-0470 section 4.1 step 1).
		case errors.Is(err, trustfreeze.ErrIntegrity), errors.Is(err, seal.ErrNotCapture), errors.Is(err, seal.ErrSelfApprovalBlocked):
			return out.fail(tfResultVerification, exitGeneric, err)
		}
		return out.exec(err)
	}
	doc := tfApproveDoc{ResultClass: tfResultOK, Command: "baseline approve", Kind: res.Manifest.Kind, SealResult: res}
	return out.result(exitOK, doc, func(w io.Writer) {
		fmt.Fprintf(w, "baseline bundle written: %s\n", res.OutputDir)
		fmt.Fprintf(w, "bundle_id: %s\n", res.BundleID)
		fmt.Fprintf(w, "content_digest: %s\n", res.ContentDigest)
		fmt.Fprintf(w, "capture_digest: %s\n", res.CaptureDigest)
		fmt.Fprintf(w, "key_id: %s\n", res.KeyID)
		fmt.Fprintf(w, "approved_at: %s by %s (change %s)\n", res.Approval.ApprovedAt, res.Approval.Reviewer, res.Approval.ChangeID)
		if res.Approval.ExpiresAt != "" {
			fmt.Fprintf(w, "expires_at: %s\n", res.Approval.ExpiresAt)
		}
		for _, wn := range res.Warnings {
			fmt.Fprintf(w, "warning: %s: %s\n", wn.Code, wn.Message)
		}
	})
}

// tfSameFile reports whether a and b name the same existing file, however
// each is spelled (symlink, relative path, hard link).
func tfSameFile(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	return err == nil && os.SameFile(ai, bi)
}

// tfReasonText returns the --reason text, reading @file references. The text
// is passed on verbatim; the approval normalizes line endings.
func tfReasonText(v string) (string, error) {
	path, isFile := strings.CutPrefix(v, "@")
	if !isFile {
		return v, nil
	}
	if path == "" {
		return "", errors.New("--reason @<file>: empty file name")
	}
	// #nosec G304 -- `--reason @<datei>` bedeutet genau das: der Bediener
	// nennt die Datei, deren Text in die Freigabe gehoert. Der Inhalt wird
	// begrenzt gelesen und vor dem Signieren auf Secrets geprueft.
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("--reason: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, tfMaxReasonFile+1))
	if err != nil {
		return "", fmt.Errorf("--reason: %w", err)
	}
	if len(b) > tfMaxReasonFile {
		return "", fmt.Errorf("--reason: %s is larger than %d bytes", path, tfMaxReasonFile)
	}
	return string(b), nil
}

// --- verify ------------------------------------------------------------------

// Verification scopes: a baseline is checked completely; captures and diffs
// carry no signature, so their check is integrity plus document validity.
const (
	tfScopeBaseline  = "baseline"
	tfScopeIntegrity = "integrity"
)

// tfReasonDiffInvalid is the CLI-level failure reason of a diff bundle whose
// diff.json or verdict.json does not parse or does not match.
const tfReasonDiffInvalid seal.Reason = "diff_invalid"

type tfVerifyDoc struct {
	ResultClass string `json:"result_class"`
	Command     string `json:"command"`
	// Input names the checked input of diff ("baseline" or "current"); empty
	// for verify.
	Input string `json:"input,omitempty"`
	Scope string `json:"scope"`
	seal.VerificationResult
}

// tfTrustPolicy builds the trust policy from --trust-policy and the
// --trusted-key files, with the injected clock for expiry.
func tfTrustPolicy(d tfDeps, policyFile string, keyFiles []string) (seal.TrustPolicy, error) {
	p := seal.DefaultTrustPolicy()
	if policyFile != "" {
		var err error
		if p, err = seal.LoadTrustPolicy(policyFile); err != nil {
			return seal.TrustPolicy{}, fmt.Errorf("--trust-policy: %w", err)
		}
	}
	for _, kf := range keyFiles {
		k, err := seal.LoadTrustedKeyPEM(kf)
		if err != nil {
			return seal.TrustPolicy{}, fmt.Errorf("--trusted-key %s: %w", kf, err)
		}
		if !p.Trusts(k.PublicKey) {
			p.TrustedKeys = append(p.TrustedKeys, k)
		}
	}
	p.Now = d.Clock
	return p, nil
}

// tfVerifyBundle checks one bundle offline. A baseline (or a bundle whose
// manifest cannot be read, so its kind is unknown) goes through seal.Verify;
// a capture or diff through the core integrity check plus a strict parse of
// its documents. allowed limits the kinds; another kind fails as wrong_kind.
func tfVerifyBundle(ctx context.Context, dir string, tp seal.TrustPolicy, allowed ...trustfreeze.Kind) tfVerifyDoc {
	doc := tfVerifyDoc{Command: "verify"}
	ir := trustfreeze.VerifyDir(dir)
	var kind trustfreeze.Kind
	if ir.Manifest != nil {
		kind = ir.Manifest.Kind
	}
	if kind == "" || kind == trustfreeze.KindBaseline {
		doc.Scope = tfScopeBaseline
		doc.VerificationResult = seal.Verify(ctx, dir, tp)
	} else {
		doc.Scope = tfScopeIntegrity
		doc.VerificationResult = tfVerifyUnsigned(ctx, dir, ir)
	}
	if kind != "" && len(allowed) > 0 {
		ok := false
		for _, k := range allowed {
			ok = ok || k == kind
		}
		if !ok {
			doc.Failures = append(doc.Failures, seal.Failure{Reason: seal.ReasonWrongKind, Path: trustfreeze.ManifestFile, Detail: fmt.Sprintf("bundle kind is %q", kind)})
			doc.OK = false
		}
	}
	doc.ResultClass = tfResultOK
	if !doc.OK {
		doc.ResultClass = tfResultVerification
	}
	return doc
}

// tfVerifyUnsigned checks a capture or diff bundle: integrity, then the
// documents the kind requires.
func tfVerifyUnsigned(ctx context.Context, dir string, ir trustfreeze.IntegrityResult) seal.VerificationResult {
	r := seal.VerificationResult{Integrity: ir, Failures: []seal.Failure{}, Warnings: []seal.Warning{}}
	if m := ir.Manifest; m != nil {
		r.Kind, r.BundleID, r.ContentDigest = m.Kind, m.BundleID, m.ContentDigest
	}
	for _, f := range ir.Failures {
		r.Failures = append(r.Failures, seal.Failure{Reason: seal.ReasonIntegrity, IntegrityReason: f.Reason, Path: f.Path, Detail: f.Detail})
	}
	if err := ctx.Err(); err != nil {
		r.Failures = append(r.Failures, seal.Failure{Reason: seal.ReasonCanceled, Detail: err.Error()})
	}
	if len(r.Failures) == 0 {
		b, err := trustfreeze.ReadBundle(dir)
		switch {
		case err != nil:
			r.Failures = append(r.Failures, seal.Failure{Reason: seal.ReasonCaptureInvalid, Detail: err.Error()})
		case b.Manifest.ContentDigest != r.ContentDigest:
			r.Failures = append(r.Failures, seal.Failure{Reason: seal.ReasonIntegrity, Path: trustfreeze.ManifestFile, Detail: "the bundle changed during verification"})
		case b.Manifest.Kind == trustfreeze.KindDiff:
			if _, err := report.FromBundle(b); err != nil {
				r.Failures = append(r.Failures, seal.Failure{Reason: tfReasonDiffInvalid, Path: compare.DiffFile, Detail: err.Error()})
			}
		}
	}
	r.OK = len(r.Failures) == 0
	return r
}

func tfVerify(ctx context.Context, d tfDeps, args []string, stdout, stderr io.Writer) int {
	fs := tfFlagSet("verify", "verify --bundle <dir> [--trust-policy <file>] [--trusted-key <public.pem>]... [--format text|json]", stderr)
	bundle := fs.String("bundle", "", "Bundle directory to verify (required): a baseline, capture or diff.")
	trustPolicy := fs.String("trust-policy", "", "Trust policy file (JSON or YAML, schema trust-freeze/trust-policy/v1).")
	var trustedKeys multiFlag
	fs.Var(&trustedKeys, "trusted-key", "ed25519 public key file (PEM SPKI, e.g. a `skillctl keygen` .pub) to trust (repeatable).")
	format := fs.String("format", "text", "Output format: text or json.")
	if code, done := tfParseArgs(fs, "verify", args, stdout, stderr); done {
		return code
	}
	out := tfOut{name: "verify", stdout: stdout, stderr: stderr, json: *format == "json"}
	if err := tfFormat(*format, []string{"text", "json"}, nil); err != nil {
		return out.usage(err)
	}
	if *bundle == "" {
		return out.usage(errors.New("--bundle is required"))
	}
	tp, err := tfTrustPolicy(d, *trustPolicy, trustedKeys)
	if err != nil {
		return out.usage(err)
	}
	doc := tfVerifyBundle(ctx, *bundle, tp)
	code := exitOK
	if !doc.OK {
		code = exitGeneric
	}
	return out.result(code, doc, func(w io.Writer) { tfPrintVerify(w, doc) })
}

func tfPrintVerify(w io.Writer, doc tfVerifyDoc) {
	verdict := "PASS"
	if !doc.OK {
		verdict = "FAIL"
	}
	kind := string(doc.Kind)
	if kind == "" {
		kind = "bundle"
	}
	label := ""
	if doc.Input != "" {
		label = "diff input " + doc.Input + ": "
	}
	fmt.Fprintf(w, "%s %s%s %s (scope %s)\n", verdict, label, kind, doc.BundleID, doc.Scope)
	if doc.ContentDigest != "" {
		fmt.Fprintf(w, "  content_digest: %s\n", doc.ContentDigest)
	}
	if doc.Scope == tfScopeBaseline && doc.SignatureChecked {
		sig := "valid"
		if !doc.SignatureValid {
			sig = "INVALID"
		}
		trust := "trusted"
		if !doc.KeyTrusted {
			trust = "NOT trusted"
		}
		fmt.Fprintf(w, "  capture_digest: %s\n", doc.CaptureDigest)
		fmt.Fprintf(w, "  signature: %s, key %s %s\n", sig, doc.KeyID, trust)
	}
	if doc.Scope == tfScopeIntegrity {
		fmt.Fprintln(w, "  captures and diffs carry no signature: integrity and document validity only")
	}
	for _, f := range doc.Failures {
		line := "  failure: " + string(f.Reason)
		if f.IntegrityReason != "" {
			line += " " + string(f.IntegrityReason)
		}
		if f.Path != "" {
			line += " " + f.Path
		}
		if f.Detail != "" {
			line += ": " + f.Detail
		}
		fmt.Fprintln(w, line)
	}
	for _, wn := range doc.Warnings {
		fmt.Fprintf(w, "  warning: %s: %s\n", wn.Code, wn.Message)
	}
}

// --- diff --------------------------------------------------------------------

type tfBundleRef struct {
	Kind          trustfreeze.Kind `json:"kind"`
	BundleID      string           `json:"bundle_id"`
	ContentDigest string           `json:"content_digest"`
}

type tfDiffDoc struct {
	ResultClass string         `json:"result_class"`
	Command     string         `json:"command"`
	DiffDigest  string         `json:"diff_digest"`
	Diff        compare.Diff   `json:"diff"`
	Verdict     policy.Verdict `json:"verdict"`
	// Output is the diff bundle written with --output.
	Output *tfBundleRef `json:"output,omitempty"`
}

func tfDiff(ctx context.Context, d tfDeps, args []string, stdout, stderr io.Writer) int {
	fs := tfFlagSet("diff", "diff --baseline <dir> --current <dir> [--trust-policy <file>] [--trusted-key <public.pem>]... [--policy <file>] [--fail-on none|low|medium|high|critical] [--allow-subject-mismatch] [--output <dir>] [--format text|json]", stderr)
	baselineDir := fs.String("baseline", "", "Baseline bundle (required). Verified with the trust policy before anything is compared.")
	currentDir := fs.String("current", "", "Current bundle (required): a capture or a baseline. Verified first as well.")
	trustPolicy := fs.String("trust-policy", "", "Trust policy file (JSON or YAML, schema trust-freeze/trust-policy/v1).")
	var trustedKeys multiFlag
	fs.Var(&trustedKeys, "trusted-key", "ed25519 public key file (PEM SPKI) to trust (repeatable).")
	policyFile := fs.String("policy", "", "Policy file (JSON or YAML, schema trust-freeze/policy/v1), or the id of a built-in policy ("+strings.Join(policy.BuiltinPolicyIDs(), ", ")+"). Default: "+policy.DefaultPolicyID+".")
	failOn := fs.String("fail-on", "", "Exit 1 when the highest finding severity is at or above this: none, low, medium, high, critical (default: the policy's fail_on).")
	allowSubject := fs.Bool("allow-subject-mismatch", false, "Compare two different devices on purpose (a golden image or fleet baseline): the subject_changed finding stays, rated by the policy as allowed (info under "+policy.DefaultPolicyID+"), and the diff records the opt-in.")
	output := fs.String("output", "", "Also write a diff bundle (diff.json, verdict.json, the evaluated policy) to this new directory.")
	format := fs.String("format", "text", "Output format: text or json (markdown and sarif: "+tfNotImplemented+").")
	if code, done := tfParseArgs(fs, "diff", args, stdout, stderr); done {
		return code
	}
	out := tfOut{name: "diff", stdout: stdout, stderr: stderr, json: *format == "json"}
	if err := tfFormat(*format, []string{"text", "json"}, []string{"markdown", "sarif"}); err != nil {
		return out.usage(err)
	}
	switch {
	case *baselineDir == "":
		return out.usage(errors.New("--baseline is required"))
	case *currentDir == "":
		return out.usage(errors.New("--current is required"))
	}
	tp, err := tfTrustPolicy(d, *trustPolicy, trustedKeys)
	if err != nil {
		return out.usage(err)
	}
	pol, err := tfLoadPolicy(*policyFile)
	if err != nil {
		return out.usage(err)
	}
	if *failOn != "" {
		t, err := policy.ParseThreshold(*failOn)
		if err != nil {
			return out.usage(fmt.Errorf("--fail-on: %w", err))
		}
		pol.FailOn = t
	}

	// SPEC-0469 R1: both inputs are verified before anything is compared, and
	// a failure stops the diff. No partial or "best effort" comparison.
	vb := tfVerifyBundle(ctx, *baselineDir, tp, trustfreeze.KindBaseline)
	vb.Command, vb.Input = "diff", "baseline"
	if !vb.OK {
		return tfRefuse(out, vb)
	}
	vc := tfVerifyBundle(ctx, *currentDir, tp, trustfreeze.KindCapture, trustfreeze.KindBaseline)
	vc.Command, vc.Input = "diff", "current"
	if !vc.OK {
		return tfRefuse(out, vc)
	}
	bl, err := tfReadVerified(*baselineDir, vb)
	if err != nil {
		return out.fail(tfResultVerification, exitGeneric, err)
	}
	cur, err := tfReadVerified(*currentDir, vc)
	if err != nil {
		return out.fail(tfResultVerification, exitGeneric, err)
	}
	df, err := compare.Compare(ctx, bl, cur, compare.CompareOptions{AllowSubjectMismatch: *allowSubject})
	if err != nil {
		return out.exec(err)
	}
	v, err := policy.Evaluate(ctx, df, pol)
	if err != nil {
		return out.exec(err)
	}
	doc := tfDiffDoc{ResultClass: tfResultOK, Command: "diff", DiffDigest: v.DiffDigest, Diff: df, Verdict: v}
	if *output != "" {
		home, err := d.HomeRoot()
		if err != nil {
			return out.exec(fmt.Errorf("cannot resolve the home root: %w", err))
		}
		ref, err := tfWriteDiffBundle(*output, home, d.Clock.Now(), cur.Manifest.Subject, df, v, pol)
		if err != nil {
			return out.exec(err)
		}
		doc.Output = ref
	}
	code := exitOK
	if v.ThresholdExceeded {
		doc.ResultClass, code = tfResultDrift, exitGeneric
	}
	return out.result(code, doc, func(w io.Writer) { tfPrintDiff(w, doc) })
}

// tfRefuse reports a failed input verification of diff.
func tfRefuse(out tfOut, doc tfVerifyDoc) int {
	msg := fmt.Sprintf("the %s bundle failed verification; nothing was compared", doc.Input)
	if out.json {
		if err := out.emit(doc); err != nil {
			fmt.Fprintf(out.stderr, "skillctl trust-freeze diff: cannot encode output: %v\n", err)
		}
	} else {
		tfPrintVerify(out.stdout, doc)
	}
	fmt.Fprintf(out.stderr, "skillctl trust-freeze diff: %s\n", msg)
	return exitGeneric
}

// tfReadVerified loads a bundle that was just verified and refuses it when
// its manifest is no longer the verified one.
func tfReadVerified(dir string, v tfVerifyDoc) (*trustfreeze.Bundle, error) {
	b, err := trustfreeze.ReadBundle(dir)
	if err != nil {
		return nil, fmt.Errorf("%s bundle: %w", v.Input, err)
	}
	if b.Manifest.ContentDigest != v.ContentDigest {
		return nil, fmt.Errorf("%s bundle changed after verification", v.Input)
	}
	return b, nil
}

// tfLoadPolicy resolves --policy: empty is the built-in default, a built-in
// policy id is that frozen policy (so an older verdict can be reproduced
// without carrying its file around), anything else is a file path.
func tfLoadPolicy(path string) (policy.Policy, error) {
	if path == "" {
		return policy.DefaultPolicy()
	}
	if p, ok, err := policy.BuiltinPolicy(path); ok {
		if err != nil {
			return policy.Policy{}, fmt.Errorf("--policy: %w", err)
		}
		return p, nil
	}
	p, err := policy.LoadPolicyFile(path)
	if err != nil {
		return policy.Policy{}, fmt.Errorf("--policy: %w", err)
	}
	return p, nil
}

// tfWriteDiffBundle writes a diff bundle: diff.json, verdict.json and the
// evaluated policy, under the subject of the current bundle.
func tfWriteDiffBundle(dir, home string, now time.Time, subject trustfreeze.Subject, df compare.Diff, v policy.Verdict, pol policy.Policy) (*tfBundleRef, error) {
	w, err := trustfreeze.NewWriter(dir, trustfreeze.WriterOptions{Kind: trustfreeze.KindDiff, HomeRoot: home})
	if err != nil {
		return nil, err
	}
	m, err := func() (trustfreeze.Manifest, error) {
		if err := w.WriteJSON(compare.DiffFile, df); err != nil {
			return trustfreeze.Manifest{}, err
		}
		if err := w.WriteJSON(policy.VerdictFile, v); err != nil {
			return trustfreeze.Manifest{}, err
		}
		if err := w.WriteJSON(tfEvaluatedPolicyFile, pol); err != nil {
			return trustfreeze.Manifest{}, err
		}
		return w.Finalize(trustfreeze.ManifestHeader{
			Kind:      trustfreeze.KindDiff,
			BundleID:  trustfreeze.BundleID(trustfreeze.KindDiff, now, subject.ID),
			CreatedAt: now,
			Subject:   subject,
		})
	}()
	if err != nil {
		return nil, errors.Join(err, w.Abort())
	}
	return &tfBundleRef{Kind: m.Kind, BundleID: m.BundleID, ContentDigest: m.ContentDigest}, nil
}

func tfPrintDiff(w io.Writer, doc tfDiffDoc) {
	df, v := doc.Diff, doc.Verdict
	fmt.Fprintf(w, "diff %s %s -> %s %s\n", df.Baseline.Kind, df.Baseline.BundleID, df.Current.Kind, df.Current.BundleID)
	fmt.Fprintf(w, "normalization: %s, policy: %s\n", df.Normalization.ID, v.Policy.ID)
	if df.AllowSubjectMismatch {
		fmt.Fprintln(w, "subject mismatch allowed (--allow-subject-mismatch)")
	}
	kinds := make([]string, 0, len(df.Counts))
	for k, n := range df.Counts {
		if n > 0 {
			kinds = append(kinds, fmt.Sprintf("%s %d", k, n))
		}
	}
	sort.Strings(kinds)
	summary := "none"
	if len(kinds) > 0 {
		summary = strings.Join(kinds, ", ")
	}
	fmt.Fprintf(w, "changes: %d (%s)\n", len(df.Changes), summary)
	for i, c := range df.Changes {
		subject := c.ArtifactID
		if subject == "" {
			// A capability entry carries no artifact id: it names its
			// capability, and a text reader must see which one.
			subject = c.CapabilityID
		}
		if subject == "" {
			subject = c.ProbeID
		}
		detail := ""
		if len(c.ChangedAttributes) > 0 {
			detail = " attributes " + strings.Join(c.ChangedAttributes, ",")
		}
		if len(c.ChangedFields) > 0 {
			detail += " fields " + strings.Join(c.ChangedFields, ",")
		}
		switch c.Kind {
		case compare.ChangeSubjectChanged:
			subject = c.BeforeSubjectID + " -> " + c.AfterSubjectID
		case compare.ChangeNotObserved:
			detail = " probe " + c.ProbeID
			if c.AfterDigest != "" {
				detail += " attributes " + strings.Join(c.UnobservedAttributes, ",")
			}
		case compare.ChangeApplicabilityChanged:
			detail = " " + string(c.BeforeStatus) + " -> " + string(c.AfterStatus)
		case compare.ChangeCoverageIncreased:
			// A downgraded capability_changed carries the fields that differ,
			// and they stay: the privilege and the blind probe alone would
			// not say what moved (R-T5).
			detail += " privilege " + c.AfterPrivilege + ", not captured in the baseline: " + strings.Join(c.BaselineGapProbes, ",")
		case compare.ChangeCapabilityAdded, compare.ChangeCapabilityRemoved, compare.ChangeCapabilityNotObserved:
			if p := c.AfterPrivilege + c.BeforePrivilege; p != "" {
				detail += " privilege " + p
			}
		}
		if c.Gap != nil {
			detail = " " + c.Gap.Cause
			if c.Gap.Required {
				detail += " (required)"
			}
		}
		sev := ""
		if i < len(v.Findings) {
			sev = fmt.Sprintf("  [%s, %s]", v.Findings[i].Severity, v.Findings[i].RuleID)
		}
		fmt.Fprintf(w, "  %s %s%s%s\n", c.Kind, subject, detail, sev)
	}
	highest := string(v.HighestSeverity)
	if highest == "" {
		highest = "none"
	}
	state := "not exceeded"
	if v.ThresholdExceeded {
		state = "EXCEEDED"
	}
	fmt.Fprintf(w, "verdict: highest %s, fail_on %s: threshold %s\n", highest, v.FailOn, state)
	fmt.Fprintf(w, "diff_digest: %s\n", doc.DiffDigest)
	if doc.Output != nil {
		fmt.Fprintf(w, "diff bundle written: %s (%s)\n", doc.Output.BundleID, doc.Output.ContentDigest)
	}
}

// --- report ------------------------------------------------------------------

type tfReportDoc struct {
	ResultClass string       `json:"result_class"`
	Command     string       `json:"command"`
	Input       report.Input `json:"input"`
	// Signature is set for a baseline: always not_evaluated, with a pointer
	// to verify (SPEC-0469 section 4.7).
	Signature *report.SignatureStatus `json:"signature,omitempty"`
	// ReportSHA256 is the lowercase hex SHA-256 of the written report file.
	ReportSHA256 string `json:"report_sha256"`
}

func tfReport(ctx context.Context, d tfDeps, args []string, stdout, stderr io.Writer) int {
	fs := tfFlagSet("report", "report --input <dir> --output <file|dir> [--format json|yaml|html]", stderr)
	input := fs.String("input", "", "Capture, baseline or diff bundle to project (required).")
	output := fs.String("output", "", "Report file to create (required). An existing directory gets report.json, report.yaml or report.html. Never overwritten, never inside the input bundle.")
	format := fs.String("format", "json", "Report file format: "+strings.Join(tfReportFormatNames(), ", ")+" (markdown and sarif: "+tfNotImplemented+"). Standard output is always JSON.")
	if code, done := tfParseArgsJSON(fs, "report", args, stdout, stderr); done {
		return code
	}
	// --format names the format of the report file, not the format of this
	// status document: stdout of report is always JSON (FR-0472). Every call
	// that was valid before this change already had JSON on stdout, because
	// json was the only accepted value.
	out := tfOut{name: "report", stdout: stdout, stderr: stderr, json: true}
	if err := tfFormat(*format, tfReportFormatNames(), []string{"markdown", "sarif"}); err != nil {
		return out.usage(err)
	}
	switch {
	case *input == "":
		return out.usage(errors.New("--input is required"))
	case *output == "":
		return out.usage(errors.New("--output is required"))
	}
	target, err := tfReportTarget(*input, *output, *format)
	if err != nil {
		return out.exec(err)
	}
	// report is a pure projection (SPEC-0469 section 4.7): it reads the
	// bundle through the core integrity check and evaluates no signature,
	// key trust or expiry, so its bytes never depend on trust material or
	// the clock. A baseline report says so and names verify.
	b, err := trustfreeze.ReadBundle(*input)
	if err != nil {
		return out.fail(tfResultVerification, exitGeneric, fmt.Errorf("input bundle: %w", err))
	}
	rep, err := report.FromBundle(b)
	if err != nil {
		return out.fail(tfResultVerification, exitGeneric, err)
	}
	raw, err := tfRenderReport(rep, *format)
	if err != nil {
		return out.exec(err)
	}
	if err := tfWriteNewFile(target, raw); err != nil {
		return out.exec(err)
	}
	doc := tfReportDoc{ResultClass: tfResultOK, Command: "report", Input: rep.Input, Signature: rep.Signature, ReportSHA256: trustfreeze.SHA256Hex(raw)}
	return out.result(exitOK, doc, func(w io.Writer) {
		fmt.Fprintf(w, "report written: %s (sha256 %s)\n", target, doc.ReportSHA256)
		if doc.Signature != nil {
			fmt.Fprintf(w, "signature: %s; evaluate it with `%s`\n", doc.Signature.Result, doc.Signature.VerifyWith)
		}
	})
}

// tfRenderReport renders a report in one of the file formats of
// tfReportFormats. Every format renders the same projection: JSON is the
// canonical form, YAML is converted from those bytes, and the page is built
// from the projection as well (FR-0472).
func tfRenderReport(rep report.Report, format string) ([]byte, error) {
	switch format {
	case "yaml":
		return report.MarshalYAML(rep)
	default:
		return report.Marshal(rep)
	}
}

// tfReportTarget resolves --output: an existing directory gets the file name of
// the format, anything else is the file itself. The file must not exist and
// must not lie inside the input bundle, which would then carry an extra file
// and fail its own verification.
func tfReportTarget(input, output, format string) (string, error) {
	target := output
	if fi, err := os.Stat(output); err == nil && fi.IsDir() {
		name, ok := tfReportFormats[format]
		if !ok {
			name = tfDefaultReportFile
		}
		target = filepath.Join(output, name)
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", fmt.Errorf("--output: %w", err)
	}
	in, err := filepath.Abs(input)
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(in); err == nil {
		in = r
	}
	p, i := parent, filepath.Clean(in)
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		p, i = strings.ToLower(p), strings.ToLower(i)
	}
	if rel, err := filepath.Rel(i, p); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
		return "", errors.New("--output: the report must not be written inside the input bundle")
	}
	final := filepath.Join(parent, filepath.Base(abs))
	// Nor inside any other bundle (TF05-R2: report never updates a baseline).
	if dir, err := trustfreeze.EnclosingBundle(final); err != nil {
		return "", fmt.Errorf("--output: %w", err)
	} else if dir != "" {
		return "", fmt.Errorf("--output: the report must not be written inside the trust-freeze bundle %s", dir)
	}
	return final, nil
}

// tfWriteNewFile creates path exclusively with mode 0600 (a report can carry
// the host name) and removes it again when the write fails.
func tfWriteNewFile(path string, b []byte) error {
	// #nosec G304 -- der Pfad IST die Eingabe des Bedieners (--output). Das
	// Kommando schreibt genau dorthin und nirgends sonst; O_EXCL verhindert,
	// dass es eine vorhandene Datei ueberschreibt.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		// Close-Fehler mitnehmen, statt ihn zu verschlucken: die halbe Datei
		// wird ohnehin entfernt, aber die Ursache gehoert in die Meldung.
		return errors.Join(err, f.Close(), os.Remove(path))
	}
	if err := f.Close(); err != nil {
		return errors.Join(err, os.Remove(path))
	}
	return nil
}
