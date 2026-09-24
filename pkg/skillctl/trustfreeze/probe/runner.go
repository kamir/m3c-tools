package probe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// CommandRunner runs commands as executable plus argument vector, never
// through a shell (SPEC-0467 R2). The production ExecRunner and the
// deterministic FakeRunner implement it the same way, including redaction,
// so tests do not depend on installed tools (SPEC-0467 R9).
type CommandRunner interface {
	// LookPath resolves an executable name to an absolute path.
	LookPath(file string) (string, error)
	// Run runs one command. It never returns raw output: every field that
	// carries output, arguments or error text has passed the redactor.
	Run(ctx context.Context, req CommandRequest) CommandResult
}

// CommandRequest describes one command run.
type CommandRequest struct {
	// Executable is a bare name resolved through the runner search path, or
	// an absolute path. Relative paths are refused.
	Executable string
	Args       []string
	// EnvAllowlist names the environment variables passed through. The child
	// environment is exactly these plus LC_ALL=C and TZ=UTC0.
	EnvAllowlist []string
	// WorkingDir of the command; empty means the filesystem root (the
	// Windows directory on Windows), never the caller's current directory.
	WorkingDir string
	// Timeout of this run; zero means no timeout beyond the context.
	Timeout time.Duration
	// MaxStdoutBytes and MaxStderrBytes cap the kept output; zero means the
	// default limit.
	MaxStdoutBytes int64
	MaxStderrBytes int64
	// Redactor applied to the result; nil means redact.Default(). There is
	// no way to switch redaction off.
	Redactor *redact.Redactor
}

// Error classes of a command run. They are stable strings for
// ProbeError.Class and ToolInvocation.Error.
const (
	ClassToolMissing      = "tool_missing"
	ClassPermissionDenied = "permission_denied"
	ClassTimeout          = "timeout"
	ClassCanceled         = "canceled"
	ClassStartFailed      = "start_failed"
	ClassTerminated       = "terminated"
	ClassIONotClosed      = "io_not_closed"
	ClassInvalidRequest   = "invalid_request"
	ClassNotScripted      = "not_scripted"
	ClassLimitExceeded    = "limit_exceeded"
	ClassRedactionFailed  = "redaction_failed"
	ClassPanic            = "panic"
)

// Sentinel errors, one per class. CommandResult.Err wraps exactly one.
var (
	ErrToolMissing      = errors.New(ClassToolMissing)
	ErrPermissionDenied = errors.New(ClassPermissionDenied)
	ErrTimeout          = errors.New(ClassTimeout)
	ErrCanceled         = errors.New(ClassCanceled)
	ErrStartFailed      = errors.New(ClassStartFailed)
	ErrTerminated       = errors.New(ClassTerminated)
	ErrIONotClosed      = errors.New(ClassIONotClosed)
	ErrInvalidRequest   = errors.New(ClassInvalidRequest)
	ErrNotScripted      = errors.New(ClassNotScripted)
)

// CommandError is the error of a command run. Message has passed the
// redactor.
type CommandError struct {
	Class   string
	Message string
	kind    error
}

func (e *CommandError) Error() string {
	if e.Message == "" {
		return e.Class
	}
	return e.Class + ": " + e.Message
}

// Unwrap returns the class sentinel.
func (e *CommandError) Unwrap() error { return e.kind }

func newCommandError(kind error, msg string) *CommandError {
	return &CommandError{Class: kind.Error(), Message: msg, kind: kind}
}

// ErrorClass returns the class of err: the CommandError class, a class
// derived from a well-known sentinel, or "failed".
func ErrorClass(err error) string {
	var ce *CommandError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &ce):
		return ce.Class
	case errors.Is(err, ErrLimitExceeded):
		return ClassLimitExceeded
	case errors.Is(err, redact.ErrRedactionFailed):
		return ClassRedactionFailed
	case errors.Is(err, context.DeadlineExceeded):
		return ClassTimeout
	case errors.Is(err, context.Canceled):
		return ClassCanceled
	case errors.Is(err, fs.ErrPermission):
		return ClassPermissionDenied
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, exec.ErrNotFound):
		return ClassToolMissing
	}
	return "failed"
}

// CommandResult is the redacted outcome of one command run.
type CommandResult struct {
	// Executable as requested, Path as resolved; both redacted.
	Executable string
	Path       string
	// Args after redaction (see redact.Redactor.RedactArgs).
	Args []string
	// Stdout and Stderr hold the redacted kept output. When truncated, only
	// whole lines are kept, so no secret is cut into an unrecognizable
	// prefix.
	Stdout redact.Redacted
	Stderr redact.Redacted
	// StdoutBytes and StderrBytes count every byte the command wrote.
	StdoutBytes     int64
	StderrBytes     int64
	StdoutTruncated bool
	StderrTruncated bool
	// ExitCode is -1 when the process did not exit normally or never ran.
	ExitCode int
	Duration time.Duration
	TimedOut bool
	// Err is a *CommandError or nil. A non-zero exit is not an error.
	Err error
	// RedactionFailed says that some field could not be redacted and was
	// dropped (fail-closed). A probe must then be at least partial.
	RedactionFailed bool
	// Redactions counts the replacements made.
	Redactions redact.RedactionLog
}

// OK reports a run without error and with exit code 0.
func (r CommandResult) OK() bool { return r.Err == nil && r.ExitCode == 0 }

// Invocation returns the persisted tool record (SPEC-0467 R8).
func (r CommandResult) Invocation() trustfreeze.ToolInvocation {
	args := r.Args
	if args == nil {
		args = []string{}
	}
	inv := trustfreeze.ToolInvocation{
		Name:            r.Executable,
		Path:            r.Path,
		Args:            append([]string{}, args...),
		ExitCode:        r.ExitCode,
		DurationMS:      r.Duration.Milliseconds(),
		TimedOut:        r.TimedOut,
		StdoutBytes:     r.StdoutBytes,
		StderrBytes:     r.StderrBytes,
		StdoutTruncated: r.StdoutTruncated,
		StderrTruncated: r.StderrTruncated,
	}
	if r.Err != nil {
		inv.Error = r.Err.Error()
	}
	return inv
}

// rawResult is the unredacted outcome inside a runner. It never leaves the
// package: finish turns it into a CommandResult.
type rawResult struct {
	path       string
	stdout     *cappedBuffer
	stderr     *cappedBuffer
	exitCode   int
	duration   time.Duration
	timedOut   bool
	errKind    error
	errMessage string
}

// finish redacts a raw result. The redaction runs even when ctx is done
// (a timed-out command still has output worth keeping), bounded by the
// output caps. Secrets found in the arguments are also removed from stdout,
// stderr and the error text.
func finish(ctx context.Context, req CommandRequest, raw rawResult) CommandResult {
	rctx := context.WithoutCancel(ctx)
	red := req.Redactor
	res := CommandResult{ExitCode: raw.exitCode, Duration: raw.duration, TimedOut: raw.timedOut}
	var log redact.RedactionLog
	fail := func() { res.RedactionFailed = true }

	if s, l, err := red.RedactString(rctx, req.Executable); err == nil {
		res.Executable, log = s, log.Merge(l)
	} else {
		res.Executable = redact.Marker(ClassRedactionFailed)
		fail()
	}
	if raw.path != "" {
		if s, l, err := red.RedactString(rctx, raw.path); err == nil {
			res.Path, log = s, log.Merge(l)
		} else {
			fail()
		}
	}
	args, secrets, l, err := red.RedactArgsSecrets(rctx, req.Args)
	if err == nil {
		res.Args, log = args, log.Merge(l)
	} else {
		res.Args = []string{}
		fail()
	}
	// A tool may echo its arguments: every secret removed from them is also
	// removed from the output and the error text of this run.
	red = red.WithSecrets(secrets)
	for _, s := range []struct {
		name string
		buf  *cappedBuffer
		out  *redact.Redacted
		n    *int64
		tr   *bool
	}{
		{"stdout", raw.stdout, &res.Stdout, &res.StdoutBytes, &res.StdoutTruncated},
		{"stderr", raw.stderr, &res.Stderr, &res.StderrBytes, &res.StderrTruncated},
	} {
		if s.buf == nil {
			continue
		}
		kept, total, truncated := s.buf.snapshot()
		*s.n, *s.tr = total, truncated
		if truncated {
			kept = keepWholeLines(kept)
		}
		rr, err := red.RedactBytes(rctx, redact.EvidenceDescriptor{Name: s.name, Source: req.Executable}, kept)
		if err != nil {
			fail()
			continue
		}
		*s.out, log = rr.Data, log.Merge(rr.Log)
	}
	if raw.errKind != nil {
		msg, l, err := red.RedactString(rctx, raw.errMessage)
		if err != nil {
			msg = redact.Marker(ClassRedactionFailed)
			fail()
		}
		log = log.Merge(l)
		res.Err = newCommandError(raw.errKind, msg)
	}
	res.Redactions = log
	return res
}

// keepWholeLines drops the incomplete last line of truncated output.
func keepWholeLines(b []byte) []byte {
	i := bytes.LastIndexByte(b, '\n')
	if i < 0 {
		return nil
	}
	return b[:i+1]
}

// cappedBuffer keeps at most max bytes, counts everything and never blocks
// the writer: excess output is drained, so a chatty tool cannot stall on a
// full pipe.
type cappedBuffer struct {
	mu        sync.Mutex
	limit     int64
	buf       []byte
	total     int64
	truncated bool
}

func newCappedBuffer(limit, def int64) *cappedBuffer {
	if limit <= 0 {
		limit = def
	}
	return &cappedBuffer{limit: limit}
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total += int64(len(p))
	room := c.limit - int64(len(c.buf))
	switch {
	case int64(len(p)) <= room:
		c.buf = append(c.buf, p...)
	case room > 0:
		c.buf = append(c.buf, p[:room]...)
		c.truncated = true
	case len(p) > 0:
		c.truncated = true
	}
	return len(p), nil
}

func (c *cappedBuffer) snapshot() ([]byte, int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...), c.total, c.truncated
}

func (req CommandRequest) validate() error {
	if req.Executable == "" {
		return errors.New("empty executable")
	}
	if strings.ContainsRune(req.Executable, 0) {
		return errors.New("executable contains NUL")
	}
	for _, a := range req.Args {
		if strings.ContainsRune(a, 0) {
			return errors.New("argument contains NUL")
		}
	}
	if req.Timeout < 0 || req.MaxStdoutBytes < 0 || req.MaxStderrBytes < 0 {
		return errors.New("negative timeout or output limit")
	}
	return refuseElevation(req.Executable)
}

// elevationHelpers are executables whose purpose is to run something with
// other privileges. Trust Freeze never elevates and never makes a password
// or consent prompt appear (SPEC-0467 R6, TF02-AC5), so both runners refuse
// them by name: requested bare, by absolute path, or reached through a
// symlink. Starting a helper in a session of its own is not enough, because
// pkexec and run0 ask polkit, whose desktop agent is bound to the login
// session, and a descendant that switched uid after authenticating cannot
// be signaled by the group kill.
var elevationHelpers = map[string]bool{
	"doas": true, "pkexec": true, "run0": true, "runas": true,
	"runuser": true, "su": true, "sudo": true,
}

// isElevationHelper reports whether the last element of p names an
// elevation helper, ignoring case, either separator and a Windows .exe.
func isElevationHelper(p string) bool {
	p = strings.ReplaceAll(p, `\`, "/")
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	return elevationHelpers[strings.TrimSuffix(strings.ToLower(p), ".exe")]
}

// refuseElevation returns an error when any of names is an elevation helper.
func refuseElevation(names ...string) error {
	for _, n := range names {
		if n != "" && isElevationHelper(n) {
			return fmt.Errorf("refusing elevation helper %q: trust freeze never elevates", n)
		}
	}
	return nil
}

// ExecRunner is the production CommandRunner. It resolves executables only
// in a fixed search path (not the caller's PATH), refuses elevation helpers,
// passes only allowlisted environment variables plus LC_ALL=C and TZ=UTC0,
// runs in the filesystem root, caps stdout and stderr, and on timeout kills
// the tool with everything it started: on Unix the session and process group
// of its own that every tool gets; on Windows the started process and every
// descendant traceable by parent pid (procgroup_windows.go lists the
// remaining gaps).
//
// A process in uninterruptible sleep (for example on a hung NFS or FUSE
// mount) does not die from SIGKILL until its I/O returns, and Wait then blocks
// past WaitDelay. The capture engine abandons such a run at the probe
// deadline and continues, but the process outlives the group kill; probes
// should therefore read mount tables rather than stat mount points.
type ExecRunner struct {
	// SearchPath lists the directories bare names are resolved in.
	SearchPath []string
	// LookupEnv reads the parent environment; nil means os.LookupEnv.
	LookupEnv func(string) (string, bool)
	// Clock measures durations; nil means the system clock.
	Clock trustfreeze.Clock
	// WaitDelay bounds the wait for I/O after exit or cancellation; zero
	// means DefaultWaitDelay.
	WaitDelay time.Duration
}

// DefaultWaitDelay bounds how long a run waits for stdout and stderr to
// close after the process exited or was killed.
const DefaultWaitDelay = 2 * time.Second

// NewExecRunner returns an ExecRunner with DefaultSearchPath.
func NewExecRunner() *ExecRunner {
	return &ExecRunner{SearchPath: DefaultSearchPath(runtime.GOOS)}
}

// DefaultSearchPath returns the fixed system directories bare names are
// resolved in. User-writable directories are not part of it, so a planted
// "uname" earlier in PATH is never run.
func DefaultSearchPath(goos string) []string {
	if goos == "windows" {
		// The OS answer when running on Windows; %SystemRoot% is controlled
		// by the caller's environment and only a fallback.
		if dir := systemDirectory(); dir != "" {
			return []string{dir}
		}
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		return []string{filepath.Join(root, "System32")}
	}
	return []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"}
}

// LookPath resolves file in the search path. An absolute path is checked
// as is; a relative path with a separator is refused.
func (r *ExecRunner) LookPath(file string) (string, error) {
	if file == "" || strings.ContainsRune(file, 0) {
		return "", newCommandError(ErrInvalidRequest, "bad executable name")
	}
	if filepath.IsAbs(file) {
		p, err := exec.LookPath(file)
		if err != nil {
			return "", lookPathError(file, err)
		}
		return p, nil
	}
	if strings.ContainsAny(file, `/\`) {
		return "", newCommandError(ErrInvalidRequest, fmt.Sprintf("relative executable path %q", file))
	}
	var permErr error
	for _, dir := range r.SearchPath {
		if !filepath.IsAbs(dir) {
			continue
		}
		p, err := exec.LookPath(filepath.Join(dir, file))
		if err == nil {
			return p, nil
		}
		if errors.Is(err, fs.ErrPermission) && permErr == nil {
			permErr = err
		}
	}
	if permErr != nil {
		return "", lookPathError(file, permErr)
	}
	return "", newCommandError(ErrToolMissing, fmt.Sprintf("%q not found in the runner search path", file))
}

func lookPathError(file string, err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return newCommandError(ErrPermissionDenied, fmt.Sprintf("%q is not executable", file))
	}
	return newCommandError(ErrToolMissing, fmt.Sprintf("%q not found", file))
}

// Run runs req. See CommandRunner.
func (r *ExecRunner) Run(ctx context.Context, req CommandRequest) CommandResult {
	clock := r.Clock
	if clock == nil {
		clock = trustfreeze.SystemClock{}
	}
	raw := rawResult{exitCode: -1}
	if err := req.validate(); err != nil {
		raw.errKind, raw.errMessage = ErrInvalidRequest, err.Error()
		return finish(ctx, req, raw)
	}
	path, err := r.LookPath(req.Executable)
	if err != nil {
		var ce *CommandError
		if errors.As(err, &ce) {
			raw.errKind, raw.errMessage = ce.kind, ce.Message
		} else {
			raw.errKind, raw.errMessage = ErrToolMissing, err.Error()
		}
		return finish(ctx, req, raw)
	}
	raw.path = path
	// The resolved path and, through a symlink, its target must not be an
	// elevation helper either.
	target, _ := filepath.EvalSymlinks(path)
	if err := refuseElevation(path, target); err != nil {
		raw.errKind, raw.errMessage = ErrInvalidRequest, err.Error()
		return finish(ctx, req, raw)
	}
	if err := ctx.Err(); err != nil {
		raw.errKind, raw.errMessage = ctxKind(err), "not started: "+err.Error()
		return finish(ctx, req, raw)
	}

	runCtx, cancel := ctx, context.CancelFunc(func() {})
	if req.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, req.Timeout)
	}
	defer cancel()

	raw.stdout = newCappedBuffer(req.MaxStdoutBytes, DefaultMaxStdoutBytes)
	raw.stderr = newCappedBuffer(req.MaxStderrBytes, DefaultMaxStderrBytes)
	// #nosec G204 -- ein Prozess mit variablem Programm IST die Aufgabe
	// dieses Runners: er ruft die autoritativen Systemwerkzeuge auf. Der Pfad
	// stammt aus LookPath ueber eine feste Suchliste, Argumente gehen als
	// Vektor und nie durch eine Shell, die Umgebung ist eine Positivliste,
	// und Laufzeit sowie Ausgabemenge sind begrenzt (SPEC-0467 Abschnitt 5.1).
	cmd := exec.CommandContext(runCtx, path, req.Args...)
	cmd.Env = r.env(req.EnvAllowlist)
	cmd.Dir = req.WorkingDir
	if cmd.Dir == "" {
		cmd.Dir = defaultWorkingDir()
	}
	cmd.Stdin = nil
	cmd.Stdout = raw.stdout
	cmd.Stderr = raw.stderr
	cmd.WaitDelay = r.WaitDelay
	if cmd.WaitDelay <= 0 {
		cmd.WaitDelay = DefaultWaitDelay
	}
	configureProcessGroup(cmd)

	start := clock.Now()
	runErr := cmd.Run()
	raw.duration = clock.Now().Sub(start)
	cleanupProcessGroup(cmd)

	if cmd.ProcessState != nil {
		raw.exitCode = cmd.ProcessState.ExitCode()
	}
	var exitErr *exec.ExitError
	switch {
	case runErr != nil && runCtx.Err() != nil:
		// Killed at the deadline or on cancellation: not a normal exit. On
		// Windows TerminateProcess leaves exit code 1, which must not read
		// as the tool's own answer.
		raw.exitCode = -1
		kind := ctxKind(runCtx.Err())
		raw.timedOut = kind == ErrTimeout
		raw.errKind, raw.errMessage = kind, "process group killed at the deadline"
		if kind == ErrCanceled {
			raw.errMessage = "process group killed on cancellation"
		}
	case runErr == nil:
	case errors.Is(runErr, exec.ErrWaitDelay):
		raw.errKind, raw.errMessage = ErrIONotClosed, "output pipes stayed open after exit"
	case errors.As(runErr, &exitErr):
		if raw.exitCode < 0 {
			raw.errKind, raw.errMessage = ErrTerminated, exitErr.Error()
		}
	case cmd.ProcessState == nil:
		switch {
		case errors.Is(runErr, fs.ErrPermission):
			raw.errKind = ErrPermissionDenied
		case errors.Is(runErr, fs.ErrNotExist), errors.Is(runErr, exec.ErrNotFound):
			raw.errKind = ErrToolMissing
		default:
			raw.errKind = ErrStartFailed
		}
		raw.errMessage = runErr.Error()
	default:
		raw.errKind, raw.errMessage = ErrStartFailed, runErr.Error()
	}
	return finish(ctx, req, raw)
}

func ctxKind(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrTimeout
	}
	return ErrCanceled
}

// env builds the child environment: allowlisted variables that are set in
// the parent, sorted by name, then LC_ALL=C and TZ=UTC0. TZ in its POSIX form
// needs no tzdata (glibc and musl alike); without it a tool falls back to
// /etc/localtime, and evidence with local timestamps would differ between
// hosts in different time zones. On Windows, os/exec adds SYSTEMROOT itself
// when it is missing.
func (r *ExecRunner) env(allow []string) []string {
	lookup := r.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	names := make([]string, 0, len(allow))
	seen := map[string]bool{}
	for _, n := range allow {
		if n == "" || strings.ContainsAny(n, "=\x00") || strings.EqualFold(n, "LC_ALL") || strings.EqualFold(n, "TZ") || seen[n] {
			continue
		}
		seen[n] = true
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names)+2)
	for _, n := range names {
		if v, ok := lookup(n); ok {
			out = append(out, n+"="+v)
		}
	}
	return append(out, "LC_ALL=C", "TZ=UTC0")
}
