package probe

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"time"
)

// FakeResponse is the scripted outcome of one command in a FakeRunner.
type FakeResponse struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	// Duration is reported as the run duration (no real time passes).
	Duration time.Duration
	// TimedOut simulates a run killed at its deadline.
	TimedOut bool
	// PermissionDenied simulates a start refused by the OS.
	PermissionDenied bool
	// StartFailed simulates any other start failure.
	StartFailed bool
	// ErrMessage is the error text for the simulated failure. It passes the
	// redactor like everything else.
	ErrMessage string
}

// FakeCall records one Run call of a FakeRunner as requested. It exists for
// test assertions only and is never persisted.
type FakeCall struct {
	Executable string
	Args       []string
	Env        []string
	WorkingDir string
	Timeout    time.Duration
	MaxStdout  int64
	MaxStderr  int64
}

// FakeRunner is the deterministic CommandRunner for tests (SPEC-0467 R9).
// Results are scripted per executable plus argument vector. Output goes
// through the same cap, whole-line truncation and redaction as ExecRunner,
// so a test of a probe against the fake exercises the persisted path.
//
// A tool that has no path (AddTool) is missing: LookPath and Run report
// tool_missing. A command without a script reports not_scripted, so a test
// cannot pass by accident.
type FakeRunner struct {
	mu      sync.Mutex
	paths   map[string]string
	denied  map[string]bool
	scripts map[string]FakeResponse
	calls   []FakeCall
	dirs    []string
}

// NewFakeRunner returns an empty fake runner.
func NewFakeRunner() *FakeRunner {
	return &FakeRunner{paths: map[string]string{}, denied: map[string]bool{}, scripts: map[string]FakeResponse{}}
}

// FakeKey returns the script key of an executable and its arguments.
func FakeKey(executable string, args ...string) string {
	return executable + "\x00" + strings.Join(args, "\x00")
}

// AddTool makes executable resolvable at path.
func (f *FakeRunner) AddTool(executable, path string) *FakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths[executable] = path
	return f
}

// DenyTool makes executable exist but not be executable (permission denied).
func (f *FakeRunner) DenyTool(executable, path string) *FakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths[executable] = path
	f.denied[executable] = true
	return f
}

// Script sets the response for executable with exactly args. The tool
// becomes resolvable at "/fake/bin/<executable>" unless AddTool set a path.
func (f *FakeRunner) Script(executable string, args []string, resp FakeResponse) *FakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.paths[executable]; !ok {
		f.paths[executable] = "/fake/bin/" + executable
	}
	f.scripts[FakeKey(executable, args...)] = resp
	return f
}

// WithSearchDirs makes the fake report dirs as the directories it resolves
// bare names in. It is a statement of the test, not a search: LookPath keeps
// answering from the AddTool table. A fake without it reports none, so a
// probe that names the searched directories says it cannot name them rather
// than inventing a list.
func (f *FakeRunner) WithSearchDirs(dirs ...string) *FakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dirs = append([]string(nil), dirs...)
	return f
}

// SearchDirs implements SearchPathReporter.
func (f *FakeRunner) SearchDirs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dirs...)
}

// Calls returns the recorded calls in call order.
func (f *FakeRunner) Calls() []FakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]FakeCall(nil), f.calls...)
}

// LookPath resolves executable from the AddTool/Script table.
func (f *FakeRunner) LookPath(file string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.paths[file]
	switch {
	case !ok:
		return "", newCommandError(ErrToolMissing, fmt.Sprintf("%q not found in the runner search path", file))
	case f.denied[file]:
		return "", newCommandError(ErrPermissionDenied, fmt.Sprintf("%q is not executable", file))
	}
	return p, nil
}

// Run returns the scripted response for req.
func (f *FakeRunner) Run(ctx context.Context, req CommandRequest) CommandResult {
	raw := rawResult{exitCode: -1}
	if err := req.validate(); err != nil {
		raw.errKind, raw.errMessage = ErrInvalidRequest, err.Error()
		return finish(ctx, req, raw)
	}
	path, lookErr := f.LookPath(req.Executable)
	f.mu.Lock()
	resp, scripted := f.scripts[FakeKey(req.Executable, req.Args...)]
	f.calls = append(f.calls, FakeCall{
		Executable: req.Executable,
		Args:       append([]string(nil), req.Args...),
		Env:        append([]string(nil), req.EnvAllowlist...),
		WorkingDir: req.WorkingDir,
		Timeout:    req.Timeout,
		MaxStdout:  req.MaxStdoutBytes,
		MaxStderr:  req.MaxStderrBytes,
	})
	f.mu.Unlock()

	if lookErr != nil {
		raw.errKind, raw.errMessage = ErrToolMissing, lookErr.Error()
		var ce *CommandError
		if errors.As(lookErr, &ce) {
			raw.errKind, raw.errMessage = ce.kind, ce.Message
		}
		return finish(ctx, req, raw)
	}
	raw.path = path
	if err := refuseElevation(path); err != nil {
		raw.errKind, raw.errMessage = ErrInvalidRequest, err.Error()
		return finish(ctx, req, raw)
	}
	if err := ctx.Err(); err != nil {
		raw.errKind, raw.errMessage = ctxKind(err), "not started: "+err.Error()
		return finish(ctx, req, raw)
	}
	if !scripted {
		raw.errKind, raw.errMessage = ErrNotScripted, fmt.Sprintf("no script for %q with %d argument(s)", req.Executable, len(req.Args))
		return finish(ctx, req, raw)
	}
	switch {
	case resp.PermissionDenied:
		raw.errKind, raw.errMessage = ErrPermissionDenied, resp.ErrMessage
		return finish(ctx, req, raw)
	case resp.StartFailed:
		raw.errKind, raw.errMessage = ErrStartFailed, resp.ErrMessage
		return finish(ctx, req, raw)
	}
	raw.stdout = newCappedBuffer(req.MaxStdoutBytes, DefaultMaxStdoutBytes)
	raw.stderr = newCappedBuffer(req.MaxStderrBytes, DefaultMaxStderrBytes)
	_, _ = raw.stdout.Write(resp.Stdout)
	_, _ = raw.stderr.Write(resp.Stderr)
	raw.duration = resp.Duration
	raw.exitCode = resp.ExitCode
	if resp.TimedOut {
		raw.exitCode = -1
		raw.timedOut = true
		raw.errKind, raw.errMessage = ErrTimeout, "process group killed at the deadline"
		if resp.ErrMessage != "" {
			raw.errMessage = resp.ErrMessage
		}
	}
	return finish(ctx, req, raw)
}

// FakeFiles is a FileReader over an in-memory table, for tests. Errs maps a
// path to the error ReadFile returns for it (for example fs.ErrPermission).
// Paths not in either table do not exist.
type FakeFiles struct {
	Files map[string][]byte
	Errs  map[string]error
}

// ReadFile returns a copy of the file content or the scripted error.
func (f FakeFiles) ReadFile(name string) ([]byte, error) {
	if err, ok := f.Errs[name]; ok {
		return nil, &fs.PathError{Op: "read", Path: name, Err: err}
	}
	b, ok := f.Files[name]
	if !ok {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrNotExist}
	}
	return append([]byte(nil), b...), nil
}
