package probe

import (
	"context"
	"sort"
	"sync"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// RecordingRunner wraps the runner of one probe run. It clamps every request
// to the run limits, forces the run redactor, records a ToolInvocation per
// run (the engine persists these, not what the probe claims) and refuses
// every run after Close, so a probe abandoned at its timeout cannot start new
// processes.
type RecordingRunner struct {
	inner    CommandRunner
	limits   Limits
	redactor *redact.Redactor

	mu              sync.Mutex
	closed          bool
	invocations     []trustfreeze.ToolInvocation
	redactionFailed bool
	truncated       []string
	argSecrets      []string
}

// NewRecordingRunner wraps inner. red is forced on every request; nil means
// redact.Default().
func NewRecordingRunner(inner CommandRunner, limits Limits, red *redact.Redactor) *RecordingRunner {
	return &RecordingRunner{inner: inner, limits: limits.WithDefaults(), redactor: red}
}

// LookPath delegates to the wrapped runner.
func (r *RecordingRunner) LookPath(file string) (string, error) { return r.inner.LookPath(file) }

// SearchDirs implements SearchPathReporter by forwarding to the wrapped
// runner, and returns nil for a runner that does not report its search path.
// Without this the engine's own wrapper would hide the directories from every
// probe: the engine hands each Collect a RecordingRunner, so a probe asking
// probe.SearchDirs would be told that nobody knows where the tool was looked
// for, while the ExecRunner underneath knows exactly.
func (r *RecordingRunner) SearchDirs() []string { return SearchDirs(r.inner) }

// Run clamps req, runs it and records the invocation.
func (r *RecordingRunner) Run(ctx context.Context, req CommandRequest) CommandResult {
	req = r.limits.clampRequest(req)
	req.Redactor = r.redactor
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return finish(ctx, req, rawResult{exitCode: -1, errKind: ErrCanceled, errMessage: "probe run already finished"})
	}
	_, secrets, _, err := r.redactor.RedactArgsSecrets(context.WithoutCancel(ctx), req.Args)
	res := r.inner.Run(ctx, req)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.redactionFailed = true
	}
	r.argSecrets = append(r.argSecrets, secrets...)
	if !r.closed {
		r.invocations = append(r.invocations, res.Invocation())
		if res.RedactionFailed {
			r.redactionFailed = true
		}
		if res.StdoutTruncated {
			r.truncated = append(r.truncated, "stdout:"+res.Executable)
		}
		if res.StderrTruncated {
			r.truncated = append(r.truncated, "stderr:"+res.Executable)
		}
	}
	return res
}

// Close stops recording and refuses further runs. It returns the recorded
// invocations in call order, whether any redaction failed, and the truncated
// streams ("stdout:<tool>"), sorted.
func (r *RecordingRunner) Close() ([]trustfreeze.ToolInvocation, bool, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	tr := append([]string(nil), r.truncated...)
	sort.Strings(tr)
	return append([]trustfreeze.ToolInvocation(nil), r.invocations...), r.redactionFailed, tr
}

// ArgSecrets returns every secret value that was redacted from a command
// argument during this run. The engine feeds them to redact.WithSecrets for
// its final pass over the probe result, so a probe cannot persist an
// argument secret by copying it into another field. The values stay in
// memory; they must never be persisted or logged.
func (r *RecordingRunner) ArgSecrets() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.argSecrets...)
}
