package main

// runner.go — execute the REAL skillctl binary as a subprocess, capture its
// stdout/stderr and the numbered exit code, and stream output lines to a sink.
//
// This is the honesty spine of the demo: every LIVE scenario verdict is the
// real skillctl process exit code, never a value we invent. The sandbox sets up
// hermetic key material and bundles; the runner only ever OBSERVES skillctl.

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

// RunResult is one skillctl invocation's fully-captured outcome.
type RunResult struct {
	Args     []string
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error // non-nil only for exec failures (binary missing, etc.), not for non-zero exits
}

// Runner execs a fixed skillctl binary with a hermetic environment (HOME points
// at the sandbox so skillctl reads/writes a throwaway ~/.claude, never the
// presenter's real one).
type Runner struct {
	Skillctl string   // absolute path to the real skillctl(.exe)
	Home     string   // sandbox HOME; injected as HOME + USERPROFILE
	ExtraEnv []string // additional KEY=VALUE entries (rarely needed)
}

// Run executes `skillctl <args...>` with an optional stdin string. It streams
// each output line through emit (prefixed by stream name) as it is produced,
// and returns the complete captured result. A non-zero exit is NOT an error —
// the exit code is the whole point.
func (r *Runner) Run(emit func(stream, line string), stdin string, args ...string) RunResult {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, r.Skillctl, args...)
	cmd.Env = r.env()
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	var outBuf, errBuf bytes.Buffer
	outPipe, _ := cmd.StdoutPipe()
	errPipe, _ := cmd.StderrPipe()

	res := RunResult{Args: args}
	if err := cmd.Start(); err != nil {
		res.Err = err
		return res
	}

	done := make(chan struct{}, 2)
	go streamPipe(outPipe, &outBuf, "stdout", emit, done)
	go streamPipe(errPipe, &errBuf, "stderr", emit, done)
	<-done
	<-done

	err := cmd.Wait()
	res.Stdout = outBuf.String()
	res.Stderr = errBuf.String()
	res.ExitCode = exitCodeOf(err)
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			res.Err = err // a genuine exec failure, not a non-zero exit
		}
	}
	return res
}

func streamPipe(r interface{ Read([]byte) (int, error) }, buf *bytes.Buffer, stream string, emit func(string, string), done chan<- struct{}) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		buf.WriteString(line)
		buf.WriteByte('\n')
		if emit != nil {
			emit(stream, line)
		}
	}
	done <- struct{}{}
}

// exitCodeOf extracts the numbered process exit code from a Wait() error.
// nil → 0; *exec.ExitError → its code; anything else → -1 (exec failure).
func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}

// env builds the hermetic environment: the real environment with HOME (and the
// Windows USERPROFILE) redirected into the sandbox, and XDG_CONFIG_HOME cleared
// so skillctl's ~/.claude resolution lands inside the sandbox on every OS.
func (r *Runner) env() []string {
	base := os.Environ()
	out := make([]string, 0, len(base)+4)
	for _, kv := range base {
		k := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k = kv[:i]
		}
		switch k {
		case "HOME", "USERPROFILE", "XDG_CONFIG_HOME":
			continue // we set these ourselves
		}
		out = append(out, kv)
	}
	out = append(out,
		"HOME="+r.Home,
		"USERPROFILE="+r.Home,
		"XDG_CONFIG_HOME=",
	)
	out = append(out, r.ExtraEnv...)
	return out
}
