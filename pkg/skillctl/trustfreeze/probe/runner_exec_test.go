package probe

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

const testSecret = "s3cr3t-ZXCVBNM-0123456789"

// TestExecRunnerTimeoutKillsChildAndGrandchild: TF02-AC1. A timed-out tool
// ends without leaving its child or a grandchild behind. The grandchild
// shares the stdout pipe, so without the process-group kill the run would
// hang until WaitDelay and report io_not_closed instead of timeout.
func TestExecRunnerTimeoutKillsChildAndGrandchild(t *testing.T) {
	t.Setenv(helperEnv, "spawn")
	r := &ExecRunner{}
	clock := trustfreeze.SystemClock{}
	begin := clock.Now()
	const timeout = 3 * time.Second
	res := r.Run(context.Background(), CommandRequest{
		Executable:   helperPath(t),
		EnvAllowlist: []string{helperEnv},
		Timeout:      timeout,
	})
	elapsed := clock.Now().Sub(begin)
	out := string(res.Stdout.Bytes())

	if !res.TimedOut || !errors.Is(res.Err, ErrTimeout) {
		t.Fatalf("want a timeout, got TimedOut=%v Err=%v stdout=%q", res.TimedOut, res.Err, out)
	}
	if res.ExitCode != -1 {
		t.Fatalf("exit code %d, want -1 for a killed process", res.ExitCode)
	}
	if elapsed >= timeout+DefaultWaitDelay {
		t.Fatalf("run took %s: the pipes were only closed by WaitDelay, the group was not killed", elapsed)
	}
	if inv := res.Invocation(); !inv.TimedOut || inv.Error == "" {
		t.Fatalf("invocation does not record the timeout: %+v", inv)
	}
	childPID, err := strconv.Atoi(lineValue(out, "child"))
	if err != nil {
		t.Fatalf("no child pid in stdout %q", out)
	}
	if !waitGone(childPID) {
		t.Fatalf("child %d still exists after the run", childPID)
	}
	if skipGrandchild(t) {
		return
	}
	gcPID, err := strconv.Atoi(lineValue(out, "grandchild"))
	if err != nil {
		t.Fatalf("no grandchild pid in stdout %q", out)
	}
	if !waitGone(gcPID) {
		t.Fatalf("grandchild %d survived the timeout (process group not killed)", gcPID)
	}
}

// waitGone polls until pid no longer exists (a killed orphan is reaped by
// init shortly after its death).
func waitGone(pid int) bool {
	clock := trustfreeze.SystemClock{}
	deadline := clock.Now().Add(5 * time.Second)
	for clock.Now().Before(deadline) {
		if !processAlive(pid) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return !processAlive(pid)
}

// TestExecRunnerOutputLimit: TF02-AC2. Output over the limit is drained and
// counted, the kept part ends at a whole line, and the result says it was
// truncated.
func TestExecRunnerOutputLimit(t *testing.T) {
	t.Setenv(helperEnv, "flood")
	res := (&ExecRunner{}).Run(context.Background(), CommandRequest{
		Executable:     helperPath(t),
		EnvAllowlist:   []string{helperEnv},
		Timeout:        30 * time.Second,
		MaxStdoutBytes: 1000,
	})
	if res.Err != nil || res.ExitCode != 0 {
		t.Fatalf("run failed: %v exit %d", res.Err, res.ExitCode)
	}
	out := res.Stdout.Bytes()
	if !res.StdoutTruncated {
		t.Fatal("StdoutTruncated not set")
	}
	if res.StdoutBytes != 2000*int64(len("line 0000 of flood output\n")) {
		t.Fatalf("StdoutBytes %d does not count every byte written", res.StdoutBytes)
	}
	if len(out) == 0 || len(out) > 1000 || out[len(out)-1] != '\n' {
		t.Fatalf("kept %d bytes, last %q: want at most 1000 bytes ending at a line", len(out), out[len(out)-1:])
	}
	inv := res.Invocation()
	if !inv.StdoutTruncated || inv.StdoutBytes != res.StdoutBytes {
		t.Fatalf("invocation lost the truncation: %+v", inv)
	}
}

// TestExecRunnerNoShellEnvAndRedaction: arguments reach the tool literally
// (no shell), the environment is only the allowlist plus LC_ALL=C and
// TZ=UTC0 (neither can be overridden through the allowlist), and a
// secret in an argument, in stdout and in stderr is redacted in the result
// (SPEC-0467 R2, R5, TF02-AC3).
func TestExecRunnerNoShellEnvAndRedaction(t *testing.T) {
	t.Setenv(helperEnv, "echo")
	t.Setenv("TF_PROBE_TEST_SECRET", testSecret)
	t.Setenv("TF_PROBE_TEST_NOT_ALLOWED", "leak")
	t.Setenv("LC_ALL", "de_DE.UTF-8")
	t.Setenv("TZ", "Europe/Berlin")
	args := []string{"$(echo pwned)", "a;b|c", "*", "--token", testSecret}
	res := (&ExecRunner{}).Run(context.Background(), CommandRequest{
		Executable:   helperPath(t),
		Args:         args,
		EnvAllowlist: []string{helperEnv, "TF_PROBE_TEST_SECRET", "LC_ALL", "TZ"},
		Timeout:      30 * time.Second,
	})
	if res.Err != nil || res.ExitCode != 0 {
		t.Fatalf("run failed: %v exit %d", res.Err, res.ExitCode)
	}
	out := string(res.Stdout.Bytes())
	for _, want := range []string{"ARG $(echo pwned)\n", "ARG a;b|c\n", "ARG *\n", "ARG --token\n", "ENV LC_ALL=C\n", "ENV TZ=UTC0\n", "ENV " + helperEnv + "=echo\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if name, ok := strings.CutPrefix(line, "ENV "); ok {
			k, _, _ := strings.Cut(name, "=")
			switch k {
			case helperEnv, "TF_PROBE_TEST_SECRET", "LC_ALL", "TZ", "SYSTEMROOT":
			default:
				t.Errorf("unexpected variable in the child environment: %q", line)
			}
		}
	}
	all := out + string(res.Stderr.Bytes()) + strings.Join(res.Args, " ") + res.Invocation().Error
	if strings.Contains(all, testSecret) {
		t.Fatalf("secret survived redaction:\nstdout %q\nstderr %q\nargs %q", out, res.Stderr.Bytes(), res.Args)
	}
	if res.Args[3] != "--token" || res.Args[4] != "[REDACTED:token]" {
		t.Fatalf("args %q", res.Args)
	}
	if !strings.Contains(string(res.Stderr.Bytes()), "password=[REDACTED:") {
		t.Fatalf("stderr %q", res.Stderr.Bytes())
	}
	// The tool echoed the bare secret argument on a line of its own; only the
	// argument context identifies it, so the runner removes it from stdout.
	if !strings.Contains(out, "ARG [REDACTED:arg_secret]\n") {
		t.Fatalf("echoed argument secret not removed from stdout:\n%s", out)
	}
}

// TestExecRunnerNonZeroExit: a non-zero exit is a tool outcome, not a runner
// error; the output is kept.
func TestExecRunnerNonZeroExit(t *testing.T) {
	t.Setenv(helperEnv, "exit3")
	res := (&ExecRunner{}).Run(context.Background(), CommandRequest{Executable: helperPath(t), EnvAllowlist: []string{helperEnv}, Timeout: 30 * time.Second})
	if res.Err != nil || res.ExitCode != 3 || res.OK() {
		t.Fatalf("got Err=%v exit=%d", res.Err, res.ExitCode)
	}
	if string(res.Stdout.Bytes()) != "partial output\n" {
		t.Fatalf("stdout %q", res.Stdout.Bytes())
	}
}

// TestExecRunnerLookPath: bare names resolve only in the search path;
// relative paths are refused; a missing tool is tool_missing (SPEC-0467 R3).
func TestExecRunnerLookPath(t *testing.T) {
	dir := t.TempDir()
	r := &ExecRunner{SearchPath: []string{dir, "relative/dir"}}
	if _, err := r.LookPath("definitely-not-a-tool"); !errors.Is(err, ErrToolMissing) {
		t.Fatalf("missing tool: %v", err)
	}
	for _, bad := range []string{"./tool", "sub/tool", `sub\tool`, ""} {
		if _, err := r.LookPath(bad); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("LookPath(%q) = %v, want invalid_request", bad, err)
		}
	}
	self := helperPath(t)
	if p, err := r.LookPath(self); err != nil || p == "" {
		t.Fatalf("absolute path: %q %v", p, err)
	}
	res := r.Run(context.Background(), CommandRequest{Executable: "definitely-not-a-tool", Args: []string{"x"}})
	if !errors.Is(res.Err, ErrToolMissing) || res.ExitCode != -1 || res.Invocation().Name != "definitely-not-a-tool" {
		t.Fatalf("run of a missing tool: %+v", res)
	}
	res = r.Run(context.Background(), CommandRequest{Executable: self, Args: []string{"a\x00b"}})
	if !errors.Is(res.Err, ErrInvalidRequest) {
		t.Fatalf("NUL argument: %v", res.Err)
	}
}

// TestExecRunnerCanceledContext: a done context starts nothing.
func TestExecRunnerCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := (&ExecRunner{}).Run(ctx, CommandRequest{Executable: helperPath(t)})
	if !errors.Is(res.Err, ErrCanceled) {
		t.Fatalf("got %v", res.Err)
	}
}

// TestDefaultSearchPath pins the fixed system directories. Linux carries
// /snap/bin as well, and last: Ubuntu installs the entry point of a snap
// there, and a bastion measured on 2026-09-23 had its only docker at
// /snap/bin/docker, which the four classic directories do not cover. macOS
// has no snapd, so its list is unchanged.
func TestDefaultSearchPath(t *testing.T) {
	if got := strings.Join(DefaultSearchPath("linux"), ":"); got != "/usr/bin:/bin:/usr/sbin:/sbin:/snap/bin" {
		t.Fatalf("linux search path %q", got)
	}
	if got := strings.Join(DefaultSearchPath("darwin"), ":"); got != "/usr/bin:/bin:/usr/sbin:/sbin" {
		t.Fatalf("darwin search path %q", got)
	}
	// Every entry stays an absolute system directory: nothing user writable
	// and nothing from the caller's environment enters the list.
	for _, dir := range DefaultSearchPath("linux") {
		if !strings.HasPrefix(dir, "/") {
			t.Fatalf("relative directory %q in the linux search path", dir)
		}
	}
	// On Windows the OS reports the directory (often ending in system32),
	// elsewhere %SystemRoot% or C:\Windows names it.
	if got := DefaultSearchPath("windows"); len(got) != 1 || !strings.HasSuffix(strings.ToLower(got[0]), "system32") {
		t.Fatalf("windows search path %q", got)
	}
}

// TestRunnersReportTheirSearchDirs: a probe that has to say where it looked
// asks the runner, so the sentence it writes is about the directories that
// were really searched. A runner that does not report them yields nothing,
// never a default list.
func TestRunnersReportTheirSearchDirs(t *testing.T) {
	exec := NewExecRunner()
	if got := strings.Join(SearchDirs(exec), ":"); got != strings.Join(DefaultSearchPath(runtime.GOOS), ":") {
		t.Errorf("exec runner reports %q", got)
	}
	dirs := exec.SearchDirs()
	if len(dirs) == 0 {
		t.Fatal("the exec runner reports no search directory at all")
	}
	dirs[0] = "/tampered"
	if SearchDirs(exec)[0] == "/tampered" {
		t.Error("the reported list aliases the runner's own search path")
	}
	if got := SearchDirs(NewFakeRunner()); len(got) != 0 {
		t.Errorf("a fake without declared directories reports %v", got)
	}
	if got := strings.Join(SearchDirs(NewFakeRunner().WithSearchDirs("/usr/bin", "/snap/bin")), ":"); got != "/usr/bin:/snap/bin" {
		t.Errorf("declared directories come back as %q", got)
	}
	if got := SearchDirs(notReportingRunner{}); got != nil {
		t.Errorf("a runner that does not implement the interface reports %v", got)
	}
}

// notReportingRunner is a CommandRunner without a search path to report.
type notReportingRunner struct{}

func (notReportingRunner) LookPath(string) (string, error) { return "", ErrToolMissing }
func (notReportingRunner) Run(context.Context, CommandRequest) CommandResult {
	return CommandResult{}
}

// TestExecRunnerFindsABinaryInALaterSearchDir: LookPath walks the list in
// order, so a directory appended to it (as /snap/bin was) really is
// searched, and an earlier directory still wins.
func TestExecRunnerFindsABinaryInALaterSearchDir(t *testing.T) {
	first, last := t.TempDir(), t.TempDir()
	tool := filepath.Join(last, "trustfreeze-fake-tool")
	// #nosec G306 -- a test fixture in t.TempDir() that has to be executable.
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("write: %v", err)
	}
	r := &ExecRunner{SearchPath: []string{first, last}}
	got, err := r.LookPath("trustfreeze-fake-tool")
	if err != nil || got != tool {
		t.Fatalf("LookPath = %q, %v; want %q", got, err, tool)
	}
	shadow := filepath.Join(first, "trustfreeze-fake-tool")
	// #nosec G306 -- same fixture, in the earlier directory.
	if err := os.WriteFile(shadow, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got, err := r.LookPath("trustfreeze-fake-tool"); err != nil || got != shadow {
		t.Fatalf("LookPath = %q, %v; want the earlier directory %q", got, err, shadow)
	}
}

// TestRunnersRefuseElevationHelpers: SPEC-0467 R6, TF02-AC5. Both runners
// refuse an elevation helper by bare name, absolute path, any case and a
// Windows suffix, before anything starts.
func TestRunnersRefuseElevationHelpers(t *testing.T) {
	refused := []string{"sudo", "su", "doas", "pkexec", "run0", "runuser", "runas",
		"/usr/bin/sudo", "/bin/su", "/usr/bin/pkexec", `C:\Windows\System32\runas.exe`, "SUDO", "sudo.exe"}
	for _, exe := range refused {
		for name, r := range map[string]CommandRunner{
			"exec": &ExecRunner{SearchPath: []string{t.TempDir()}},
			"fake": NewFakeRunner().Script(exe, nil, FakeResponse{Stdout: []byte("ran\n")}),
		} {
			res := r.Run(context.Background(), CommandRequest{Executable: exe})
			if !errors.Is(res.Err, ErrInvalidRequest) || res.ExitCode != -1 || len(res.Stdout.Bytes()) != 0 {
				t.Errorf("%s runner, %q: Err=%v exit=%d stdout=%q, want invalid_request before start", name, exe, res.Err, res.ExitCode, res.Stdout.Bytes())
			}
		}
	}
	// Names that merely contain a helper name are not refused.
	for _, exe := range []string{"sudoers-check", "resume", "subst", "/usr/bin/sum", "pkexec-doc"} {
		if isElevationHelper(exe) {
			t.Errorf("%q refused, want allowed", exe)
		}
	}
	// A fake tool resolved to a helper path is refused as well.
	f := NewFakeRunner().AddTool("innocent", "/usr/bin/sudo").Script("innocent", nil, FakeResponse{Stdout: []byte("ran\n")})
	if res := f.Run(context.Background(), CommandRequest{Executable: "innocent"}); !errors.Is(res.Err, ErrInvalidRequest) {
		t.Errorf("fake tool resolved to sudo: %v", res.Err)
	}
}

// TestExecRunnerWorkingDirDefault: an empty WorkingDir runs the tool in the
// filesystem root (the Windows directory on Windows), not in the current
// directory of the caller.
func TestExecRunnerWorkingDirDefault(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv(helperEnv, "pwd")
	res := (&ExecRunner{}).Run(context.Background(), CommandRequest{Executable: helperPath(t), EnvAllowlist: []string{helperEnv}, Timeout: 30 * time.Second})
	if res.Err != nil || res.ExitCode != 0 {
		t.Fatalf("run failed: %v exit %d", res.Err, res.ExitCode)
	}
	got := strings.TrimSpace(lineValue(string(res.Stdout.Bytes()), "cwd"))
	want := defaultWorkingDir()
	if !strings.EqualFold(filepath.Clean(got), filepath.Clean(want)) {
		t.Fatalf("working directory %q, want %q", got, want)
	}
}

// TestExecRunnerCleanupKillsLeftoverGrandchild: TF02-AC1 after a normal
// exit. The tool starts a grandchild that does not share its output, exits
// 0, and the grandchild must not outlive the run.
func TestExecRunnerCleanupKillsLeftoverGrandchild(t *testing.T) {
	t.Setenv(helperEnv, "spawn-exit")
	res := (&ExecRunner{}).Run(context.Background(), CommandRequest{Executable: helperPath(t), EnvAllowlist: []string{helperEnv}, Timeout: 30 * time.Second})
	out := string(res.Stdout.Bytes())
	if res.Err != nil || res.ExitCode != 0 {
		t.Fatalf("run failed: %v exit %d stdout %q", res.Err, res.ExitCode, out)
	}
	gcPID, err := strconv.Atoi(lineValue(out, "grandchild"))
	if err != nil {
		t.Fatalf("no grandchild pid in stdout %q", out)
	}
	if !waitGone(gcPID) {
		t.Fatalf("grandchild %d survived the run", gcPID)
	}
}
