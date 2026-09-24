package probe

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"
)

// helperEnv selects a helper mode when the test binary runs as a child of
// an ExecRunner test. The runner passes it through its env allowlist.
const helperEnv = "TF_PROBE_TEST_HELPER"

// TestMain turns the test binary into a small fake tool when helperEnv is
// set, so ExecRunner tests need no installed tool (SPEC-0467 R9).
func TestMain(m *testing.M) {
	if mode := os.Getenv(helperEnv); mode != "" {
		os.Exit(runHelper(mode))
	}
	os.Exit(m.Run())
}

func runHelper(mode string) int {
	switch mode {
	case "echo":
		// Every argument on its own line, then the environment, sorted.
		for _, a := range os.Args[1:] {
			fmt.Printf("ARG %s\n", a)
		}
		env := os.Environ()
		sort.Strings(env)
		for _, e := range env {
			fmt.Printf("ENV %s\n", e)
		}
		fmt.Fprintf(os.Stderr, "stderr password=%s\n", os.Getenv("TF_PROBE_TEST_SECRET"))
		return 0
	case "exit3":
		fmt.Println("partial output")
		return 3
	case "flood":
		for i := 0; i < 2000; i++ {
			fmt.Printf("line %04d of flood output\n", i)
		}
		return 0
	case "spawn":
		// A child that starts a grandchild sharing its stdout, reports both
		// pids and then hangs until killed.
		fmt.Printf("child=%d\n", os.Getpid())
		if code := startSleeper(true); code != 0 {
			return code
		}
		time.Sleep(time.Hour)
		return 0
	case "spawn-exit":
		// A child that starts a grandchild with its own output, reports its
		// pid and exits 0, leaving the grandchild behind.
		return startSleeper(false)
	case "pwd":
		wd, err := os.Getwd()
		if err != nil {
			return 2
		}
		fmt.Printf("cwd=%s\n", wd)
		return 0
	case "sleep":
		time.Sleep(time.Hour)
		return 0
	}
	fmt.Fprintf(os.Stderr, "unknown helper mode %q\n", mode)
	return 2
}

// startSleeper starts the test binary as a sleeping grandchild and prints
// its pid. With shareStdout the grandchild holds the stdout pipe open.
func startSleeper(shareStdout bool) int {
	self, err := os.Executable()
	if err != nil {
		return 2
	}
	gc := exec.Command(self)
	gc.Env = []string{helperEnv + "=sleep"}
	if shareStdout {
		gc.Stdout = os.Stdout
	}
	if err := gc.Start(); err != nil {
		fmt.Printf("grandchild start failed: %v\n", err)
		return 2
	}
	fmt.Printf("grandchild=%d\n", gc.Process.Pid)
	return 0
}

// helperPath returns the absolute path of the test binary.
func helperPath(t *testing.T) string {
	t.Helper()
	p, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// lineValue returns the value after "key=" on the first matching line.
func lineValue(out, key string) string {
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(l, key+"="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
