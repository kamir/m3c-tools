package probe

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"
)

// TestFakeRunnerScripted covers every scripted outcome of SPEC-0467
// section 5.1: success,
// missing executable, permission denied (at lookup and at start), timeout,
// oversized output, non-zero exit and an unscripted command.
func TestFakeRunnerScripted(t *testing.T) {
	big := bytes.Repeat([]byte("0123456789abcdef\n"), 100) // 1700 bytes
	f := NewFakeRunner().
		Script("uname", []string{"-r"}, FakeResponse{Stdout: []byte("6.8.0-generic\n"), Duration: 7 * time.Millisecond}).
		Script("slow", nil, FakeResponse{TimedOut: true, Stdout: []byte("started\n")}).
		Script("chatty", nil, FakeResponse{Stdout: big}).
		Script("fails", []string{"x"}, FakeResponse{ExitCode: 4, Stderr: []byte("bad x\n")}).
		Script("blocked", nil, FakeResponse{PermissionDenied: true, ErrMessage: "operation not permitted"}).
		DenyTool("noexec", "/fake/bin/noexec")
	ctx := context.Background()

	cases := []struct {
		name     string
		req      CommandRequest
		wantErr  error
		wantExit int
		check    func(t *testing.T, r CommandResult)
	}{
		{"success", CommandRequest{Executable: "uname", Args: []string{"-r"}}, nil, 0, func(t *testing.T, r CommandResult) {
			if string(r.Stdout.Bytes()) != "6.8.0-generic\n" || r.Path != "/fake/bin/uname" || r.Duration != 7*time.Millisecond || !r.OK() {
				t.Fatalf("%+v", r)
			}
		}},
		{"missing", CommandRequest{Executable: "nft", Args: []string{"--json", "list", "ruleset"}}, ErrToolMissing, -1, nil},
		{"lookup_denied", CommandRequest{Executable: "noexec"}, ErrPermissionDenied, -1, nil},
		{"start_denied", CommandRequest{Executable: "blocked"}, ErrPermissionDenied, -1, func(t *testing.T, r CommandResult) {
			if !strings.Contains(r.Err.Error(), "operation not permitted") {
				t.Fatalf("error %q", r.Err)
			}
		}},
		{"timeout", CommandRequest{Executable: "slow"}, ErrTimeout, -1, func(t *testing.T, r CommandResult) {
			if !r.TimedOut || string(r.Stdout.Bytes()) != "started\n" {
				t.Fatalf("%+v", r)
			}
		}},
		{"oversized", CommandRequest{Executable: "chatty", MaxStdoutBytes: 100}, nil, 0, func(t *testing.T, r CommandResult) {
			out := r.Stdout.Bytes()
			if !r.StdoutTruncated || r.StdoutBytes != int64(len(big)) || len(out) != 85 || out[len(out)-1] != '\n' {
				t.Fatalf("truncated=%v bytes=%d kept=%d", r.StdoutTruncated, r.StdoutBytes, len(out))
			}
		}},
		{"nonzero", CommandRequest{Executable: "fails", Args: []string{"x"}}, nil, 4, func(t *testing.T, r CommandResult) {
			if r.OK() || string(r.Stderr.Bytes()) != "bad x\n" {
				t.Fatalf("%+v", r)
			}
		}},
		{"unscripted", CommandRequest{Executable: "uname", Args: []string{"-a"}}, ErrNotScripted, -1, nil},
		{"invalid", CommandRequest{Executable: ""}, ErrInvalidRequest, -1, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := f.Run(ctx, tc.req)
			if tc.wantErr == nil && r.Err != nil || tc.wantErr != nil && !errors.Is(r.Err, tc.wantErr) {
				t.Fatalf("err %v, want %v", r.Err, tc.wantErr)
			}
			if r.ExitCode != tc.wantExit {
				t.Fatalf("exit %d, want %d", r.ExitCode, tc.wantExit)
			}
			if tc.wantErr != nil && ErrorClass(r.Err) != tc.wantErr.Error() {
				t.Fatalf("class %q, want %q", ErrorClass(r.Err), tc.wantErr.Error())
			}
			if tc.check != nil {
				tc.check(t, r)
			}
		})
	}
	if n := len(f.Calls()); n != len(cases)-1 {
		t.Fatalf("%d calls recorded, want %d (invalid requests are not recorded)", n, len(cases)-1)
	}
}

// TestFakeRunnerRedacts: the fake uses the same redaction path as the real
// runner, so probe tests against it prove the persisted bytes (TF02-AC3).
func TestFakeRunnerRedacts(t *testing.T) {
	f := NewFakeRunner().Script("tool", []string{"--api-key", testSecret}, FakeResponse{
		Stdout:   []byte("echo " + testSecret + "\n"),
		Stderr:   []byte("Authorization: Bearer " + testSecret + "\n"),
		ExitCode: 1, ErrMessage: "unused",
	})
	r := f.Run(context.Background(), CommandRequest{Executable: "tool", Args: []string{"--api-key", testSecret}})
	all := string(r.Stdout.Bytes()) + string(r.Stderr.Bytes()) + strings.Join(r.Args, " ")
	if strings.Contains(all, testSecret) {
		t.Fatalf("secret survived: %q", all)
	}
	if r.Redactions.Total() < 3 {
		t.Fatalf("redaction log %v", r.Redactions)
	}
}

// TestFakeFiles covers the in-memory file reader.
func TestFakeFiles(t *testing.T) {
	ff := FakeFiles{Files: map[string][]byte{"/etc/a": []byte("x")}, Errs: map[string]error{"/etc/b": fs.ErrPermission}}
	if b, err := ff.ReadFile("/etc/a"); err != nil || string(b) != "x" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := ff.ReadFile("/etc/b"); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("%v", err)
	}
	if _, err := ff.ReadFile("/etc/c"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%v", err)
	}
}
