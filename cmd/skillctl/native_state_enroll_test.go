package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func c33EnrollArgs(f *qaNativeSourceCLI, evidence string) []string {
	return []string{"trust", "native-state", "enroll", "--enterprise-profile", f.base.path, "--enterprise-profile-sha256", f.base.pin, "--home", f.base.home, "--evidence", evidence, "--json"}
}

func c33EnrollEvidence(t *testing.T, f *qaNativeSourceCLI) (string, []byte) {
	t.Helper()
	raw := qaNativeSourceCLIProof(t, f.base.revocationKey, 1, time.Now().UTC().Add(-time.Minute))
	path := filepath.Join(t.TempDir(), "initial-evidence.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path, raw
}

func TestTrustNativeStateEnrollActualCLI(t *testing.T) {
	if mode := os.Getenv("M3C_C33_ENROLL_OUTPUT_CHILD"); mode != "" {
		var args []string
		if err := json.Unmarshal([]byte(os.Getenv("M3C_C33_ENROLL_OUTPUT_ARGS")), &args); err != nil {
			t.Fatal(err)
		}
		var diagnostic bytes.Buffer
		if code := runNativeStateEnroll(args, qaNativeSourceFailedWriter{short: mode == "short"}, &diagnostic); code != 1 || !strings.Contains(diagnostic.String(), "may already be enrolled") {
			t.Fatalf("enrollment output fault hid persistence: code=%d diagnostic=%q", code, diagnostic.String())
		}
		return
	}
	binary, flags, faultChild := qaNativeSourceBinary(t)
	t.Run("explicit-first-use-and-no-reenrollment", func(t *testing.T) {
		f := qaNativeSourceCLIFixture(t)
		path, raw := c33EnrollEvidence(t, f)
		before := qaNativeSourceArtifactInventory(t, f.base.home)
		code, output := qaNativeSourceRun(t, binary, flags, f, c33EnrollArgs(f, path))
		if code != 0 {
			t.Fatalf("actual enrollment refused genuine signed local evidence: %d %s", code, output)
		}
		var result map[string]any
		if err := json.Unmarshal([]byte(output), &result); err != nil {
			t.Fatal("actual enrollment status is not JSON", err)
		}
		digest := sha256.Sum256(raw)
		status, err := f.journal(t).Status(context.Background())
		if err != nil || len(result) != 3 || result["epoch"] != float64(1) || result["history_authority_id"] != status.HistoryAuthorityID || result["evidence_sha256"] != hex.EncodeToString(digest[:]) || status.EvidenceDigest != result["evidence_sha256"] {
			t.Fatalf("enrollment output does not bind reopened signed history: %#v %v", result, err)
		}
		if !reflect.DeepEqual(before, qaNativeSourceArtifactInventory(t, f.base.home)) || f.requests.Load() != 0 || f.base.requests.Load() != 0 {
			t.Fatal("explicit local enrollment changed active artifacts or fetched a carrier/source")
		}
		persisted := nativeCLIQAInventory(t, f.base.home)
		if code, out := qaNativeSourceRun(t, binary, flags, f, c33EnrollArgs(f, path)); code != 22 {
			t.Fatalf("existing history was re-enrolled: %d %s", code, out)
		}
		if !reflect.DeepEqual(persisted, nativeCLIQAInventory(t, f.base.home)) {
			t.Fatal("refused re-enrollment changed persisted history")
		}
		var record string
		if err := filepath.WalkDir(f.base.home, func(path string, entry os.DirEntry, err error) error {
			if err == nil && !entry.IsDir() && entry.Name() == "state.record" {
				record = path
			}
			return err
		}); err != nil || record == "" {
			t.Fatal("enrollment record not found", err)
		}
		if err := os.Remove(record); err != nil {
			t.Fatal(err)
		}
		lost := nativeCLIQAInventory(t, f.base.home)
		if code, out := qaNativeSourceRun(t, binary, flags, f, c33EnrollArgs(f, path)); code != 22 {
			t.Fatalf("reserved history with lost record was silently repaired: %d %s", code, out)
		}
		if !reflect.DeepEqual(lost, nativeCLIQAInventory(t, f.base.home)) {
			t.Fatal("lost-record refusal silently recreated history")
		}
	})
	for _, name := range []string{"wrong-role", "malformed", "oversized", "empty", "directory", "symlink", "relative-evidence", "bad-pin", "empty-home", "force"} {
		t.Run(name, func(t *testing.T) {
			f := qaNativeSourceCLIFixture(t)
			path, _ := c33EnrollEvidence(t, f)
			want := 12
			switch name {
			case "wrong-role":
				if err := os.WriteFile(path, qaNativeSourceCLIProof(t, f.base.artifactKey, 1, time.Now().UTC()), 0600); err != nil {
					t.Fatal(err)
				}
			case "malformed":
				if err := os.WriteFile(path, []byte(`{"schema":`), 0600); err != nil {
					t.Fatal(err)
				}
			case "oversized", "empty":
				var raw []byte
				if name == "oversized" {
					raw = bytes.Repeat([]byte("x"), (1<<20)+1)
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				want = 1
			case "directory":
				path = t.TempDir()
				want = 1
			case "symlink":
				link := filepath.Join(t.TempDir(), "evidence-link")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal("synthetic evidence link prerequisite unavailable", err)
				}
				path, want = link, 1
			case "relative-evidence":
				path = "relative-evidence.json"
			}
			args := c33EnrollArgs(f, path)
			switch name {
			case "bad-pin":
				args[6] = strings.Repeat("0", 64)
			case "empty-home":
				args[8] = ""
			case "force":
				args = append(args, "--force")
				want = 2
			}
			before := nativeCLIQAInventory(t, f.base.home)
			code, output := qaNativeSourceRun(t, binary, flags, f, args)
			if code != want {
				t.Fatalf("enrollment negative %s code=%d want=%d output=%s", name, code, want, output)
			}
			if !reflect.DeepEqual(before, nativeCLIQAInventory(t, f.base.home)) || f.requests.Load() != 0 || f.base.requests.Load() != 0 {
				t.Fatal("refused bootstrap wrote history/artifacts or performed network I/O")
			}
		})
	}
	for _, mode := range []string{"error", "short"} {
		t.Run("persisted-before-output-"+mode, func(t *testing.T) {
			f := qaNativeSourceCLIFixture(t)
			path, _ := c33EnrollEvidence(t, f)
			args, err := json.Marshal(c33EnrollArgs(f, path)[3:])
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, faultChild, "-test.run=^TestTrustNativeStateEnrollActualCLI$")
			cmd.WaitDelay = time.Second
			cmd.Dir = f.base.project
			cmd.Env = qaNativeSourceEnv(nativeCLIQAEnv(f.base.home), "GOFLAGS", flags)
			cmd.Env = qaNativeSourceEnv(cmd.Env, "M3C_C33_ENROLL_OUTPUT_CHILD", mode)
			cmd.Env = qaNativeSourceEnv(cmd.Env, "M3C_C33_ENROLL_OUTPUT_ARGS", string(args))
			output, err := cmd.CombinedOutput()
			if err != nil || ctx.Err() != nil {
				t.Fatalf("fully trapped enrollment output helper failed: %v %s", err, output)
			}
			if status, err := f.journal(t).Status(context.Background()); err != nil || status.Epoch != 1 {
				t.Fatal("output failure was tested before actual durable enrollment", err)
			}
			if code, out := qaNativeSourceRun(t, binary, flags, f, c33EnrollArgs(f, path)); code != 22 || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatalf("output uncertainty allowed re-enrollment: %d %s", code, out)
			}
		})
	}
}
