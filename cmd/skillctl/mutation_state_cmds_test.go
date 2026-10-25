package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/mutationstate"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

func newMutationStateCLIFixture(t *testing.T) installableFixture {
	t.Helper()
	f := buildInstallableFixture(t)
	managedEvidenceRoots(t, f, true, "closed")
	// The older local-age regression helper enrolls its own baseline. This new
	// home deliberately starts without any durable state for the same pinned root.
	f.home = t.TempDir()
	return f
}

func mutationCLIList(t *testing.T, f installableFixture, name string, epoch int, issued time.Time) string {
	t.Helper()
	list, err := verify.NewSignedRevocationList(f.regURL, issued.Format(time.RFC3339Nano), epoch, nil, f.regPriv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.dir, name+".json")
	writeJSON(t, path, list)
	return path
}

func mutationCLI(t *testing.T, binary string, f installableFixture, want int, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Env = append(os.Environ(), "HOME="+f.home, "USERPROFILE="+f.home, "M3C_TOKEN_STORE=file", "M3C_TEST_KEYCHAIN=0", "M3C_ER1_KEYCHAIN=off")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	if code != want {
		t.Fatalf("actual CLI %v exit=%d want=%d; stdout=%s stderr=%s", args, code, want, stdout.String(), stderr.String())
	}
	return stdout.Bytes()
}

func mutationStateCLI(t *testing.T, binary string, f installableFixture, want int, verb string, extra ...string) []byte {
	t.Helper()
	args := append([]string{"trust", "state", verb, "--home", f.home, "--trust-roots", f.trPath, "--registry", f.regURL}, extra...)
	return mutationCLI(t, binary, f, want, args...)
}

func enrollStateCLI(t *testing.T, binary string, f installableFixture, list string) mutationstate.Status {
	t.Helper()
	return decodeMutationStatus(t, mutationStateCLI(t, binary, f, 0, "enroll", "--profile", "local-operator-v1", "--confirm-local-trust", "--revocations", list), f)
}

func decodeMutationStatus(t *testing.T, raw []byte, f installableFixture) mutationstate.Status {
	t.Helper()
	var status mutationstate.Status
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatalf("actual CLI status not JSON: %v", err)
	}
	if status.Schema == "" || status.Registry != f.regURL || status.Epoch <= 0 || len(status.RootFingerprint) != 64 || len(status.EvidenceFingerprint) != 64 || status.IssuedAt.IsZero() || status.LastSeen.IsZero() {
		t.Fatalf("incomplete actual status: %+v", status)
	}
	return status
}

func assertMutationTargetAbsent(t *testing.T, f installableFixture) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(f.home, ".claude", "skills", "revo-demo")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused mutation changed target: %v", err)
	}
}

func TestMutationStateCLIEnrollmentAndRestart(t *testing.T) {
	binary := skillctlBin(t)
	f := newMutationStateCLIFixture(t)
	mutationStateCLI(t, binary, f, 22, "status")
	base := filepath.Join(f.home, ".claude", "mutation-state")
	if _, err := os.Lstat(base); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent status created store: %v", err)
	}
	list := mutationCLIList(t, f, "initial-list", 7, time.Now().UTC().Add(-time.Hour))
	mutationStateCLI(t, binary, f, 2, "enroll", "--profile", "local-operator-v1", "--revocations", list)
	if _, err := os.Lstat(base); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unconfirmed enrollment created store: %v", err)
	}
	first := enrollStateCLI(t, binary, f, list)
	assertMutationTargetAbsent(t, f)
	restarted := decodeMutationStatus(t, mutationStateCLI(t, binary, f, 0, "status"), f)
	if restarted != first {
		t.Fatalf("new CLI process lost history: first=%+v status=%+v", first, restarted)
	}
	mutationStateCLI(t, binary, f, 1, "enroll", "--profile", "local-operator-v1", "--confirm-local-trust", "--revocations", list)
	mutationStateCLI(t, binary, f, 2, "reset")
	mutationStateCLI(t, binary, f, 2, "enroll", "--force", "--profile", "local-operator-v1", "--confirm-local-trust", "--revocations", list)
	after := decodeMutationStatus(t, mutationStateCLI(t, binary, f, 0, "status"), f)
	if after != first {
		t.Fatal("refused reset/reenrollment modified history")
	}
}

func TestMutationStateCLIMissingHistoryDeniesThenEnrollmentEnablesInstall(t *testing.T) {
	binary := skillctlBin(t)
	f := newMutationStateCLIFixture(t)
	list := mutationCLIList(t, f, "fresh-list", 7, time.Now().UTC().Add(-time.Hour))
	args := []string{"install", "--json", "--bundle", f.skbPath, "--trust-roots", f.trPath, "--home", f.home, "--revocations", list}
	raw := mutationCLI(t, binary, f, 22, args...)
	var refused bundleVerifyResult
	if err := json.Unmarshal(raw, &refused); err != nil {
		t.Fatal(err)
	}
	if refused.OK || refused.ExitCode != 22 || refused.InstallPath != "" {
		t.Fatalf("missing state claimed installation: %+v", refused)
	}
	assertMutationTargetAbsent(t, f)
	enrollStateCLI(t, binary, f, list)
	raw = mutationCLI(t, binary, f, 0, args...)
	var installed bundleVerifyResult
	if err := json.Unmarshal(raw, &installed); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(f.home, ".claude", "skills", "revo-demo")
	if !installed.OK || installed.ExitCode != 0 || installed.InstallPath != target || installed.Digest != f.digest {
		t.Fatalf("enrolled install contract differs: %+v", installed)
	}
	if body, err := os.ReadFile(filepath.Join(target, "SKILL.md")); err != nil || len(body) == 0 {
		t.Fatalf("successful enrolled install missing: %v", err)
	}
}

func TestMutationStateCLIRecordLossDoesNotReenroll(t *testing.T) {
	binary := skillctlBin(t)
	f := newMutationStateCLIFixture(t)
	list := mutationCLIList(t, f, "fresh-list", 7, time.Now().UTC().Add(-time.Hour))
	enrollStateCLI(t, binary, f, list)
	base := filepath.Join(f.home, ".claude", "mutation-state")
	var records []string
	if err := filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && entry.Name() == "record.json" {
			records = append(records, path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected single state record, got %d", len(records))
	}
	if err := os.Remove(records[0]); err != nil {
		t.Fatal(err)
	}
	mutationStateCLI(t, binary, f, 22, "status")
	mutationCLI(t, binary, f, 22, "install", "--json", "--bundle", f.skbPath, "--trust-roots", f.trPath, "--home", f.home, "--revocations", list)
	assertMutationTargetAbsent(t, f)
	mutationStateCLI(t, binary, f, 1, "enroll", "--profile", "local-operator-v1", "--confirm-local-trust", "--revocations", list)
	if _, err := os.Lstat(records[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lost record implicitly recreated: %v", err)
	}
}

func TestMutationStateCLIAdoptionFloorsPersist(t *testing.T) {
	binary := skillctlBin(t)
	f := newMutationStateCLIFixture(t)
	now := time.Now().UTC()
	initial := mutationCLIList(t, f, "initial-list", 7, now.Add(-time.Hour))
	first := enrollStateCLI(t, binary, f, initial)
	for _, tc := range []struct {
		name   string
		epoch  int
		issued time.Time
	}{
		{"older-epoch", 6, now.Add(-time.Minute)},
		{"backdated-issuance", 8, now.Add(-2 * time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			list := mutationCLIList(t, f, tc.name, tc.epoch, tc.issued)
			mutationStateCLI(t, binary, f, 22, "adopt", "--revocations", list)
			status := decodeMutationStatus(t, mutationStateCLI(t, binary, f, 0, "status"), f)
			if status != first {
				t.Fatal("denied adoption changed history")
			}
		})
	}
	fresh := mutationCLIList(t, f, "newer-list", 8, now.Add(-time.Minute))
	adopted := decodeMutationStatus(t, mutationStateCLI(t, binary, f, 0, "adopt", "--revocations", fresh), f)
	if adopted.Epoch != 8 || adopted.RootFingerprint != first.RootFingerprint || adopted.EvidenceFingerprint == first.EvidenceFingerprint || adopted.LastSeen.Before(first.LastSeen) {
		t.Fatalf("adoption did not advance expected state: %+v", adopted)
	}
	persisted := decodeMutationStatus(t, mutationStateCLI(t, binary, f, 0, "status"), f)
	if persisted != adopted {
		t.Fatal("new CLI process lost adopted history")
	}
	assertMutationTargetAbsent(t, f)
}
