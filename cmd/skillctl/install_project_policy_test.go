package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// enterpriseInstallFixtureArgs preserves explicit synthetic operator selection.
// It does not enroll history or change any signed fixture evidence.
func enterpriseInstallFixtureArgs(t *testing.T, f installableFixture) []string {
	t.Helper()
	roots, err := verify.Load(f.trPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(roots.Roots) != 1 || !roots.Roots[0].IsManaged() {
		return []string{"--trust-roots", f.trPath}
	}
	project, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	path, _ := enterpriseInstallFixtureProfile(t, f, project)
	return []string{"--enterprise-profile", path}
}

func enterpriseInstallFixtureProfile(t *testing.T, f installableFixture, project string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	runtimeRaw, err := json.Marshal(map[string]any{"schema": "m3c.skillctl.runtime-profile/v1", "project_root": project, "tools": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	runtimePath := filepath.Join(dir, "runtime.json")
	if err := os.WriteFile(runtimePath, runtimeRaw, 0600); err != nil {
		t.Fatal(err)
	}
	rootsRaw, err := os.ReadFile(f.trPath)
	if err != nil {
		t.Fatal(err)
	}
	ref := func(path string, raw []byte) map[string]string {
		sum := sha256.Sum256(raw)
		return map[string]string{"path": path, "sha256": hex.EncodeToString(sum[:])}
	}
	raw, err := json.Marshal(map[string]any{"schema": "m3c.enterprise-project-profile/v1", "project_root": project, "artifact_home": f.home, "registry_url": f.regURL, "allow_loopback_http": true, "artifact_trust": ref(f.trPath, rootsRaw), "revocation_trust": ref(f.trPath, rootsRaw), "runtime": ref(runtimePath, runtimeRaw)})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "project.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return path, hex.EncodeToString(sum[:])
}

func TestInstallEnterpriseProfileActualCLI(t *testing.T) {
	binary := skillctlBin(t)
	for _, tc := range []struct {
		name                                                string
		extra                                               []string
		change, foreignHome, foreignProject, missingProfile bool
		want                                                int
	}{
		{name: "valid", want: 0},
		{name: "missing_profile", missingProfile: true, want: 12},
		{name: "profile_bytes_changed", change: true, want: 12},
		{name: "foreign_home", foreignHome: true, want: 12},
		{name: "foreign_project", foreignProject: true, want: 12},
		{name: "ignore_deps", extra: []string{"--ignore-deps"}, want: 2},
		{name: "allow_yellow", extra: []string{"--allow-yellow"}, want: 2},
		{name: "governance_override", extra: []string{"--governance-min", "green"}, want: 2},
		{name: "trust_roots_override", extra: []string{"--trust-roots", "missing-roots"}, want: 2},
		{name: "foreign_registry", extra: []string{"--registry", "https://foreign.invalid/api/skills"}, want: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := buildInstallableFixture(t)
			root := managedEvidenceRoots(t, f, true, "closed")
			project := t.TempDir()
			profile, pin := enterpriseInstallFixtureProfile(t, f, project)
			if tc.change {
				file, err := os.OpenFile(profile, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = file.WriteString(" "); err != nil {
					t.Fatal(err)
				}
				if err = file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			home := f.home
			if tc.foreignHome {
				home = t.TempDir()
			}
			args := []string{"install", "--json", "--enterprise-profile", profile, "--enterprise-profile-sha256", pin, "--home", home, "--bundle", f.skbPath, "--revocations", managedEvidenceList(t, f, root, time.Hour, 1)}
			if tc.missingProfile {
				args = []string{"install", "--json", "--home", home, "--bundle", f.skbPath, "--trust-roots", f.trPath, "--revocations", managedEvidenceList(t, f, root, time.Hour, 1)}
			}
			args = append(args, tc.extra...)
			cmd := exec.Command(binary, args...)
			cmd.Dir = project
			if tc.foreignProject {
				cmd.Dir = t.TempDir()
			}
			cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home, "M3C_TOKEN_STORE=file", "M3C_TEST_KEYCHAIN=0", "M3C_ER1_KEYCHAIN=off")
			var out, diag bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &diag
			err := cmd.Run()
			code := 0
			if err != nil {
				var e *exec.ExitError
				if !errors.As(err, &e) {
					t.Fatal(err)
				}
				code = e.ExitCode()
			}
			if code != tc.want {
				t.Fatalf("process exit=%d want=%d stdout=%s stderr=%s", code, tc.want, out.String(), diag.String())
			}
			var result bundleVerifyResult
			if json.Unmarshal(out.Bytes(), &result) != nil || result.ExitCode != code || result.OK != (code == 0) {
				t.Fatalf("machine contract differs: %s", out.String())
			}
			if tc.want != 0 {
				if _, err := os.Stat(filepath.Join(home, ".claude", "skills", "revo-demo")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("denied install changed target: %v", err)
				}
			}
		})
	}
}

func TestInstallEnterpriseProfileUsageBeforeReads(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, args := range [][]string{{"--enterprise-profile-sha256", "bad", "missing"}, {"--enterprise-profile", "missing", "--ignore-deps", "missing"}, {"--enterprise-profile", "missing", "--trust-roots", "missing", "missing"}} {
		var stdout, stderr bytes.Buffer
		if code := runInstall(args, &stdout, &stderr); code != 2 {
			t.Fatalf("usage exit=%d diagnostic=%s", code, stderr.String())
		}
	}
}

// TestInstallEnterpriseProfileHTTPPreflightActualCLI checks denial before any
// synthetic registry request or lifecycle audit publication.
func TestInstallEnterpriseProfileHTTPPreflightActualCLI(t *testing.T) {
	binary := skillctlBin(t)
	for _, kind := range []string{"missing_profile", "foreign_project", "foreign_home", "ignore_deps", "foreign_registry", "invalid_pin"} {
		t.Run(kind, func(t *testing.T) {
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				http.Error(w, "unexpected fixture request", http.StatusInternalServerError)
			}))
			defer srv.Close()
			f := buildInstallableFixture(t)
			f.regURL = srv.URL + "/api/skills"
			managedEvidenceRoots(t, f, true, "closed")
			project := t.TempDir()
			profile, pin := enterpriseInstallFixtureProfile(t, f, project)
			home := f.home
			cwd := project
			want := 12
			args := []string{"install", "--json", "--enterprise-profile", profile, "--enterprise-profile-sha256", pin, "--registry", f.regURL}
			switch kind {
			case "missing_profile":
				args = []string{"install", "--json", "--trust-roots", f.trPath, "--registry", f.regURL}
			case "foreign_project":
				cwd = t.TempDir()
			case "foreign_home":
				home = t.TempDir()
			case "ignore_deps":
				args = append(args, "--ignore-deps")
				want = 2
			case "foreign_registry":
				args = append(args, "--registry", "https://foreign.invalid/api/skills")
				want = 2
			case "invalid_pin":
				args = append(args, "--enterprise-profile-sha256", "invalid")
			}
			args = append(args, "--home", home, "fetch-contract")
			cmd := exec.Command(binary, args...)
			cmd.Dir = cwd
			cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home, "M3C_TOKEN_STORE=file", "M3C_TEST_KEYCHAIN=0", "M3C_ER1_KEYCHAIN=off")
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()
			code := 0
			if err != nil {
				var e *exec.ExitError
				if !errors.As(err, &e) {
					t.Fatal(err)
				}
				code = e.ExitCode()
			}
			if code != want {
				t.Fatalf("process exit=%d want=%d out=%s diagnostic=%s", code, want, stdout.String(), stderr.String())
			}
			if requests.Load() != 0 {
				t.Fatalf("denied configuration reached registry %d times", requests.Load())
			}
			if _, err := os.Stat(lifecycleAuditPath(home)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("denied configuration published lifecycle audit: %v", err)
			}
			if _, err := os.Stat(filepath.Join(home, ".claude", "skills", "fetch-contract")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("denied configuration changed install: %v", err)
			}
		})
	}
}
