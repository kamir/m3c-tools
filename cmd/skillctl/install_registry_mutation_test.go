package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

func registryMutationFixture(t *testing.T) installableFixture {
	t.Helper()
	fx := newFixture(t)
	srv := httptest.NewServer(fx.happyMux(t, map[string]any{"author_governance_intent": "green", "depends_on": []any{}}, "green", nil))
	t.Cleanup(srv.Close)
	home := t.TempDir()
	fx.pinTrust(t, home, srv.URL, "")
	defaultPath := filepath.Join(home, ".claude", "skill-trust-roots.yaml")
	body, err := os.ReadFile(defaultPath)
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, []byte("    offline_policy:\n      enterprise: true\n")...)
	explicit := filepath.Join(t.TempDir(), "selected-roots.yaml")
	if err := os.WriteFile(explicit, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(defaultPath); err != nil {
		t.Fatal(err)
	}
	// There is deliberately no default trust-roots file in this process home.
	return installableFixture{home: home, dir: t.TempDir(), trPath: explicit, regURL: srv.URL + "/api/skills", regPriv: fx.regPriv, regPubB64: base64.StdEncoding.EncodeToString(fx.regPub), digest: fx.digestStr}
}

func registryMutationInstall(t *testing.T, binary string, f installableFixture, want int) {
	t.Helper()
	args := []string{"install", "--json"}
	args = append(args, enterpriseInstallFixtureArgs(t, f)...)
	args = append(args, "--registry", f.regURL, "fetch-contract")
	out := mutationCLI(t, binary, f, want, args...)
	var result bundleVerifyResult
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("CLI JSON: %v output=%s", err, out)
	}
	if result.Operation != "install" || result.ExitCode != want || result.OK != (want == 0) {
		t.Fatalf("process/JSON contradiction: %+v", result)
	}
}

func TestInstallRegistryManagedActualCLI(t *testing.T) {
	binary := skillctlBin(t)
	for _, state := range []string{"fresh", "revoked", "lost"} {
		t.Run(state, func(t *testing.T) {
			f := registryMutationFixture(t)
			target := filepath.Join(f.home, ".claude", "skills", "fetch-contract")
			if err := os.MkdirAll(target, 0700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(target, "SKILL.md")
			if err := os.WriteFile(marker, []byte("previous installed skill"), 0600); err != nil {
				t.Fatal(err)
			}
			registryMutationInstall(t, binary, f, 22)
			if got, err := os.ReadFile(marker); err != nil || string(got) != "previous installed skill" {
				t.Fatalf("missing-state denial changed old install: %v", err)
			}
			var digests []string
			if state == "revoked" {
				digests = []string{f.digest}
			}
			list, err := verify.NewSignedRevocationList(f.regURL, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano), 1, digests, f.regPriv)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.dir, "enrollment.json")
			writeJSON(t, path, list)
			enrollStateCLI(t, binary, f, path)
			want := 0
			if state == "revoked" {
				want = 17
			}
			if state == "lost" {
				paths, err := filepath.Glob(filepath.Join(f.home, ".claude", "mutation-state", "*", "record.json"))
				if err != nil || len(paths) != 1 {
					t.Fatalf("record path: %v %v", paths, err)
				}
				if err := os.Remove(paths[0]); err != nil {
					t.Fatal(err)
				}
				want = 22
			}
			registryMutationInstall(t, binary, f, want)
			got, err := os.ReadFile(marker)
			if err != nil {
				t.Fatal(err)
			}
			if want != 0 && string(got) != "previous installed skill" {
				t.Fatal("policy denial replaced existing skill")
			}
			if want == 0 && (!strings.Contains(string(got), "fetch-contract") || string(got) == "previous installed skill") {
				t.Fatalf("fresh authorized install did not publish bundle: %s", got)
			}
		})
	}
}

func TestInstallRegistryOlderEvidenceCannotUndoAdoptionActualCLI(t *testing.T) {
	binary := skillctlBin(t)
	f := registryMutationFixture(t)
	initial := mutationCLIList(t, f, "initial", 1, time.Now().Add(-2*time.Hour))
	enrollStateCLI(t, binary, f, initial)
	newer := mutationCLIList(t, f, "newer", 2, time.Now().Add(-time.Hour))
	mutationStateCLI(t, binary, f, 0, "adopt", "--revocations", newer)
	mutationStateCLI(t, binary, f, 22, "adopt", "--revocations", initial)
	status := decodeMutationStatus(t, mutationStateCLI(t, binary, f, 0, "status"), f)
	if status.Epoch != 2 {
		t.Fatalf("older evidence lowered floor: %+v", status)
	}
	registryMutationInstall(t, binary, f, 0)
}

func TestInstallRegistryOfflineOnlyFlagsUsageActualCLI(t *testing.T) {
	binary := skillctlBin(t)
	for _, flag := range []string{"--meta", "--revocations", "--checkpoint", "--emergency"} {
		t.Run(flag, func(t *testing.T) {
			home := t.TempDir()
			f := installableFixture{home: home}
			// Missing roots and flag paths make ordering observable: usage must win
			// before any registry/trust-file access or management-state creation.
			mutationCLI(t, binary, f, 2, "install", "--trust-roots", filepath.Join(home, "missing-roots.yaml"), flag, filepath.Join(home, "missing-input.json"), "fetch-contract")
			entries, err := os.ReadDir(home)
			if err != nil || len(entries) != 0 {
				t.Fatalf("usage refusal created state: entries=%v error=%v", entries, err)
			}
		})
	}
}
