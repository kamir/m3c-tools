package main

// Revocations read from a git registry must reach the load-time gate and verify.
// Both pin routes run through the real pull, git backend and hook.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	backendgit "github.com/kamir/m3c-tools/pkg/skillctl/backend/git"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

const gitRevocationSkill = "git-revoke-skill"

type gitRevocationFixture struct {
	home   string
	spec   string
	regDir string
	priv   ed25519.PrivateKey
	digest string
	event  string
}

func newGitRevocationFixture(t *testing.T, route string) *gitRevocationFixture {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_ER1_KEYCHAIN", "off")
	t.Setenv("M3C_TOKEN_STORE", "file")
	peersConfigPath = filepath.Join(home, ".claude", "skill-peers.yaml")
	t.Cleanup(func() { peersConfigPath = "" })
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	regDir := filepath.Join(t.TempDir(), "reg.git")
	spec := "local://" + regDir
	if _, err := backendgit.InitLocalRegistry(spec); err != nil {
		t.Fatalf("init registry: %v", err)
	}
	be, err := artifact.Open(spec, artifact.OpenOptions{})
	if err != nil {
		t.Fatalf("open registry: %v", err)
	}
	defer be.Close() //nolint:errcheck // test fixture
	body := "---\nname: " + gitRevocationSkill + "\nversion: 1.0.0\ndescription: Fixture for the revocation gate tests.\n---\n# fixture\n"
	digest := publishSignedSkill(t, be, priv, gitRevocationSkill, "1.0.0", body)

	switch route {
	case "handwritten":
		roots := fmt.Sprintf("registry: %s\npubkey_b64: %s\nfingerprint: %s\ngovernance_minimum: green\n",
			spec, base64.StdEncoding.EncodeToString(pub), fpOf(pub))
		if err := os.WriteFile(filepath.Join(home, ".claude", "trust-roots.yaml"), []byte(roots), 0o600); err != nil {
			t.Fatal(err)
		}
	case "peer":
		peers := &registry.Peers{Peers: []registry.Peer{{
			Name: "meins", Locator: spec, PubKeyB64: base64.StdEncoding.EncodeToString(pub),
			Fingerprint: fpOf(pub), GovernanceMinimum: "green",
		}}}
		if err := peers.Save(peersConfigPath); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown route %q", route)
	}

	f := &gitRevocationFixture{home: home, spec: spec, regDir: regDir, priv: priv, digest: digest,
		event: fmt.Sprintf(`{"tool_name":"Skill","tool_input":{"skill":%q}}`, gitRevocationSkill)}
	code, plan, stderr := f.pull(t, "--dry-run-install")
	if code != 0 {
		t.Fatalf("plan: exit %d\n%s\n%s", code, plan, stderr)
	}
	token := ""
	for _, line := range strings.Split(plan, "\n") {
		if strings.Contains(line, "dry-run-install token") {
			fields := strings.Fields(line)
			token = fields[len(fields)-1]
		}
	}
	if token == "" {
		t.Fatalf("no token in plan:\n%s", plan)
	}
	code, out, stderr := f.pull(t, "--confirm-install", "--dry-run-install-token", token)
	if code != 0 {
		t.Fatalf("confirm: exit %d\n%s\n%s", code, out, stderr)
	}
	return f
}

func (f *gitRevocationFixture) pull(t *testing.T, extra ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	args := append([]string{"--registry", f.spec, "--skill", gitRevocationSkill, "--install", "--trust-mode", "--no-checkpoint"}, extra...)
	return runPull(args, &out, &errb), out.String(), errb.String()
}

func (f *gitRevocationFixture) revoke(t *testing.T, signer ed25519.PrivateKey) {
	t.Helper()
	be, err := artifact.Open(f.spec, artifact.OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer be.Close() //nolint:errcheck // test fixture
	rev, err := registry.BuildBundleRevokedEvent(registry.RevokedEventInput{
		BundleDigest: f.digest, RevokedBy: "id:a@org", OccurredAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.SignEnvelopeSignature(signer, rev); err != nil {
		t.Fatal(err)
	}
	meta := artifact.ArtifactMeta{Name: gitRevocationSkill, Version: "1.0.0", Digest: f.digest}
	if _, err := be.Publish(context.Background(), artifact.PublishRequest{Kind: artifact.KindRevoke, Event: rev, Meta: meta}); err != nil {
		t.Fatalf("publish revoke: %v", err)
	}
}

func (f *gitRevocationFixture) verifyOne(t *testing.T) int {
	t.Helper()
	var out, errb bytes.Buffer
	return runVerify([]string{gitRevocationSkill}, &out, &errb)
}

func (f *gitRevocationFixture) sweep(t *testing.T) (int, map[string]any) {
	t.Helper()
	var out, errb bytes.Buffer
	code := runVerify([]string{"--all", "--json"}, &out, &errb)
	var rep map[string]any
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("sweep output is not JSON: %v\n%s\n%s", err, out.String(), errb.String())
	}
	return code, rep
}

func sweepEntryFor(t *testing.T, rep map[string]any, name string) map[string]any {
	t.Helper()
	entries, _ := rep["entries"].([]any)
	for _, raw := range entries {
		if e, _ := raw.(map[string]any); e != nil && e["skill"] == name {
			return e
		}
	}
	t.Fatalf("no sweep entry for %q: %v", name, rep)
	return nil
}

var gitRevocationRoutes = []string{"handwritten", "peer"}

func TestGitRevocation_CleanSkillPassesGateAndVerify(t *testing.T) {
	for _, route := range gitRevocationRoutes {
		t.Run(route, func(t *testing.T) {
			f := newGitRevocationFixture(t, route)
			code, out, _ := feed(t, f.event)
			assertAllow(t, code, out)
			if got := f.verifyOne(t); got != exitOK {
				t.Fatalf("verify exit = %d, want 0", got)
			}
		})
	}
}

func TestGitRevocation_PullFeedsGateAndVerify(t *testing.T) {
	for _, route := range gitRevocationRoutes {
		t.Run(route, func(t *testing.T) {
			f := newGitRevocationFixture(t, route)
			f.revoke(t, f.priv)
			if code, out, errb := f.pull(t, "--dry-run-install"); code == exitOK {
				t.Fatalf("pull of a revoked bundle succeeded\n%s\n%s", out, errb)
			}
			code, out, _ := feed(t, f.event)
			assertDeny(t, code, out, "revoked")
			if got := f.verifyOne(t); got != exitBundleRevoked {
				t.Fatalf("verify exit = %d, want %d", got, exitBundleRevoked)
			}
		})
	}
}

func TestGitRevocation_SweepFindsRevocationWithoutPull(t *testing.T) {
	for _, route := range gitRevocationRoutes {
		t.Run(route, func(t *testing.T) {
			f := newGitRevocationFixture(t, route)
			f.revoke(t, f.priv)
			_, rep := f.sweep(t)
			entry := sweepEntryFor(t, rep, gitRevocationSkill)
			if got, _ := entry["exit"].(float64); int(got) != exitBundleRevoked {
				t.Fatalf("entry exit = %v, want %d: %v", entry["exit"], exitBundleRevoked, entry)
			}
			code, out, _ := feed(t, f.event)
			assertDeny(t, code, out, "revoked")
		})
	}
}

func TestGitRevocation_CleanSweepOnGitOnlyHostIsComplete(t *testing.T) {
	for _, route := range gitRevocationRoutes {
		t.Run(route, func(t *testing.T) {
			f := newGitRevocationFixture(t, route)
			code, rep := f.sweep(t)
			entry := sweepEntryFor(t, rep, gitRevocationSkill)
			if code != exitOK {
				t.Fatalf("sweep exit = %d, want 0: %v", code, rep)
			}
			if entry["status"] != "valid" {
				t.Fatalf("entry = %v, want status valid", entry)
			}
		})
	}
}

func TestGitRevocation_DeletedEventDoesNotUnrevoke(t *testing.T) {
	f := newGitRevocationFixture(t, "handwritten")
	f.revoke(t, f.priv)
	if code, _, _ := f.pull(t, "--dry-run-install"); code == exitOK {
		t.Fatal("pull of a revoked bundle succeeded")
	}
	if err := os.RemoveAll(f.regDir); err != nil {
		t.Fatal(err)
	}
	if _, err := backendgit.InitLocalRegistry(f.spec); err != nil {
		t.Fatal(err)
	}
	f.sweep(t)
	code, out, _ := feed(t, f.event)
	assertDeny(t, code, out, "revoked")
}

func TestGitRevocation_ForgedEventIsIgnored(t *testing.T) {
	for _, route := range gitRevocationRoutes {
		t.Run(route, func(t *testing.T) {
			f := newGitRevocationFixture(t, route)
			_, attacker, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			f.revoke(t, attacker)
			f.pull(t, "--dry-run-install")
			f.sweep(t)
			code, out, _ := feed(t, f.event)
			assertAllow(t, code, out)
		})
	}
}

func TestGitRevocation_UnreachableRegistryDoesNotDenyCleanSkill(t *testing.T) {
	f := newGitRevocationFixture(t, "handwritten")
	if err := os.RemoveAll(f.regDir); err != nil {
		t.Fatal(err)
	}
	code, out, _ := feed(t, f.event)
	assertAllow(t, code, out)
	exit, rep := f.sweep(t)
	if exit == exitOK {
		t.Fatalf("a sweep that could not read the registry must not report success: %v", rep)
	}
	entry := sweepEntryFor(t, rep, gitRevocationSkill)
	if got, _ := entry["exit"].(float64); int(got) == exitBundleRevoked {
		t.Fatalf("an unreachable registry must not read as revoked: %v", entry)
	}
}
