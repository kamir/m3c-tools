package main

// SPEC-0277 P0+P1 — end-to-end tests for `skillctl agentid`. They drive the real
// CLI runners with on-disk ed25519 keys + a pinned trust-roots file and assert
// the canonical exit codes. NO HTTP server is ever started — the whole point is
// the offline, pinned-key path (AC-P0: "verify --offline passes with a nil
// network"). The approver floor + offline revocation cases cover AC-P1.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// agentFixture is a fully-wired agentid scenario on disk: owner + approver keys,
// a registry key (to sign revocation lists), and a pinned trust-roots file where
// owners are pinned as authors and approvers as reviewers.
type agentFixture struct {
	dir           string
	trPath        string
	ownerKeyPath  string
	approverKey   string
	regKeyPath    string
	ownerID       string
	approverID    string
	regURL        string
	requireApprov bool
}

func writePrivKeyPEM(t *testing.T, path string, priv ed25519.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	blob := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("write priv key: %v", err)
	}
}

func rawPubB64(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

func buildAgentFixture(t *testing.T, requireApprover bool) agentFixture {
	t.Helper()
	dir := t.TempDir()

	ownerPub, ownerPriv, _ := ed25519.GenerateKey(rand.Reader)
	approverPub, approverPriv, _ := ed25519.GenerateKey(rand.Reader)
	regPub, regPriv, _ := ed25519.GenerateKey(rand.Reader)

	ownerKeyPath := filepath.Join(dir, "owner.priv")
	approverKeyPath := filepath.Join(dir, "approver.priv")
	regKeyPath := filepath.Join(dir, "reg.priv")
	writePrivKeyPEM(t, ownerKeyPath, ownerPriv)
	writePrivKeyPEM(t, approverKeyPath, approverPriv)
	writePrivKeyPEM(t, regKeyPath, regPriv)

	ownerID := "id:kamir@m3c"
	approverID := "id:approver@m3c"
	regURL := "https://reg.example/api/skills"

	trPath := filepath.Join(dir, "trust-roots.yaml")
	var b strings.Builder
	b.WriteString("trust_roots:\n")
	b.WriteString("  - registry_url: " + regURL + "\n")
	b.WriteString("    registry_keys:\n")
	b.WriteString("      - id: reg-1\n")
	b.WriteString("        pubkey: " + rawPubB64(regPub) + "\n")
	b.WriteString("    identity_keys_authorized: pinned\n")
	b.WriteString("    governance_minimum: green\n")
	if requireApprover {
		b.WriteString("    require_agent_approver: true\n")
	}
	b.WriteString("    authors:\n")
	b.WriteString("      - id: " + ownerID + "\n")
	b.WriteString("        pubkey: " + rawPubB64(ownerPub) + "\n")
	b.WriteString("    reviewers:\n")
	b.WriteString("      - id: " + approverID + "\n")
	b.WriteString("        pubkey: " + rawPubB64(approverPub) + "\n")
	if err := os.WriteFile(trPath, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write trust-roots: %v", err)
	}

	return agentFixture{
		dir: dir, trPath: trPath,
		ownerKeyPath: ownerKeyPath, approverKey: approverKeyPath, regKeyPath: regKeyPath,
		ownerID: ownerID, approverID: approverID, regURL: regURL, requireApprov: requireApprover,
	}
}

// issue runs `agentid issue` and returns the output path. Extra args are appended.
func (f agentFixture) issue(t *testing.T, agentID, out string, extra ...string) {
	t.Helper()
	outPath := filepath.Join(f.dir, out)
	args := []string{
		"--owner", f.ownerID, "--owner-key", f.ownerKeyPath,
		"--agent-id", agentID,
		"--skills", "fetch-contract@>=1.0.0,summarize",
		"--intents", "network:read,fs:read",
		"--trust-root", f.regURL,
		"--out", outPath,
	}
	args = append(args, extra...)
	var so, se bytes.Buffer
	if code := runAgentIDIssue(args, &so, &se); code != exitOK {
		t.Fatalf("issue %s: exit %d, stderr=%s", agentID, code, se.String())
	}
}

func (f agentFixture) verify(t *testing.T, bundle string, extra ...string) (int, string, string) {
	t.Helper()
	args := append([]string{"--bundle", filepath.Join(f.dir, bundle), "--trust-roots", f.trPath, "--offline"}, extra...)
	var so, se bytes.Buffer
	code := runAgentIDVerify(args, &so, &se)
	return code, so.String(), se.String()
}

// TestAgentID_IssueVerifyOffline — AC-P0: issue → verify --offline passes.
func TestAgentID_IssueVerifyOffline(t *testing.T) {
	f := buildAgentFixture(t, false)
	f.issue(t, "agent:ok", "ok.json", "--expires", "2099-12-31T00:00:00Z")
	code, out, se := f.verify(t, "ok.json")
	if code != exitOK {
		t.Fatalf("verify: exit %d, stderr=%s", code, se)
	}
	if !strings.Contains(out, "agent:ok OK") {
		t.Fatalf("summary missing: %q", out)
	}
}

// TestAgentID_TamperFails — AC-P0: tamper the payload → exit 11.
func TestAgentID_TamperFails(t *testing.T) {
	f := buildAgentFixture(t, false)
	f.issue(t, "agent:tamper", "t.json")
	p := filepath.Join(f.dir, "t.json")
	data, _ := os.ReadFile(p)
	// Escalate the grant after signing: inject a skill into the JSON.
	tampered := strings.Replace(string(data),
		`"summarize"`, `"summarize",
        "root-skill"`, 1)
	if tampered == string(data) {
		t.Fatal("tamper did not change the document")
	}
	_ = os.WriteFile(p, []byte(tampered), 0o644)
	code, _, _ := f.verify(t, "t.json")
	if code != verify.ExitAuthorSigInvalid {
		t.Fatalf("want exit %d on tamper, got %d", verify.ExitAuthorSigInvalid, code)
	}
}

// TestAgentID_WrongKeyExit11 — AC-P0: sign with a non-pinned key → exit 11.
func TestAgentID_WrongKeyExit11(t *testing.T) {
	f := buildAgentFixture(t, false)
	// Issue using the REGISTRY key (not the pinned owner key) but claim the owner id.
	out := filepath.Join(f.dir, "wrong.json")
	args := []string{
		"--owner", f.ownerID, "--owner-key", f.regKeyPath,
		"--agent-id", "agent:wrong", "--skills", "foo", "--out", out,
	}
	var so, se bytes.Buffer
	if code := runAgentIDIssue(args, &so, &se); code != exitOK {
		t.Fatalf("issue: exit %d %s", code, se.String())
	}
	code, _, _ := f.verify(t, "wrong.json")
	if code != verify.ExitAuthorSigInvalid {
		t.Fatalf("want exit %d on wrong key, got %d", verify.ExitAuthorSigInvalid, code)
	}
}

// TestAgentID_OwnerNotPinnedExit11 — AC-P0: an owner with no pin → exit 11.
func TestAgentID_OwnerNotPinnedExit11(t *testing.T) {
	f := buildAgentFixture(t, false)
	out := filepath.Join(f.dir, "unpinned.json")
	args := []string{
		"--owner", "id:stranger@m3c", "--owner-key", f.ownerKeyPath,
		"--agent-id", "agent:unpinned", "--skills", "foo", "--out", out,
	}
	var so, se bytes.Buffer
	if code := runAgentIDIssue(args, &so, &se); code != exitOK {
		t.Fatalf("issue: exit %d %s", code, se.String())
	}
	code, _, _ := f.verify(t, "unpinned.json")
	if code != verify.ExitAuthorSigInvalid {
		t.Fatalf("want exit %d on unpinned owner, got %d", verify.ExitAuthorSigInvalid, code)
	}
}

// TestAgentID_ExpiredExit21 — AC-P0: expired → distinct exit 21.
func TestAgentID_ExpiredExit21(t *testing.T) {
	f := buildAgentFixture(t, false)
	f.issue(t, "agent:exp", "exp.json", "--expires", "2020-01-01T00:00:00Z")
	code, _, se := f.verify(t, "exp.json")
	if code != exitAgentIDExpired {
		t.Fatalf("want exit %d on expired, got %d (stderr=%s)", exitAgentIDExpired, code, se)
	}
	if code == verify.ExitAuthorSigInvalid {
		t.Fatal("expired must be DISTINCT from a signature failure")
	}
}

// TestAgentID_ApproverFloorMet — AC-P1: owner+approver passes under the floor.
func TestAgentID_ApproverFloorMet(t *testing.T) {
	f := buildAgentFixture(t, true)
	f.issue(t, "agent:two", "two.json",
		"--approver", f.approverID, "--approver-key", f.approverKey)
	code, out, se := f.verify(t, "two.json")
	if code != exitOK {
		t.Fatalf("approver floor should be met: exit %d, stderr=%s", code, se)
	}
	if !strings.Contains(out, "approver "+f.approverID) {
		t.Fatalf("approver not surfaced: %q", out)
	}
}

// TestAgentID_ApproverFloorRefusesOwnerOnly — AC-P1: owner-only refused (exit 20).
func TestAgentID_ApproverFloorRefusesOwnerOnly(t *testing.T) {
	f := buildAgentFixture(t, true)
	f.issue(t, "agent:solo", "solo.json") // no approver
	code, _, _ := f.verify(t, "solo.json")
	if code != verify.ExitSelfAttested {
		t.Fatalf("want exit %d (approver floor) on owner-only, got %d", verify.ExitSelfAttested, code)
	}
}

// TestAgentID_ApproverFloorRefusesApproverEqualsOwner — AC-P1: approver==owner refused.
func TestAgentID_ApproverFloorRefusesApproverEqualsOwner(t *testing.T) {
	f := buildAgentFixture(t, true)
	// Owner co-signs an approver row under their OWN id (and owner is pinned as an
	// author, not a reviewer, so the approver lookup also fails — both guards bite).
	f.issue(t, "agent:self", "self.json",
		"--approver", f.ownerID, "--approver-key", f.ownerKeyPath)
	code, _, _ := f.verify(t, "self.json")
	if code != verify.ExitSelfAttested {
		t.Fatalf("want exit %d when approver==owner, got %d", verify.ExitSelfAttested, code)
	}
}

// TestAgentID_RevokedOffline — AC-P1: a revoked agent is denied offline (exit 17).
func TestAgentID_RevokedOffline(t *testing.T) {
	f := buildAgentFixture(t, false)
	f.issue(t, "agent:doomed", "doomed.json", "--expires", "2099-12-31T00:00:00Z")

	// Revoke it into a signed list (reuses the registry key pinned in trust-roots).
	listPath := filepath.Join(f.dir, "revs.json")
	var so, se bytes.Buffer
	rc := runAgentIDRevoke([]string{
		"agent:doomed", "--reason", "key_compromise",
		"--registry", f.regURL, "--key", f.regKeyPath, "--out", listPath,
	}, &so, &se)
	if rc != exitOK {
		t.Fatalf("revoke: exit %d, stderr=%s", rc, se.String())
	}

	// Without --revocations it still verifies...
	if code, _, _ := f.verify(t, "doomed.json"); code != exitOK {
		t.Fatalf("pre-revocation verify should pass, got %d", code)
	}
	// ...with the signed list it is denied OFFLINE.
	code, _, _ := f.verify(t, "doomed.json", "--revocations", listPath)
	if code != exitBundleRevoked {
		t.Fatalf("want exit %d (revoked) offline, got %d", exitBundleRevoked, code)
	}
}

// TestAgentID_ForgedRevocationListRefused — a revocation list signed by a key NOT
// pinned in trust-roots is refused (exit 12), never silently "not revoked".
func TestAgentID_ForgedRevocationListRefused(t *testing.T) {
	f := buildAgentFixture(t, false)
	f.issue(t, "agent:victim", "victim.json", "--expires", "2099-12-31T00:00:00Z")

	// Forge a list with a DIFFERENT (unpinned) key.
	_, forgedPriv, _ := ed25519.GenerateKey(rand.Reader)
	list, err := verify.NewSignedAgentRevocationList(f.regURL, "2026-06-23T00:00:00Z", 1, []string{"agent:victim"}, forgedPriv)
	if err != nil {
		t.Fatalf("forge list: %v", err)
	}
	listPath := filepath.Join(f.dir, "forged.json")
	writeJSON(t, listPath, list)

	code, _, _ := f.verify(t, "victim.json", "--revocations", listPath)
	if code != verify.ExitRegistryNotTrusted {
		t.Fatalf("want exit %d on forged list, got %d", verify.ExitRegistryNotTrusted, code)
	}
}

// TestAgentID_Show prints owner + grant.
func TestAgentID_Show(t *testing.T) {
	f := buildAgentFixture(t, false)
	f.issue(t, "agent:shown", "shown.json")
	var so, se bytes.Buffer
	if code := runAgentIDShow([]string{filepath.Join(f.dir, "shown.json")}, &so, &se); code != exitOK {
		t.Fatalf("show: exit %d %s", code, se.String())
	}
	out := so.String()
	for _, want := range []string{"agent:shown", "id:kamir@m3c", "fetch-contract"} {
		if !strings.Contains(out, want) {
			t.Fatalf("show output missing %q: %s", want, out)
		}
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
