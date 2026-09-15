package main

// Befund 1.10 (Enterprise-Audit Welle 1): `install --bundle` nahm die
// Offline-Revocation-Eingaben seines verify-Zwillings nicht an; die Kette
// pruefte Revocation nur ueber das unsignierte meta.Status-Feld. Diese Tests
// fahren den ECHTEN Flag-Parser (runInstall), damit genau der gemessene Defekt
// ("flag provided but not defined: -revocations") abgedeckt ist, und messen
// nach jedem Refusal den Installationszustand: ein verweigertes Bundle darf
// NICHTS auf der Platte hinterlassen.
//
// Exit-Codes sind die des Zwillings (verify --bundle): revoked digest → 17,
// forged/untrusted list → 12, stale snapshot (high risk) → 22, emergency → 17,
// unlesbare Liste → 1 (generic, fail-closed).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/install"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// installableFixture is a real, extractable .skb (tar.gz with a signed
// bundle.json) plus sidecar, pinned trust-roots and a private home. Unlike
// bundleFixture (arbitrary bytes, enough for verify), install needs the real
// archive because InstallBundle reads the signed name out of it.
type installableFixture struct {
	skbPath      string
	trPath       string
	home         string
	dir          string
	digest       string
	authorID     string
	regURL       string
	regPriv      ed25519.PrivateKey
	regPubB64    string
	authorPubB64 string
}

func buildInstallableFixture(t *testing.T) installableFixture {
	t.Helper()
	dir := t.TempDir()

	authorPub, authorPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("author keygen: %v", err)
	}
	regPub, regPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("reg keygen: %v", err)
	}

	blob := twoPartyBundle(t, "revo-demo", "a bundle for the revocation gate")
	sum := sha256.Sum256(blob)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	skbPath := filepath.Join(dir, "revo-demo@1.0.0.skb")
	if err := os.WriteFile(skbPath, blob, 0o644); err != nil {
		t.Fatalf("write skb: %v", err)
	}

	authorID := "id:bob@m3c"
	regURL := "https://reg.example/api/skills"

	meta := registry.BundleMeta{
		Bundle: map[string]any{
			"bundle_digest": digest,
			"name":          "revo-demo",
			"version":       "1.0.0",
			"status":        "admitted",
		},
		Signatures: []registry.SignatureRow{
			{Role: "author", IdentityID: authorID, SignatureB64: signB64(authorPriv, sum), Status: "active"},
			{Role: "registry", IdentityID: "id:registry@aims-core", SignatureB64: signB64(regPriv, sum), Status: "active"},
		},
		CurrentGovernance: "green",
	}
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	if err := os.WriteFile(defaultMetaSidecar(skbPath), metaJSON, 0o644); err != nil {
		t.Fatalf("write meta: %v", err)
	}

	regPubB64 := base64.StdEncoding.EncodeToString(regPub)
	authorPubB64 := base64.StdEncoding.EncodeToString(authorPub)
	trPath := filepath.Join(dir, "trust-roots.pinned.yaml")
	writePinnedTrustRoots(t, trPath, regURL, regPubB64, authorID, authorPubB64)

	return installableFixture{
		skbPath: skbPath, trPath: trPath, home: t.TempDir(), dir: dir,
		digest: digest, authorID: authorID, regURL: regURL, regPriv: regPriv,
		regPubB64: regPubB64, authorPubB64: authorPubB64,
	}
}

// installedSkillDirs lists what actually landed under <home>/.claude/skills,
// minus the tool's own staging dir. Empty slice = nothing installed.
func installedSkillDirs(t *testing.T, home string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(home, ".claude", "skills"))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && e.Name() != install.StagingDirName {
			out = append(out, e.Name())
		}
	}
	return out
}

// runInstallArgs drives the real CLI entry point, flags and all.
func runInstallArgs(f installableFixture, extra ...string) (int, string) {
	args := append([]string{
		"--bundle", f.skbPath, "--trust-roots", f.trPath, "--home", f.home,
	}, extra...)
	var out bytes.Buffer
	code := runInstall(args, &out, &out)
	return code, out.String()
}

// (a) A signed revocation list naming the bundle's digest refuses the install
// with the twin's exit code, and NOTHING lands on disk.
func TestInstallBundle_RevokedDigestRefused(t *testing.T) {
	f := buildInstallableFixture(t)
	list, err := verify.NewSignedRevocationList(f.regURL, "2026-09-06T10:00:00Z", 1, []string{f.digest}, f.regPriv)
	if err != nil {
		t.Fatal(err)
	}
	revPath := writeRevocations(t, f.dir, list)

	before := installedSkillDirs(t, f.home)
	code, out := runInstallArgs(f, "--revocations", revPath)
	if code != exitBundleRevoked {
		t.Fatalf("revoked digest must exit %d, got %d; output=%s", exitBundleRevoked, code, out)
	}
	after := installedSkillDirs(t, f.home)
	if len(before) != 0 || len(after) != 0 {
		t.Fatalf("a refused install must leave the skills dir untouched; before=%v after=%v", before, after)
	}
}

// (b) A signed list that does NOT name the digest lets the install through.
func TestInstallBundle_NotRevokedInstalls(t *testing.T) {
	f := buildInstallableFixture(t)
	list, err := verify.NewSignedRevocationList(f.regURL, "2026-09-06T10:00:00Z", 1, []string{otherDigest()}, f.regPriv)
	if err != nil {
		t.Fatal(err)
	}
	revPath := writeRevocations(t, f.dir, list)

	code, out := runInstallArgs(f, "--revocations", revPath)
	if code != exitOK {
		t.Fatalf("not-revoked bundle must install (exit 0), got %d; output=%s", code, out)
	}
	after := installedSkillDirs(t, f.home)
	if len(after) != 1 || after[0] != "revo-demo" {
		t.Fatalf("expected exactly [revo-demo] installed, got %v", after)
	}
}

// (c) An unreadable revocation list is an ERROR, never a pass, and nothing is
// installed (fail-closed).
func TestInstallBundle_UnreadableRevocationListFailsClosed(t *testing.T) {
	f := buildInstallableFixture(t)
	code, out := runInstallArgs(f, "--revocations", filepath.Join(f.dir, "no-such-file.json"))
	if code != exitGeneric {
		t.Fatalf("unreadable revocation list must exit %d, got %d; output=%s", exitGeneric, code, out)
	}
	if after := installedSkillDirs(t, f.home); len(after) != 0 {
		t.Fatalf("fail-closed means nothing installed, got %v", after)
	}
}

// A list signed by a key the trust root does not pin is refused (12), and
// nothing is installed. Same as the verify twin's forged-list case.
func TestInstallBundle_ForgedRevocationListRefused(t *testing.T) {
	f := buildInstallableFixture(t)
	_, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	list, err := verify.NewSignedRevocationList(f.regURL, "2026-09-06T10:00:00Z", 1, []string{f.digest}, attackerPriv)
	if err != nil {
		t.Fatal(err)
	}
	revPath := writeRevocations(t, f.dir, list)

	code, out := runInstallArgs(f, "--revocations", revPath)
	if code != verify.ExitRegistryNotTrusted {
		t.Fatalf("forged list must exit %d, got %d; output=%s", verify.ExitRegistryNotTrusted, code, out)
	}
	if after := installedSkillDirs(t, f.home); len(after) != 0 {
		t.Fatalf("a forged list must not install anything, got %v", after)
	}
}

// (d) Without the new flags the behavior is exactly as before: the bundle
// installs, no new mandatory parameter.
func TestInstallBundle_NoRevocationFlagsUnchanged(t *testing.T) {
	f := buildInstallableFixture(t)
	code, out := runInstallArgs(f)
	if code != exitOK {
		t.Fatalf("install without revocation flags must stay exit 0, got %d; output=%s", code, out)
	}
	if after := installedSkillDirs(t, f.home); len(after) != 1 || after[0] != "revo-demo" {
		t.Fatalf("expected exactly [revo-demo] installed, got %v", after)
	}
}

// A stale snapshot for a high-risk bundle (no declared data-scopes) fails
// closed with the twin's exit code 22, before anything is written.
func TestInstallBundle_StaleHighRiskFailsClosed(t *testing.T) {
	f := buildInstallableFixture(t)
	writePinnedTrustRootsFresh(t, f.trPath, f.regURL, f.regPubB64, f.authorID, f.authorPubB64, "24h", "open")

	list, err := verify.NewSignedRevocationList(f.regURL, freshBundleISO(48*time.Hour), 1, []string{otherDigest()}, f.regPriv)
	if err != nil {
		t.Fatal(err)
	}
	revPath := writeRevocations(t, f.dir, list)

	code, out := runInstallArgs(f, "--revocations", revPath)
	if code != verify.ExitRevocationStale {
		t.Fatalf("stale high-risk install must exit %d, got %d; output=%s", verify.ExitRevocationStale, code, out)
	}
	if after := installedSkillDirs(t, f.home); len(after) != 0 {
		t.Fatalf("a stale-refused install must leave nothing behind, got %v", after)
	}
}

// An emergency deny-list naming the digest denies immediately (17), even with a
// fresh snapshot, and nothing is installed.
func TestInstallBundle_EmergencyDeniesDigest(t *testing.T) {
	f := buildInstallableFixture(t)
	writePinnedTrustRootsFresh(t, f.trPath, f.regURL, f.regPubB64, f.authorID, f.authorPubB64, "24h", "open")

	list, err := verify.NewSignedRevocationList(f.regURL, freshBundleISO(1*time.Hour), 1, []string{otherDigest()}, f.regPriv)
	if err != nil {
		t.Fatal(err)
	}
	revPath := writeRevocations(t, f.dir, list)

	em, err := verify.NewSignedEmergencyDenyList(f.regURL, freshBundleISO(30*time.Minute), 1, []string{f.digest}, f.regPriv)
	if err != nil {
		t.Fatal(err)
	}
	emPath := filepath.Join(f.dir, "emergency.json")
	if b, _ := json.MarshalIndent(em, "", "  "); os.WriteFile(emPath, b, 0o644) != nil {
		t.Fatal("write emergency")
	}

	code, out := runInstallArgs(f, "--revocations", revPath, "--emergency", emPath)
	if code != exitBundleRevoked {
		t.Fatalf("emergency deny must exit %d, got %d; output=%s", exitBundleRevoked, code, out)
	}
	if after := installedSkillDirs(t, f.home); len(after) != 0 {
		t.Fatalf("an emergency-denied install must leave nothing behind, got %v", after)
	}
}

// The three offline inputs belong to --bundle. On the registry path they are
// refused (usage), never silently ignored: an accepted-but-unenforced security
// flag would be its own fail-open.
func TestInstall_RevocationFlagsRequireBundle(t *testing.T) {
	var out bytes.Buffer
	code := runInstall([]string{"--revocations", "somewhere.json", "some-skill"}, &out, &out)
	if code != exitUsage {
		t.Fatalf("--revocations without --bundle must exit %d, got %d; output=%s", exitUsage, code, out.String())
	}
}
