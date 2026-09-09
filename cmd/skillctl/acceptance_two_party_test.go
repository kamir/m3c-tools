package main

// acceptance_two_party_test.go: SPEC-0406, the two-party acceptance test as an
// automated regression.
//
// WHAT IT IS. The machine-checked half of the procedure Mirko and Eric run by
// hand. It plays both parties in one process, but with NOTHING shared between
// them except a directory that is explicitly declared to be the untrusted
// transport: separate homes, separate keys, separate trust-roots files.
//
// WHY THE SEPARATION IS THE TEST. If the two parties shared a home, a key, or a
// trust-roots file, the run would demonstrate that a tool can verify its own
// output, which nobody doubts. The claim under test is narrower and harder: that
// the RECIPIENT does not have to trust the sender, the channel, or anything that
// travelled with the artifact. Every shared value would quietly weaken that.
//
// HERMETIC BY CONSTRUCTION. No ER1, no network beyond a local httptest server
// standing in for the sender's own registry, and the trust-roots lookup is
// redirected per party so the run never reads the developer's own machine. An
// ambient registry once masked an over-broad fail-closed through two adversarial
// review rounds; only a hermetic run caught it.
//
// WHAT IT DOES NOT COVER, stated so nobody reads more into a green run than it
// says: the human steps. Whether a person understands the output, whether the
// fingerprint really was compared over a second channel, and whether the two
// machines really were two machines. Those are Phase 0 and the task test, and
// they stay human.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/auditevent"
	"github.com/kamir/m3c-tools/pkg/skillctl/install"
	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// party is one side of the exchange: their own home, keys and trust roots.
// Nothing in here is shared with the other party.
type party struct {
	name       string
	home       string
	trustRoots string
	authorPub  ed25519.PublicKey
	authorPriv ed25519.PrivateKey
	// The same author key ALSO on disk, because the sender's own check
	// (T03, `verify-sig --pubkey`) takes file paths, not in-memory keys.
	authorPubPath  string
	authorPrivPath string
	regPub         ed25519.PublicKey
	regPriv        ed25519.PrivateKey
	authorID       string
	skill          string
	greeting       string
}

func newParty(t *testing.T, name, skill, greeting string) *party {
	t.Helper()
	// The author key is generated THROUGH the product's own keygen and read
	// back, so the bytes the test signs with are the bytes an operator would
	// have on disk after `skillctl keygen`. Anything else would test a key
	// format nobody ships.
	keyBase := filepath.Join(t.TempDir(), name)
	if err := signing.Generate(keyBase); err != nil {
		t.Fatalf("%s author keygen: %v", name, err)
	}
	aPriv, err := signing.LoadPrivateKey(keyBase + ".priv")
	if err != nil {
		t.Fatalf("%s load author priv: %v", name, err)
	}
	aPub, err := signing.LoadPublicKey(keyBase + ".pub")
	if err != nil {
		t.Fatalf("%s load author pub: %v", name, err)
	}
	rPub, rPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("%s registry key: %v", name, err)
	}
	return &party{
		name: name, home: t.TempDir(), authorPub: aPub, authorPriv: aPriv,
		authorPubPath: keyBase + ".pub", authorPrivPath: keyBase + ".priv",
		regPub: rPub, regPriv: rPriv, authorID: "id:" + name + "@acceptance",
		skill: skill, greeting: greeting,
	}
}

// pinTrustRoots writes the RECIPIENT's view of the SENDER: the sender's author
// key, pinned locally. This stands in for Phase 0, where the fingerprint is
// compared over a second channel before anything is installed.
//
// identity_keys_authorized: pinned is what makes the offline paths possible. It
// says the author key is not to be fetched from anywhere, which is precisely why
// the transport cannot influence the decision.
func (p *party) pinTrustRoots(t *testing.T, sender *party, regURL string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("trust_roots:\n")
	b.WriteString("  - registry_url: " + regURL + "\n")
	b.WriteString("    registry_keys:\n")
	b.WriteString("      - id: reg-1\n")
	b.WriteString("        pubkey: " + base64.StdEncoding.EncodeToString(sender.regPub) + "\n")
	b.WriteString("    identity_keys_authorized: pinned\n")
	b.WriteString("    governance_minimum: green\n")
	b.WriteString("    authors:\n")
	b.WriteString("      - id: " + sender.authorID + "\n")
	b.WriteString("        pubkey: " + base64.StdEncoding.EncodeToString(sender.authorPub) + "\n")
	p.trustRoots = filepath.Join(t.TempDir(), "trust-roots-"+p.name+".yaml")
	if err := os.WriteFile(p.trustRoots, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("%s trust roots: %v", p.name, err)
	}
}

// sealed is what the sender produces and hands over: the artifact and the
// envelope beside it. Nothing else travels.
type sealed struct {
	skb    string
	meta   string
	digest string
}

// seal packs, signs and writes the pair into the transport directory.
//
// It builds the envelope directly rather than driving `export-bundle`, because
// export-bundle needs a live registry and this test is about the RECIPIENT's
// side of the exchange. The envelope it writes is the same shape export-bundle
// writes, and a separate test pins that the two agree.
func (p *party) seal(t *testing.T, transport string) sealed {
	t.Helper()
	blob := twoPartyBundle(t, p.skill, p.greeting)
	sum := sha256.Sum256(blob)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	base := filepath.Join(transport, p.skill+"@1.0.0.skb")
	if err := os.WriteFile(base, blob, 0o600); err != nil {
		t.Fatalf("%s write artifact: %v", p.name, err)
	}
	meta := map[string]any{
		"bundle": map[string]any{
			"bundle_digest": digest, "name": p.skill, "version": "1.0.0", "status": "admitted",
		},
		"signatures": []map[string]any{
			{"role": "author", "identity_id": p.authorID,
				"signature_b64": base64.StdEncoding.EncodeToString(ed25519.Sign(p.authorPriv, sum[:])), "status": "active"},
			{"role": "registry", "identity_id": "id:" + p.name + "-registry",
				"signature_b64": base64.StdEncoding.EncodeToString(ed25519.Sign(p.regPriv, sum[:])), "status": "active"},
		},
		"manifest":           map[string]any{"author_governance_intent": "green", "depends_on": []any{}},
		"current_governance": "green",
		"attestations": []map[string]any{
			{"level": "green", "reviewer_id": "id:reviewer@acceptance", "attested_at": "2026-09-06T00:00:00Z"},
		},
	}
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatalf("%s marshal envelope: %v", p.name, err)
	}
	metaPath := defaultMetaSidecar(base)
	if err := os.WriteFile(metaPath, raw, 0o600); err != nil {
		t.Fatalf("%s write envelope: %v", p.name, err)
	}
	// The detached signature beside the artifact. The envelope above is what
	// the RECIPIENT verifies against a trust root; this is what the SENDER
	// verifies against his own public key, and the runbook's step 4 shows
	// exactly that pair of commands. Both are produced here because a sender
	// who cannot check his own work finds a broken signing step only after it
	// has already travelled.
	if _, _, err := signing.SignBundle(base, p.authorPrivPath, p.authorID); err != nil {
		t.Fatalf("%s sign bundle: %v", p.name, err)
	}
	return sealed{skb: base, meta: metaPath, digest: digest}
}

// verifyBundle and installBundle drive the real CLI entry points, so the test
// exercises the same argument handling, the same error mapping and the same
// audit emission an operator gets.
func (p *party) verifyBundle(s sealed) (int, string) {
	var out bytes.Buffer
	code := runVerify([]string{"--bundle", s.skb, "--trust-roots", p.trustRoots, "--home", p.home}, &out, &out)
	return code, out.String()
}

func (p *party) installBundle(s sealed) (int, string) {
	var out bytes.Buffer
	code := runInstallBundle(installBundleParams{
		bundlePath: s.skb, trustRootsPath: p.trustRoots, homeOverride: p.home,
	}, &out, &out)
	return code, out.String()
}

func (p *party) installedSkills(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(p.home, ".claude", "skills"))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		// The tool's own staging directory is not an installed skill. This test
		// is what found it being counted as one.
		if e.IsDir() && e.Name() != install.StagingDirName {
			out = append(out, e.Name())
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// The ledger: what this run actually evaluated
// ---------------------------------------------------------------------------
//
// A bare PASS on this test answers "did anything fail". It does NOT answer the
// question SPEC-0406 is about: WHICH of the fifteen criteria were exercised.
// The two are not the same, and the gap is not hypothetical. Until 2026-09-08
// this test reported green while T03 was never evaluated at all: nobody
// verified their own package, because no call site existed.
//
// The criteria also depend on each other in a real way, so a t.Fatalf early in
// the chain leaves the rest unreachable. WORKING-RULES B7 names that state: a
// criterion whose precondition never occurs is "nie ausgewertet", not "passed".
// The ledger reports it as such, and B6 is why the count comes from the run and
// never from this list.

// spec0406Criteria is the acceptance matrix of SPEC-0406, in its order. The SET
// is the contract and is therefore declared here; which members a run REACHES
// is measured, not declared.
var spec0406Criteria = []struct{ id, what string }{
	{"T01", "Eric kann seinen Skill paketieren"},
	{"T02", "Eric kann seinen Skill signieren"},
	{"T03", "Eric kann sein eigenes Paket verifizieren"},
	{"T04", "Mirko kann Erics Skill verifizieren"},
	{"T05", "Mirko kann Erics Skill installieren"},
	{"T06", "Mirko kann Erics Skill ausfuehren"},
	{"T07", "Mirko kann seinen Skill paketieren und signieren"},
	{"T08", "Eric kann Mirkos Skill verifizieren"},
	{"T09", "Eric kann Mirkos Skill installieren"},
	{"T10", "Eric kann Mirkos Skill ausfuehren"},
	{"T11", "Manipuliertes Eric-Artefakt wird erkannt"},
	{"T12", "Manipuliertes Artefakt wird nicht installiert"},
	{"T13", "Bestand nach verweigertem Install unversehrt"},
	{"T14", "Lokale Manipulation eines installierten Skills wird erkannt"},
	{"T15", "Manipulationsversuch ist im Audit-Trail sichtbar"},
}

type acceptanceLedger struct {
	t         *testing.T
	evaluated map[string]bool
	violated  map[string]bool
}

func newAcceptanceLedger(t *testing.T) *acceptanceLedger {
	t.Helper()
	l := &acceptanceLedger{t: t, evaluated: map[string]bool{}, violated: map[string]bool{}}
	// Cleanup, not a deferred call at the end of the body: a t.Fatalf ends the
	// goroutine, and a report that only runs on the happy path would be silent
	// in exactly the case worth reporting.
	t.Cleanup(l.report)
	return l
}

// check records that a criterion was exercised and, if it was violated, says so
// and continues. Use it wherever later criteria remain reachable.
func (l *acceptanceLedger) check(id string, ok bool, format string, args ...any) bool {
	l.t.Helper()
	l.evaluated[id] = true
	if !ok {
		l.violated[id] = true
		l.t.Errorf(id+" "+format, args...)
	}
	return ok
}

// must is check for the cases where the chain genuinely cannot continue. What
// follows is then unreachable, and the report says "nie ausgewertet" for it
// rather than letting a green summary imply it passed.
func (l *acceptanceLedger) must(id string, ok bool, format string, args ...any) {
	l.t.Helper()
	l.evaluated[id] = true
	if !ok {
		l.violated[id] = true
		l.t.Fatalf(id+" "+format, args...)
	}
}

// reached marks a criterion whose own assertions live in a helper.
func (l *acceptanceLedger) reached(id string) {
	l.t.Helper()
	l.evaluated[id] = true
}

func (l *acceptanceLedger) violate(id string) {
	l.t.Helper()
	l.violated[id] = true
}

func (l *acceptanceLedger) report() {
	var missing []string
	for _, c := range spec0406Criteria {
		if !l.evaluated[c.id] {
			missing = append(missing, c.id+" "+c.what)
		}
	}
	l.t.Logf("SPEC-0406: ausgewertet %d von %d, Verletzungen %d",
		len(l.evaluated), len(spec0406Criteria), len(l.violated))
	if len(missing) == 0 {
		return
	}
	// Not a log line: a matrix that certifies fewer criteria than it claims is
	// the failure this ledger exists for.
	l.t.Errorf("SPEC-0406: %d Kriterien NIE AUSGEWERTET, das Tor darf dafuer nicht gruen melden:\n  %s",
		len(missing), strings.Join(missing, "\n  "))
}

// TestAcceptance_TwoParty is the SPEC-0406 matrix, run end to end.
func TestAcceptance_TwoParty(t *testing.T) {
	l := newAcceptanceLedger(t)
	transport := t.TempDir() // the untrusted channel: e-mail, USB, a shared folder

	mirko := newParty(t, "mirko", "mirko-demo-skill", "Hello from Mirko")
	eric := newParty(t, "eric", "eric-demo-skill", "Hello from Eric")

	// Phase 0: each side pins the OTHER's author key. Out of band, before
	// anything arrives. Without this the exchange proves nothing.
	// The root names the SENDER's own registry. Nothing here ever calls it: the
	// offline path passes no fetcher, which is exactly what makes the decision
	// independent of the sender. The URL is a name, not an endpoint.
	mirko.pinTrustRoots(t, eric, "https://eric.example/api/skills")
	eric.pinTrustRoots(t, mirko, "https://mirko.example/api/skills")

	// ---- T01..T06: Eric to Mirko ----
	// seal() packages and signs, and fails the test itself if either step does
	// not happen: reaching the next line IS the evaluation of T01 and T02.
	fromEric := eric.seal(t, transport)
	l.reached("T01")
	l.reached("T02")

	// T03: the sender verifies his OWN package before it leaves. Added
	// 2026-09-08. It is in the SPEC-0406 matrix and had no call site, so the
	// gate reported fifteen criteria and exercised fourteen. It is not a
	// duplicate of T04: this one asks whether a party can check an artifact
	// against its own trust root, which is what makes the sender able to notice
	// a broken signing step before the recipient does.
	var t03 bytes.Buffer
	code := runVerifySig([]string{"--pubkey", eric.authorPubPath, fromEric.skb}, &t03, &t03)
	l.check("T03", code == exitOK, "the sender cannot verify his own package (exit %d): %s", code, t03.String())

	code, out := mirko.verifyBundle(fromEric)
	l.must("T04", code == exitOK, "verify failed (exit %d): %s", code, out)

	code, out = mirko.installBundle(fromEric)
	l.must("T05", code == exitOK, "install failed (exit %d): %s", code, out)
	got := mirko.installedSkills(t)
	l.must("T05", len(got) == 1 && got[0] == eric.skill, "installed %v, want [%s]", got, eric.skill)

	// T06: the skill is USABLE, not merely present. Reading back the greeting
	// from the installed tree is the closest this hermetic test gets to running
	// it, and it is what distinguishes "delivered" from "verified".
	l.reached("T06")
	assertGreeting(t, l, "T06", mirko, eric)

	// ---- T07..T10: the same in reverse. Symmetry is part of the claim: neither
	// side holds a privileged role, and nothing depends on our machine.
	fromMirko := mirko.seal(t, transport)
	l.reached("T07")

	code, out = eric.verifyBundle(fromMirko)
	l.must("T08", code == exitOK, "verify failed (exit %d): %s", code, out)

	code, out = eric.installBundle(fromMirko)
	l.must("T09", code == exitOK, "install failed (exit %d): %s", code, out)

	l.reached("T10")
	assertGreeting(t, l, "T10", eric, mirko)

	// ---- T11..T13: the tamper ----
	//
	// A COPY of the already-signed artifact, altered, with its envelope intact.
	// The signature is deliberately NOT re-made: that is the whole test.
	tampered := sealed{
		skb:    filepath.Join(transport, "eric-demo-skill-tampered.skb"),
		digest: fromEric.digest,
	}
	blob, err := os.ReadFile(fromEric.skb) // #nosec G304 -- the test's own temp dir.
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	blob[len(blob)/2] ^= 0xFF
	if err := os.WriteFile(tampered.skb, blob, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	metaRaw, err := os.ReadFile(fromEric.meta) // #nosec G304 -- the test's own temp dir.
	if err != nil {
		t.Fatalf("read envelope: %v", err)
	}
	if err := os.WriteFile(defaultMetaSidecar(tampered.skb), metaRaw, 0o600); err != nil {
		t.Fatalf("write tampered envelope: %v", err)
	}

	before := snapshotSkills(t, mirko)

	// T11: detected, with the numbered code that names the cause.
	code, out = mirko.verifyBundle(tampered)
	l.check("T11", code == verify.ExitDigestMismatch,
		"verify exit = %d, want %d (digest mismatch): %s", code, verify.ExitDigestMismatch, out)
	// A refusal must be legible. A silent non-zero exit is nearly as bad as a
	// wrong one, because the operator cannot act on it.
	l.check("T11", strings.TrimSpace(out) != "", "refused without printing a reason")

	// T12: not installed.
	code, out = mirko.installBundle(tampered)
	l.check("T12", code != exitOK, "a tampered artifact was INSTALLED: %s", out)
	l.check("T12", code == verify.ExitDigestMismatch,
		"install exit = %d, want %d: %s", code, verify.ExitDigestMismatch, out)

	// T13: and the refusal changed nothing. This is INV-6 at the acceptance
	// level: a build that refuses loudly and writes anyway looks green in every
	// log, so the disk is asked directly.
	after := snapshotSkills(t, mirko)
	l.check("T13", equalSnapshots(before, after),
		"a refused install changed the install target\n before: %v\n after:  %v", before, after)

	// ---- T14: post-install tampering ----
	//
	// The most common real case: the artifact was fine on arrival and the file
	// was edited afterwards. Nothing about the transport catches this; only
	// re-verification does.
	victim := filepath.Join(mirko.home, ".claude", "skills", eric.skill, "SKILL.md")
	if err := os.WriteFile(victim, []byte("# "+eric.skill+"\n\nHello from Eric - LOCAL HACK\n"), 0o600); err != nil {
		t.Fatalf("local tamper: %v", err)
	}
	var vout bytes.Buffer
	vcode := runVerify([]string{"--offline", "--trust-roots", mirko.trustRoots, "--home", mirko.home, eric.skill}, &vout, &vout)
	l.check("T14", vcode != exitOK, "a locally altered installed skill still verified: %s", vout.String())

	// ---- T15: the audit trail ----
	l.reached("T15")
	assertRefusalWasRecorded(t, l, mirko)
}

// assertGreeting checks the installed tree really carries the sender's content.
// It takes the criterion id so a violation lands in the ledger too: a failure
// counted only by the test framework would leave the summary claiming a clean
// matrix.
func assertGreeting(t *testing.T, l *acceptanceLedger, id string, recipient, sender *party) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(recipient.home, ".claude", "skills", sender.skill, "SKILL.md")) // #nosec G304 -- test temp dir.
	if err != nil {
		l.violate(id)
		t.Fatalf("%s %s: installed skill has no SKILL.md: %v", id, recipient.name, err)
	}
	if !strings.Contains(string(body), sender.greeting) {
		l.violate(id)
		t.Errorf("%s %s installed %s but it does not carry %q:\n%s", id, recipient.name, sender.skill, sender.greeting, body)
	}
}

// T15. The refusal has to be findable afterwards, by someone who was not
// watching the terminal. Without this, "we blocked it" is a claim about a moment
// that has passed.
func assertRefusalWasRecorded(t *testing.T, l *acceptanceLedger, p *party) {
	t.Helper()
	path := lifecycleAuditPath(p.home)
	data, err := os.ReadFile(path) // #nosec G304 -- test temp dir.
	if err != nil {
		l.violate("T15")
		t.Fatalf("T15 no lifecycle audit log at %s: %v", path, err)
	}
	var found bool
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e auditevent.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			l.violate("T15")
			t.Errorf("T15 unparseable audit line: %v", err)
			continue
		}
		if e.Outcome == auditevent.OutcomeSuccess || e.Error == nil {
			continue
		}
		if e.Error.Code == string(auditevent.ReasonDigestMismatch) {
			found = true
		}
	}
	if !found {
		l.violate("T15")
		t.Errorf("T15 the tampering attempt left no digest-mismatch record in %s:\n%s", path, data)
	}
}

func snapshotSkills(t *testing.T, p *party) map[string]string {
	t.Helper()
	root := filepath.Join(p.home, ".claude", "skills")
	out := map[string]string{}
	_ = filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi == nil || fi.IsDir() {
			return nil //nolint:nilerr // an unreadable entry is handled by the caller's comparison.
		}
		b, rerr := os.ReadFile(path) // #nosec G304 -- test temp dir.
		if rerr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		sum := sha256.Sum256(b)
		out[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	})
	return out
}

func equalSnapshots(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// twoPartyBundle builds a minimal, deterministic .skb whose bundle.json carries
// the skill name. The name inside the archive is what decides where the skill
// lands (install_bundle.go reads it from the digest-verified archive), so it has
// to be real here rather than stubbed.
func twoPartyBundle(t *testing.T, name, greeting string) []byte {
	t.Helper()
	files := map[string]string{
		"bundle.json": fmt.Sprintf(`{"schema":"m3c-skill-bundle/v1","name":%q,"version":"1.0.0"}`+"\n", name),
		"SKILL.md":    "# " + name + "\n\n" + greeting + "\n",
	}
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	tw := tar.NewWriter(gw)
	root := name + "-1.0.0"
	if err := tw.WriteHeader(&tar.Header{Name: root + "/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatalf("tar dir: %v", err)
	}
	for path, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: root + "/" + path, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("tar header %s: %v", path, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar write %s: %v", path, err)
		}
	}
	_ = tw.Close()
	_ = gw.Close()
	return gzBuf.Bytes()
}
