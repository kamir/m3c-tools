package sim

// world.go executes a scenario against the REAL skillctl binary and a REAL git
// registry (a bare local:// repo, which is the same backend code path as
// github:// and gitlab:// with the remote strecke removed). Nothing here is
// simulated: every verdict in the report is a process exit from the shipping
// binary.
//
// The registry is local:// by default so the whole corpus is hermetic, offline
// and free to run on every commit. A benchmark that needs the network and a
// secret is a benchmark that gets switched off, and one that runs rarely stops
// catching the seams it exists for. The remote backends stay reachable through
// --registry for a deliberate, occasional run.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// World is one scenario's universe: its keys, its registry, its consumer machine.
type World struct {
	Skillctl string // path to the real binary
	Root     string // throwaway directory; everything lives under it
	Registry string // registry spec, e.g. local:///tmp/x/reg.git

	consumerHome string
	bundles      map[string]*bundleState
	trace        []string
}

type bundleState struct {
	skill     string
	version   string
	path      string // the .skb
	digest    string // sha256:<hex>, the value sign printed
	admitted  bool
	attested  bool
	revoked   bool
	installed bool
}

// NewWorld builds the sandbox: a bare registry and an empty consumer home.
func NewWorld(skillctl, root string) (*World, error) {
	w := &World{
		Skillctl:     skillctl,
		Root:         root,
		Registry:     "local://" + filepath.Join(root, "reg.git"),
		consumerHome: filepath.Join(root, "consumer"),
		bundles:      map[string]*bundleState{},
	}
	for _, d := range []string{"keys", "src", "work", filepath.Join("consumer", ".claude")} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			return nil, err
		}
	}
	if _, _, err := w.run(nil, "registry", "init", "--registry", w.Registry); err != nil {
		return nil, fmt.Errorf("registry init: %w", err)
	}
	return w, nil
}

// Keygen mints one named keypair. Names are logical roles ("publisher"), so a
// scenario reads as a story rather than as a list of paths.
func (w *World) Keygen(name string) error {
	_, _, err := w.run(nil, "keygen", "--out", w.keyPath(name))
	return err
}

func (w *World) keyPath(name string) string { return filepath.Join(w.Root, "keys", name) }

// PubRaw returns the raw 32-byte ed25519 key and its fingerprint, the two values
// a consumer needs to pin. Parsed in-process rather than shelled out to openssl:
// one less tool the benchmark depends on, and the same bytes either way.
func (w *World) PubRaw(name string) (b64, fingerprint string, err error) {
	// #nosec G304 G703 -- the path is composed from a fixed sandbox root and a
	// role name from this package's own constant set. No scenario field reaches it.
	data, err := os.ReadFile(w.keyPath(name) + ".pub")
	if err != nil {
		return "", "", err
	}
	blk, _ := pem.Decode(data)
	if blk == nil {
		return "", "", fmt.Errorf("sim: %s.pub is not PEM", name)
	}
	key, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return "", "", err
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return "", "", fmt.Errorf("sim: %s.pub is not ed25519", name)
	}
	sum := sha256.Sum256(pub)
	return base64.StdEncoding.EncodeToString(pub), "sha256:" + hex.EncodeToString(sum[:]), nil
}

// WriteSkill lays down a minimal, deterministic skill source.
func (w *World) WriteSkill(name string) error {
	dir := filepath.Join(w.Root, "src", name)
	if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o700); err != nil {
		return err
	}
	md := "---\nname: " + name + "\nversion: 1.0.0\ndescription: Simulation skill, at least twenty characters long.\n---\n\n# " + name + "\n"
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(md), 0o600); err != nil {
		return err
	}
	// #nosec G306 -- the script has to be executable for the skill to be a skill;
	// 0700 is already the tightest mode that keeps it runnable, and it lives in a
	// throwaway sandbox that is deleted when the scenario ends.
	return os.WriteFile(filepath.Join(dir, "scripts", "run.sh"), []byte("echo "+name+"\n"), 0o700)
}

var digestLine = regexp.MustCompile(`(?m)^digest: ([0-9a-f]{64})`)

// gateLine finds the refusal a pull reports, so the report can say WHICH gate
// held rather than only that something did.
var gateLine = regexp.MustCompile(`gate (\d)`)

// run invokes the real binary. env entries are appended to a hermetic base so a
// scenario can never reach the operator's own ~/.claude.
func (w *World) run(env []string, args ...string) (string, int, error) {
	// #nosec G204 -- launching the binary under test IS this package's purpose.
	// The path comes from the operator's -skillctl flag or the repo's own build
	// directory, and the arguments are built here, never from scenario input.
	cmd := exec.Command(w.Skillctl, args...)
	cmd.Dir = filepath.Join(w.Root, "work")
	base := []string{
		"HOME=" + filepath.Join(w.Root, "nobody"),
		"PATH=" + os.Getenv("PATH"),
		"USERPROFILE=" + filepath.Join(w.Root, "nobody"),
	}
	cmd.Env = append(base, env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
		err = nil
	}
	w.trace = append(w.trace, fmt.Sprintf("$ skillctl %s -> %d", strings.Join(args, " "), code))
	return string(out), code, err
}

// consumerEnv runs a command as the consumer machine.
func (w *World) consumerEnv() []string {
	return []string{"HOME=" + w.consumerHome, "USERPROFILE=" + w.consumerHome}
}

// Trace is the command log, for a human reading a failed scenario.
func (w *World) Trace() []string { return w.trace }

// --- the actions ---------------------------------------------------------

// PackSign seals a skill with the named key and records its signed digest.
func (w *World) PackSign(skill, keyName, identity string) (string, int, error) {
	skb := filepath.Join(w.Root, "work", skill+"@1.0.0.skb")
	out, code, err := w.run(nil, "pack",
		"--skill", filepath.Join(w.Root, "src", skill),
		"-o", skb, "--name", skill, "--version", "1.0.0",
		"--summary", "simulation", "--author-intent", "green",
		"--author-intent-rationale", "no network")
	if err != nil || code != 0 {
		return out, code, err
	}
	out2, code2, err := w.run(nil, "sign", "--key", w.keyPath(keyName)+".priv",
		"--identity-id", identity, skb)
	if err != nil || code2 != 0 {
		return out2, code2, err
	}
	m := digestLine.FindStringSubmatch(out2)
	if m == nil {
		return out2, code2, fmt.Errorf("sim: sign printed no digest")
	}
	w.bundles[skill] = &bundleState{skill: skill, version: "1.0.0", path: skb, digest: "sha256:" + m[1]}
	return out + out2, 0, nil
}

// Admit takes a bundle into the registry under the given key.
func (w *World) Admit(skill, keyName, identity string) (string, int, error) {
	b := w.bundles[skill]
	if b == nil {
		return "", -1, fmt.Errorf("sim: %s not packed", skill)
	}
	out, code, err := w.run(nil, "publish", skill+"@"+b.version,
		"--bundle", b.path, "--version", b.version, "--registry", w.Registry,
		"--key", w.keyPath(keyName)+".priv", "--identity", identity, "--yes")
	if code == 0 && err == nil {
		b.admitted = true
	}
	return out, code, err
}

// Attest posts a governance verdict signed by keyName.
func (w *World) Attest(skill, keyName, identity, level string) (string, int, error) {
	b := w.bundles[skill]
	if b == nil {
		return "", -1, fmt.Errorf("sim: %s not packed", skill)
	}
	out, code, err := w.run(nil, "publish", "--attest", skill+"@"+b.version,
		"--digest", b.digest, "--level", level, "--rationale", "simulated review",
		"--registry", w.Registry, "--identity", identity,
		"--key", w.keyPath(keyName)+".priv", "--yes")
	if code == 0 && err == nil && level == "green" {
		b.attested = true
	}
	return out, code, err
}

// Revoke pulls the brake on a digest.
func (w *World) Revoke(skill, keyName, identity string) (string, int, error) {
	b := w.bundles[skill]
	if b == nil {
		return "", -1, fmt.Errorf("sim: %s not packed", skill)
	}
	out, code, err := w.run(nil, "publish", "--revoke", skill,
		"--digest", b.digest, "--reason", "superseded", "--registry", w.Registry,
		"--key", w.keyPath(keyName)+".priv", "--identity", identity, "--yes")
	if code == 0 && err == nil {
		b.revoked = true
	}
	return out, code, err
}

// Pin writes the consumer's trust decision: the registry key, and optionally a
// separate reviewer whose attestations count.
func (w *World) Pin(regKey string, signers map[string]string) (string, int, error) {
	b64, fp, err := w.PubRaw(regKey)
	if err != nil {
		return "", -1, err
	}
	args := []string{"peer", "add", "reg", w.Registry, "--pubkey", b64, "--pin", fp}
	for id, keyName := range signers {
		sb64, _, serr := w.PubRaw(keyName)
		if serr != nil {
			return "", -1, serr
		}
		args = append(args, "--signer", id+":"+sb64)
	}
	if len(signers) > 0 {
		args = append(args, "--quorum", "1")
	}
	return w.run(w.consumerEnv(), args...)
}

// Pull runs the gauntlet and installs on success. The G-23 two-step is executed
// in full: a scenario that skipped the confirm would not be exercising the path a
// real operator walks.
func (w *World) Pull(skill string) (string, int, error) {
	base := []string{"pull", "--registry", w.Registry, "--skill", skill,
		"--install", "--trust-mode", "--no-checkpoint"}
	out, code, err := w.run(w.consumerEnv(), append(append([]string{}, base...), "--dry-run-install")...)
	if err != nil || code != 0 {
		return out, code, err
	}
	tok := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "dry-run-install token") {
			f := strings.Fields(line)
			tok = f[len(f)-1]
		}
	}
	if tok == "" {
		return out, code, nil // nothing staged: the plan is the whole answer
	}
	out2, code2, err := w.run(w.consumerEnv(), append(append([]string{}, base...),
		"--confirm-install", "--dry-run-install-token", tok)...)
	if code2 == 0 && err == nil {
		if b := w.bundles[skill]; b != nil {
			b.installed = true
		}
	}
	return out + out2, code2, err
}

// Verify re-checks an installed skill.
func (w *World) Verify(skill string) (string, int, error) {
	return w.run(w.consumerEnv(), "verify", skill)
}

// VerifySig is the offline author check.
func (w *World) VerifySig(skill, keyName string) (string, int, error) {
	b := w.bundles[skill]
	if b == nil {
		return "", -1, fmt.Errorf("sim: %s not packed", skill)
	}
	return w.run(nil, "verify-sig", "--pubkey", w.keyPath(keyName)+".pub", b.path)
}

// --- adversary capabilities ----------------------------------------------

// TamperTransit flips a byte in the bundle and leaves the original signature
// under its original name. The attacker controls the artifact, not the signer.
func (w *World) TamperTransit(skill string) error {
	b := w.bundles[skill]
	if b == nil {
		return fmt.Errorf("sim: %s not packed", skill)
	}
	return flipByte(b.path, 200)
}

// LyingSignature flips a byte AND renames the signature to match the new digest,
// so the verifier FINDS a signature and has to do real cryptography to refuse.
func (w *World) LyingSignature(skill string) error {
	b := w.bundles[skill]
	if b == nil {
		return fmt.Errorf("sim: %s not packed", skill)
	}
	oldSig := b.path + "." + strings.TrimPrefix(b.digest, "sha256:") + ".author.sig"
	if err := flipByte(b.path, 300); err != nil {
		return err
	}
	// #nosec G304 -- re-reading the sandbox artifact the harness just wrote.
	data, err := os.ReadFile(b.path)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	newSig := b.path + "." + hex.EncodeToString(sum[:]) + ".author.sig"
	// #nosec G304 -- the detached signature the harness produced a moment ago.
	sig, err := os.ReadFile(oldSig)
	if err != nil {
		return err
	}
	// #nosec G703 -- newSig is built from the sandbox path plus a hex digest this
	// function just computed. Nothing from a scenario definition reaches it.
	if err := os.WriteFile(newSig, sig, 0o600); err != nil {
		return err
	}
	// The world now tracks the NEW digest, so everything the publisher does next
	// (admit, attest, revoke) refers to the bytes that actually exist.
	//
	// Without this line the attestation stayed bound to the pre-tamper digest, the
	// admitted bytes carried no governance, and the pull died at gate 4 with gate 3
	// never consulted. That is a real behaviour and it is worth knowing, but it is
	// not the question this move was added to ask. A malicious publisher signs off
	// on what he actually published.
	b.digest = "sha256:" + hex.EncodeToString(sum[:])
	return nil
}

// TamperInstalled edits a file inside an installed skill: the same-uid attacker,
// after the install. What the model claims here is narrow and stated in the
// oracle, not here.
func (w *World) TamperInstalled(skill string) error {
	p := filepath.Join(w.consumerHome, ".claude", "skills", skill, "SKILL.md")
	// #nosec G304 -- same: the post-install tamper is the move under test.
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString("\n<!-- injected -->\n")
	return err
}

// StripRevoke deletes the revoke event from the registry: a hostile mirror trying
// to suppress the kill switch by withholding it.
func (w *World) StripRevoke(skill string) error {
	return w.mutateRegistry(skill, func(dir, evPath string) error {
		if strings.Contains(evPath, "revoked") {
			return os.Remove(filepath.Join(dir, evPath))
		}
		return nil
	})
}

// RelabelRevoke renames a revoke event so its FILENAME claims to be an install:
// the registry controls the path, so the path must not be what decides.
func (w *World) RelabelRevoke(skill string) error {
	return w.mutateRegistry(skill, func(dir, evPath string) error {
		if strings.Contains(evPath, "revoked") {
			return os.Rename(filepath.Join(dir, evPath),
				filepath.Join(dir, strings.Replace(evPath, "revoked", "installed", 1)))
		}
		return nil
	})
}

// flipByte corrupts one byte at an offset, growing the file if it is short.
func flipByte(path string, off int64) error {
	// #nosec G304 -- an adversary step deliberately corrupts a file inside the
	// throwaway sandbox; that is the experiment, not a vulnerability.
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if off >= fi.Size() {
		off = fi.Size() / 2
	}
	buf := make([]byte, 1)
	if _, err := f.ReadAt(buf, off); err != nil {
		return err
	}
	buf[0] ^= 0xff
	_, err = f.WriteAt(buf, off)
	return err
}

// ---------------------------------------------------------------------------
// The independent oracle: what is ON DISK, not what the process said.
//
// Everything above this line reads the trust plane through its own output: an
// exit code, a line of text, a gate name. That is a real oracle and it catches
// real defects, but it shares a failure mode with the thing it measures. A build
// that reports "refused" and writes the file anyway passes every check in this
// file, because every check asked the build how it went.
//
// An external reviewer put it plainly on 2026-09-05: "Fehler gemeldet, aber
// vorher trotzdem geschrieben" muss rot werden. It cannot go red while the only
// witness is the accused. So the harness now takes its own reading of the
// consumer's install target, before and after every pull, and the invariants
// compare the two without asking anybody.

// InstallSnapshot is what the consumer's skill directory actually contains: the
// set of file paths and the SHA-256 of each. Comparing two snapshots answers
// "did anything change, and into what" without trusting a single word the tool
// printed.
type InstallSnapshot struct {
	Files map[string]string // path relative to the skills root -> sha256 hex

	// Err is set when the reading itself failed: a directory that exists but
	// cannot be walked, an entry that cannot be hashed. It is NOT set for an
	// absent skills root, which is a real and expected state before the first
	// install.
	//
	// The distinction is the whole point. The first version treated an unreadable
	// entry as an absent one, so two failed readings compared equal and INV-6
	// concluded "nothing changed" from having measured nothing twice. An external
	// reviewer named it on 2026-09-05: an unexpected measurement error has to
	// produce NOT EVALUABLE and stop the run, never a quiet pass.
	Err string
}

// Equal reports whether two snapshots describe the same bytes on disk.
func (s InstallSnapshot) Equal(o InstallSnapshot) bool {
	// A snapshot that failed to read is never equal to anything, including another
	// failed snapshot. "We could not look, twice" is not evidence of sameness.
	if s.Err != "" || o.Err != "" {
		return false
	}
	if len(s.Files) != len(o.Files) {
		return false
	}
	for k, v := range s.Files {
		if o.Files[k] != v {
			return false
		}
	}
	return true
}

// Describe renders a snapshot difference for a violation message, so a report
// says WHICH file appeared or changed rather than only that something did.
func (s InstallSnapshot) Describe(o InstallSnapshot) string {
	var added, changed, removed []string
	for k, v := range o.Files {
		if old, ok := s.Files[k]; !ok {
			added = append(added, k)
		} else if old != v {
			changed = append(changed, k)
		}
	}
	for k := range s.Files {
		if _, ok := o.Files[k]; !ok {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(changed)
	sort.Strings(removed)
	parts := []string{}
	if len(added) > 0 {
		parts = append(parts, "added "+strings.Join(added, ","))
	}
	if len(changed) > 0 {
		parts = append(parts, "changed "+strings.Join(changed, ","))
	}
	if len(removed) > 0 {
		parts = append(parts, "removed "+strings.Join(removed, ","))
	}
	if len(parts) == 0 {
		return "no change"
	}
	return strings.Join(parts, "; ")
}

// SnapshotInstall walks the consumer's skills root and hashes everything under
// it. A missing root is not an error: it is the empty snapshot, which is exactly
// the state before the first successful install.
func (w *World) SnapshotInstall() InstallSnapshot {
	root := filepath.Join(w.consumerHome, ".claude", "skills")
	snap := InstallSnapshot{Files: map[string]string{}}

	// An absent root is the empty snapshot and nothing is wrong: that is the state
	// before the first install. Anything else that goes wrong while reading is a
	// failure to measure, and it is recorded as one.
	if _, err := os.Stat(root); err != nil {
		if !os.IsNotExist(err) {
			snap.Err = "install root not readable: " + err.Error()
		}
		return snap
	}

	werr := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", p, err)
		}
		if fi == nil || fi.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return fmt.Errorf("relpath %s: %w", p, rerr)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			// Record the link itself rather than following it: a snapshot that
			// silently resolves links can be told that nothing changed by an
			// attacker who only moved a target.
			snap.Files[filepath.ToSlash(rel)] = "symlink"
			return nil
		}
		// #nosec G304 -- p comes from Walk over a directory this process created
		// inside its own throwaway root; there is no user-supplied path here.
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return fmt.Errorf("read %s: %w", p, rerr)
		}
		sum := sha256.Sum256(b)
		snap.Files[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	})
	if werr != nil {
		snap.Err = werr.Error()
	}
	return snap
}

// InstalledDigestMatches reports whether the skill's installed bytes hash to the
// digest that was signed. It is the difference between "the tool said it
// installed the right thing" and "the right thing is there".
//
// It returns false when nothing is installed, which is why the invariant that
// uses it fires only after an accepted pull.
func (w *World) InstalledDigestMatches(skill string) (bool, string) {
	want, err := w.SourceManifest(skill)
	if err != nil {
		return false, "source manifest unreadable: " + err.Error()
	}
	got := w.installedManifest(skill)
	if got.Err != "" {
		return false, "NOT EVALUABLE: " + got.Err
	}

	var missing, differing, extra []string
	for path, sum := range want {
		switch g, ok := got.Files[path]; {
		case !ok:
			missing = append(missing, path)
		case g != sum:
			differing = append(differing, path)
		}
	}
	for path := range got.Files {
		if _, ok := want[path]; ok {
			continue
		}
		if installSidecars[path] {
			continue
		}
		extra = append(extra, path)
	}
	sort.Strings(missing)
	sort.Strings(differing)
	sort.Strings(extra)

	var parts []string
	if len(missing) > 0 {
		parts = append(parts, "missing "+strings.Join(missing, ","))
	}
	if len(differing) > 0 {
		parts = append(parts, "wrong bytes in "+strings.Join(differing, ","))
	}
	if len(extra) > 0 {
		parts = append(parts, "unexpected "+strings.Join(extra, ","))
	}
	if len(parts) > 0 {
		return false, strings.Join(parts, "; ")
	}
	return true, ""
}

// installSidecars are the files the install itself writes into the skill
// directory, on top of the packed content. They are listed by name rather than
// tolerated by a pattern, so a file that is genuinely unexpected still fails.
//
// Measuring them was not planned. The manifest check was written to catch a
// missing file, and the first run reported five "unexpected" ones, which turned
// out to be the provenance sidecar, the attestation, the checksums, the bundle
// metadata and the .skb the verifier needs later. That is the check doing its
// job: it described the install more completely than the person who wrote it
// could, and the correct response was to write down what belongs there.
var installSidecars = map[string]bool{
	"bundle.json":            true,
	"CHECKSUMS":              true,
	"simskill.skb":           true,
	".m3c-provenance.json":   true,
	".skillctl-attest.json":  true,
	".skillctl-install.json": true,
	".skillctl-provenance":   true,
}

// SourceManifest is the set of paths and hashes the packed skill consists of,
// taken from the source tree BEFORE anything is published.
//
// It replaces a single-file comparison that checked only SKILL.md against its
// source. That check was useful for the small test artifact and it was named as
// if it proved more: an external reviewer pointed out on 2026-09-05 that it
// verified neither the complete installed file set nor its binding to the signed
// bundle. A file that goes missing, and a file that appears which nobody signed,
// both passed it. The manifest catches both directions.
//
// What it still does NOT do is verify against the bundle's own signed manifest.
// The source tree is the harness's own record, so this is an independent reading
// of the install, not a cryptographic one. That gap is named rather than papered
// over, and closing it means reading the .skb.
func (w *World) SourceManifest(skill string) (map[string]string, error) {
	root := filepath.Join(w.Root, "src", skill)
	out := map[string]string{}
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi == nil || fi.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		// #nosec G304 -- the harness's own source tree inside its throwaway root.
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		sum := sha256.Sum256(b)
		out[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	})
	return out, err
}

// installedManifest reads what is actually under the consumer's skill directory,
// with the same not-evaluable discipline as SnapshotInstall.
func (w *World) installedManifest(skill string) InstallSnapshot {
	full := w.SnapshotInstall()
	if full.Err != "" {
		return full
	}
	out := InstallSnapshot{Files: map[string]string{}}
	prefix := skill + "/"
	for path, sum := range full.Files {
		if strings.HasPrefix(path, prefix) {
			out.Files[strings.TrimPrefix(path, prefix)] = sum
		}
	}
	return out
}
