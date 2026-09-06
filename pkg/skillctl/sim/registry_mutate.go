package sim

// registry_mutate.go gives the adversary the one capability a signature cannot
// take away: control of the STORE. A hostile mirror, a compromised CI token or a
// malicious maintainer can delete an event, rename it, or reorder the tree. It
// cannot forge a signature, and the whole design rests on the difference.
//
// These mutations are why the corpus needs a real git registry rather than a
// mock: the interesting attacks are on the carrier, and a mock carrier proves
// nothing about the real one.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// mutateRegistry clones the bare registry, applies fn to every event file that
// belongs to the skill's digest, and pushes the result back. fn receives the
// clone root and the repo-relative path of one event file.
func (w *World) mutateRegistry(skill string, fn func(dir, evPath string) error) error {
	b := w.bundles[skill]
	if b == nil {
		return fmt.Errorf("sim: %s not packed", skill)
	}
	bare := strings.TrimPrefix(w.Registry, "local://")
	clone, err := os.MkdirTemp(w.Root, "mutate-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(clone)

	if out, err := git(clone, "clone", "--quiet", bare, "."); err != nil {
		return fmt.Errorf("clone: %v: %s", err, out)
	}
	evDir := filepath.Join("events", strings.TrimPrefix(b.digest, "sha256:"))
	entries, err := os.ReadDir(filepath.Join(clone, evDir))
	if err != nil {
		return fmt.Errorf("no events for %s: %w", skill, err)
	}
	touched := false
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		before := filepath.Join(evDir, e.Name())
		if err := fn(clone, before); err != nil {
			return err
		}
		touched = true
	}
	if !touched {
		return nil
	}
	if out, err := git(clone, "add", "-A"); err != nil {
		return fmt.Errorf("add: %v: %s", err, out)
	}
	// An empty commit means fn changed nothing; that is not an error, the
	// adversary simply had nothing to do here.
	if out, err := git(clone, "commit", "--quiet", "-m", "adversary: mutate registry"); err != nil {
		if strings.Contains(out, "nothing to commit") {
			return nil
		}
		return fmt.Errorf("commit: %v: %s", err, out)
	}
	if out, err := git(clone, "push", "--quiet", "origin", "HEAD"); err != nil {
		return fmt.Errorf("push: %v: %s", err, out)
	}
	return nil
}

func git(dir string, args ...string) (string, error) {
	// #nosec G204 -- git is the registry backend under test. Arguments are literals
	// from this file; the only variable is the clone directory the harness created.
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=sim", "GIT_AUTHOR_EMAIL=sim@local",
		"GIT_COMMITTER_NAME=sim", "GIT_COMMITTER_EMAIL=sim@local",
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TamperStoredBundle flips a byte in the .skb AS STORED IN THE REGISTRY, after a
// clean admit. This is the mirror-compromise case: the events are untouched and
// correctly signed, only the artifact was swapped. The digest gate is the only
// thing standing between the victim and the attacker's bytes.
func (w *World) TamperStoredBundle(skill string) error {
	b := w.bundles[skill]
	if b == nil {
		return fmt.Errorf("sim: %s not packed", skill)
	}
	bare := strings.TrimPrefix(w.Registry, "local://")
	clone, err := os.MkdirTemp(w.Root, "mutate-blob-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(clone)
	if out, err := git(clone, "clone", "--quiet", bare, "."); err != nil {
		return fmt.Errorf("clone: %v: %s", err, out)
	}
	blob := filepath.Join(clone, "skills", skill, b.version, "bundle.skb")
	if err := flipByte(blob, 200); err != nil {
		return err
	}
	if out, err := git(clone, "add", "-A"); err != nil {
		return fmt.Errorf("add: %v: %s", err, out)
	}
	if out, err := git(clone, "commit", "--quiet", "-m", "adversary: swap the stored artifact"); err != nil {
		return fmt.Errorf("commit: %v: %s", err, out)
	}
	if out, err := git(clone, "push", "--quiet", "origin", "HEAD"); err != nil {
		return fmt.Errorf("push: %v: %s", err, out)
	}
	return nil
}

// ForgeEnvelope rewrites the envelope signature on the ADMIT event in the store.
// A hostile mirror can change any byte it holds; what it cannot do is produce a
// signature that verifies against the pinned key. This is the only move in the
// alphabet that reaches gate 1, and it exists because the theory check proved the
// gate was otherwise unreachable: no corpus size would have covered it.
func (w *World) ForgeEnvelope(skill string) error {
	return w.mutateRegistry(skill, func(dir, evPath string) error {
		if !strings.Contains(evPath, "admitted") {
			return nil
		}
		full := filepath.Join(dir, evPath)
		// #nosec G304 -- a path this function just enumerated inside its own clone.
		data, err := os.ReadFile(full)
		if err != nil {
			return err
		}
		var ev map[string]any
		if err := json.Unmarshal(data, &ev); err != nil {
			return err
		}
		// Replace the signature with a well-formed but wrong one: the shape stays
		// valid so the parser is not what refuses. The CRYPTOGRAPHY has to refuse,
		// which is the property under test.
		ev["envelope_signature"] = base64.StdEncoding.EncodeToString(make([]byte, 64))
		out, err := json.MarshalIndent(ev, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(full, out, 0o600)
	})
}

// WithholdArtifact removes the stored .skb from the registry while leaving every
// signed event in place. It is not an attack: it is the PROBE for FR-0119 D3.
//
// The requirement decided on 2026-09-05 says a pull must not fetch artifact bytes
// from an untrusted backend once it has already decided against the bundle from
// signed metadata alone. That is a statement about side effects, and it is hard to
// check from outside a process: you cannot see a fetch that did not happen.
//
// Taking the bytes away turns it into something observable. If the decision truly
// does not need them, a revoked bundle still refuses at gate 5 and an ungoverned
// one still refuses at gate 4. An implementation that fetched first would instead
// report a fetch failure, which surfaces as gate 2, and the gate-order prediction
// catches it as a conflict. No instrumentation of the product, no privileged view:
// the absence of a side effect is measured by removing what the side effect would
// have touched.
func (w *World) WithholdArtifact(skill string) error {
	b := w.bundles[skill]
	if b == nil {
		return fmt.Errorf("sim: %s not packed", skill)
	}
	bare := strings.TrimPrefix(w.Registry, "local://")
	clone, err := os.MkdirTemp(w.Root, "withhold-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(clone) }()
	if out, err := git(clone, "clone", "--quiet", bare, "."); err != nil {
		return fmt.Errorf("clone: %v: %s", err, out)
	}
	blob := filepath.Join(clone, "skills", skill, b.version, "bundle.skb")
	if err := os.Remove(blob); err != nil {
		return fmt.Errorf("remove stored artifact: %w", err)
	}
	if out, err := git(clone, "add", "-A"); err != nil {
		return fmt.Errorf("add: %v: %s", err, out)
	}
	if out, err := git(clone, "commit", "--quiet", "-m", "probe: the backend cannot serve the artifact"); err != nil {
		return fmt.Errorf("commit: %v: %s", err, out)
	}
	if out, err := git(clone, "push", "--quiet", "origin", "HEAD"); err != nil {
		return fmt.Errorf("push: %v: %s", err, out)
	}
	return nil
}

// ForgeBundleSignatures posts an admit event whose SIGNATURE ROWS do not verify,
// with an envelope that does. It is the move that reaches gate 3, and building it
// took three attempts because the first two could not get there at all.
//
// Attempt one flipped a byte inside the .skb and renamed the detached signature to
// match the new digest. The tar header broke and the installer refused before any
// signature was read. Attempt two corrupted the detached `<bundle>.<digest>.author.sig`
// file. That one ran green for two days and produced the conflict that FR-0121 was
// filed on, because nobody checked WHICH file the pull path reads: it reads the
// signature rows carried INSIDE the signed event, and never opens the sidecar. A
// move against a file the path does not read cannot exercise a gate on that path.
//
// The reachability argument is what makes the third attempt necessary. The rows
// live under the envelope signature, so a hostile STORE cannot touch them: any
// edit invalidates the envelope and gate 1 decides first. Only a party holding the
// registry key can present rows that do not verify beneath an envelope that does,
// which is why this move re-signs. That party is not a rational attacker (holding
// the key, he would simply sign correctly); he is a broken or hostile publishing
// TOOL, and gate 3 is the consumer's protection against admitting its output.
//
// The re-signing deliberately does NOT call the product's own signing code. The
// canonical form is re-implemented here from the format, the way an attacker's
// tooling would have to. If the two ever disagree the envelope stops verifying,
// gate 1 fires instead of gate 3, and the gate-order prediction reports it as a
// conflict rather than hiding it.
func (w *World) ForgeBundleSignatures(skill string) error {
	priv, err := loadSimKey(w.keyPath("publisher") + ".priv")
	if err != nil {
		return err
	}
	return w.mutateRegistry(skill, func(dir, evPath string) error {
		if !strings.Contains(evPath, "admitted") {
			return nil
		}
		full := filepath.Join(dir, evPath)
		// #nosec G304 -- a path this function just enumerated inside its own clone.
		data, err := os.ReadFile(full)
		if err != nil {
			return err
		}
		var ev map[string]any
		if err := json.Unmarshal(data, &ev); err != nil {
			return err
		}
		rows, _ := ev["signatures"].([]any)
		if len(rows) == 0 {
			return fmt.Errorf("sim: admit event carries no signature rows; the move cannot reach gate 3")
		}
		// Well-formed and wrong: correct length, correct base64, verifies against
		// nothing. The PARSER must not be what refuses, or the test would pass on a
		// build whose cryptography was gone.
		for _, r := range rows {
			m, ok := r.(map[string]any)
			if !ok {
				return fmt.Errorf("sim: signature row is not an object")
			}
			m["signature_b64"] = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		}
		canon, err := simCanonicalEvent(ev)
		if err != nil {
			return err
		}
		ev["envelope_signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canon))
		out, err := json.MarshalIndent(ev, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(full, out, 0o600)
	})
}

// simCanonicalEvent is the adversary's own copy of the canonical form: every
// field except the envelope signature, JSON-encoded with HTML escaping off and no
// trailing newline. See ForgeBundleSignatures for why this is not a call into the
// product.
func simCanonicalEvent(ev map[string]any) ([]byte, error) {
	cp := make(map[string]any, len(ev))
	for k, v := range ev {
		if k == "envelope_signature" {
			continue
		}
		cp[k] = v
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(cp); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	return out, nil
}

// loadSimKey reads a PEM/PKCS8 ed25519 private key. The harness holds the key
// because the SCENARIO says the publisher does; nothing here reaches the consumer.
func loadSimKey(path string) (ed25519.PrivateKey, error) {
	// #nosec G304 -- a key this harness generated inside its own sandbox.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sim: read publisher key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("sim: %s holds no PEM block", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sim: parse publisher key: %w", err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("sim: publisher key is %T, not ed25519", parsed)
	}
	return priv, nil
}
