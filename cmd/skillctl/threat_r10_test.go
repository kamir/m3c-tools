package main

// threat_r10_test.go — closes the R10 gap in THREAT_MODEL.md (§R10 — credential
// leakage). The existing coverage (TestSignBundle_DoesNotLeakKeyInError,
// TestGitCredNoLeak) only proves ERROR-PATH / in-flight leakage. Nothing asserts
// that secret material stays OUT of the DURABLE state skillctl writes. This test
// closes that gap.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/device"
	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
	"github.com/kamir/m3c-tools/pkg/skillctl/translog"
	"github.com/kamir/m3c-tools/pkg/skillgate"
)

// secretRepr is one on-the-wire encoding of a secret, labelled so a hit names
// exactly which secret leaked and in which encoding.
type secretRepr struct {
	label string
	bytes []byte
}

// secretReprs expands a raw secret into every representation a careless writer
// might serialise it as (raw bytes, lower/upper hex, and the four base64
// alphabets), so the "no secret at rest" sweep catches a leak regardless of how
// the leaking code happened to encode it.
func secretReprs(name string, secret []byte) []secretRepr {
	h := hex.EncodeToString(secret)
	return []secretRepr{
		{name + "/raw", append([]byte(nil), secret...)},
		{name + "/hex-lower", []byte(h)},
		{name + "/hex-upper", []byte(strings.ToUpper(h))},
		{name + "/base64-std", []byte(base64.StdEncoding.EncodeToString(secret))},
		{name + "/base64-rawstd", []byte(base64.RawStdEncoding.EncodeToString(secret))},
		{name + "/base64-url", []byte(base64.URLEncoding.EncodeToString(secret))},
		{name + "/base64-rawurl", []byte(base64.RawURLEncoding.EncodeToString(secret))},
	}
}

// TestNoSecretAtRest_PersistedArtifacts drives a full secret-handling cycle —
// device-signing the invocation trail, HMAC-signing the verdict cache, and
// ed25519-signing a transparency-log head — then sweeps EVERY durable artifact
// those operations wrote and asserts that none of the private key material used
// to produce them landed at rest in the persisted state.
//
// THREAT-R10: A signing key / device token / HMAC key must never leak into the
// evidence and state files a later reader can harvest — the invocation/audit
// trail (cmd/skillctl/invocation_trail.go), the verdict cache
// (cmd/skillctl/verdict_cache.go), and the transparency log
// (pkg/skillctl/translog). Secrets may live ONLY in their own 0600 key files
// (device-key.priv, verdict.key); those are excluded from the sweep. Every other
// persisted artifact must be secret-free.
//
// How it would fail if the property were violated: if any writer serialised the
// key bytes into a record (e.g. a "signed trail with key <bytes>" debug field, a
// verdict row that stored the HMAC key instead of the MAC, or an STH that carried
// the log private key), the sweep below would find one of the key's encodings in
// that file and fail, naming the file + which secret + which encoding.
func TestNoSecretAtRest_PersistedArtifacts(t *testing.T) {
	home := t.TempDir()
	now := time.Unix(1_700_000_000, 0).UTC()

	// --- secret #1: the per-machine DEVICE signing key (the "device token") ----
	// EnsureKey lazily generates ~/.claude/skillctl/device-key.priv(.pub); the
	// invocation trail below is device-signed with it. The genuine secret is the
	// ed25519 seed (the private half); the trail must carry only the KeyID
	// (a public fingerprint) and detached signatures, never the seed.
	if _, err := device.EnsureKey(home); err != nil {
		t.Fatalf("device.EnsureKey: %v", err)
	}
	devPriv, err := signing.LoadPrivateKey(device.PrivPath(home))
	if err != nil {
		t.Fatalf("load device priv: %v", err)
	}
	deviceSeed := devPriv.Seed() // 32 bytes — the actual secret

	// --- drive the invocation trail (writes invocation-trail.jsonl + .hwm) -----
	for i, ev := range []string{"01HZR10EVENT0000000000000A", "01HZR10EVENT0000000000000B", "01HZR10EVENT0000000000000C"} {
		rec := skillgate.InvocationRecord{
			EventID:      ev,
			EventType:    "skill.invocation",
			SkillName:    "didactic-session",
			SkillVersion: "1.0.0",
			Action:       "invoke",
			Tool:         "skill",
			SessionID:    "sess:r10",
			ExitCode:     i,
		}
		appendSignedInvocation(home, rec)
	}

	// --- secret #2: the verdict-cache HMAC key --------------------------------
	// recordVerdict lazily generates ~/.claude/skillctl/verdict.key and writes a
	// signed row to verdicts.json. The row must carry the MAC, never the key.
	skillDir := filepath.Join(home, ".claude", "skills", "good")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("# good"), 0o644); err != nil {
		t.Fatal(err)
	}
	recordVerdict(home, "good", "sess:r10", exitOK, "chain ok", now)
	verdictKey, err := os.ReadFile(verdictKeyPath(home))
	if err != nil {
		t.Fatalf("read verdict.key: %v", err)
	}
	verdictKey = verdictKey[:32]

	// --- secret #3: the transparency-log ed25519 signing key -------------------
	// A KNOWN seed so we search for exact bytes. The log persists JSONL entries on
	// Append and we persist the signed STH; neither must carry the log priv key.
	logSeed := bytes.Repeat([]byte{0xA7}, ed25519.SeedSize)
	logKey := ed25519.NewKeyFromSeed(logSeed)
	logPath := filepath.Join(home, translog.DefaultLogPath)
	l, err := translog.OpenLog(logPath, "log:r10-test")
	if err != nil {
		t.Fatalf("translog.OpenLog: %v", err)
	}
	if _, err := translog.EmitAdmit(l, "sha256:"+strings.Repeat("ab", 32), "good", now); err != nil {
		t.Fatalf("EmitAdmit: %v", err)
	}
	if _, err := translog.EmitAttest(l, "sha256:"+strings.Repeat("cd", 32), "green", now); err != nil {
		t.Fatalf("EmitAttest: %v", err)
	}
	sth, err := l.SignHead(logKey, now)
	if err != nil {
		t.Fatalf("SignHead: %v", err)
	}
	sthBytes, err := json.Marshal(sth)
	if err != nil {
		t.Fatal(err)
	}
	sthPath := filepath.Join(home, ".claude", "skillctl", "sth.json")
	if err := os.WriteFile(sthPath, sthBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	// Build the needle set for every secret in every encoding.
	var needles []secretRepr
	needles = append(needles, secretReprs("device-seed", deviceSeed)...)
	needles = append(needles, secretReprs("verdict-hmac-key", verdictKey)...)
	needles = append(needles, secretReprs("translog-log-key", logSeed)...)

	// Positive control: the search mechanism actually detects a present secret.
	// verdict.key holds the raw HMAC key, so its raw representation MUST be found
	// in that (excluded) key file — proving a non-detection below is a real
	// absence, not a broken matcher.
	if rawKeyFile, err := os.ReadFile(verdictKeyPath(home)); err != nil {
		t.Fatalf("positive-control read verdict.key: %v", err)
	} else if !bytes.Contains(rawKeyFile, verdictKey) {
		t.Fatal("positive control failed: raw HMAC key not found in its own key file — matcher is broken")
	}

	// Files that legitimately HOLD secret material (their whole purpose) are the
	// only ones excused from the sweep.
	secretKeyFiles := map[string]bool{
		"device-key.priv": true,
		"device-key.pub":  true, // public half, but excluded to keep the sweep about EVIDENCE files
		"verdict.key":     true,
	}

	// Sweep every durable artifact under home and assert no secret appears at rest.
	var swept []string
	err = filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if secretKeyFiles[d.Name()] {
			return nil // the secret's own protected home — not evidence state
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		rel, _ := filepath.Rel(home, p)
		swept = append(swept, rel)
		for _, n := range needles {
			if bytes.Contains(data, n.bytes) {
				t.Errorf("SECRET AT REST: %s leaked into persisted artifact %s (encoding %s)", n.label, rel, n.label)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}

	// Guard against a vacuous pass: the sweep MUST have covered the durable
	// artifacts each secret-handling operation wrote. If one is missing, the
	// absence assertions above proved nothing.
	mustHaveSwept := []string{
		filepath.Join(".claude", "skillctl", "invocation-trail.jsonl"),
		filepath.Join(".claude", "skillctl", "verdicts.json"),
		filepath.Join(".claude", "skillctl", "transparency-log.jsonl"),
		filepath.Join(".claude", "skillctl", "sth.json"),
	}
	for _, want := range mustHaveSwept {
		found := false
		for _, got := range swept {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected durable artifact %q was not written/swept — the no-leak assertion over it is vacuous", want)
		}
	}

	// Sanity: the trail we swept is real signed evidence (carries a device
	// signature + the PUBLIC device key id), confirming we searched populated
	// files rather than empty stubs.
	trail, rerr := os.ReadFile(invocationTrailPath(home))
	if rerr != nil {
		t.Fatalf("read trail: %v", rerr)
	}
	if !bytes.Contains(trail, []byte("device_signature_b64")) {
		t.Fatalf("trail is not populated signed evidence: %q", string(trail))
	}
}
