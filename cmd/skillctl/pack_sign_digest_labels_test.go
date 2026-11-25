package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// BUG-0213: `pack` prints `bundle_digest:` and `sign` prints `digest:`, two
// different SHA-256 values for the same file, and neither said which one
// belongs in `attest`, `publish --digest` and `revoke --digest`. The wrong one
// does not fail at once; it fails much later at the consumer as
// "gate 4: no attestation ...".
//
// The fix labels both outputs and keeps the field prefixes, so scripts that
// parse `^bundle_digest:` or `^digest:` keep working. Until now only
// scripts/tutorial-smoke.sh checked the labels; this test locks them in Go,
// together with the facts they state.
func TestPackAndSignSayWhichDigestCounts(t *testing.T) {
	dir := t.TempDir()
	skb := filepath.Join(dir, "t@1.0.0.skb")
	key := filepath.Join(dir, "k")

	var pOut, pErr bytes.Buffer
	if code := runPack(baseArgs(writePackSkillDir(t), skb), &pOut, &pErr); code != exitOK {
		t.Fatalf("pack exit=%d stderr=%s", code, pErr.String())
	}
	var kOut, kErr bytes.Buffer
	if code := runKeygen([]string{"--out", key}, &kOut, &kErr); code != 0 {
		t.Fatalf("keygen exit=%d stderr=%s", code, kErr.String())
	}
	var sOut, sErr bytes.Buffer
	if code := runSign([]string{"--key", key + ".priv", skb}, &sOut, &sErr); code != 0 {
		t.Fatalf("sign exit=%d stderr=%s", code, sErr.String())
	}
	packOut, signOut := pOut.String(), sOut.String()

	// The parseable prefixes are unchanged.
	pm := regexp.MustCompile(`(?m)^bundle_digest: (sha256:)?([0-9a-f]{64})\b(.*)$`).FindStringSubmatch(packOut)
	if pm == nil {
		t.Fatalf("pack output lost its `bundle_digest: <hex>` line:\n%s", packOut)
	}
	sm := regexp.MustCompile(`(?m)^digest: ([0-9a-f]{64})$`).FindStringSubmatch(signOut)
	if sm == nil {
		t.Fatalf("sign output lost its `digest: <hex>` line:\n%s", signOut)
	}
	packHex, packNote, signHex := pm[2], pm[3], sm[1]

	// The facts the labels state: sign's value is the SHA-256 of the .skb
	// bytes (and names the signature file); pack's value is a different one.
	raw, err := os.ReadFile(skb)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if want := hex.EncodeToString(sum[:]); signHex != want {
		t.Errorf("sign digest %s is not the SHA-256 of the bundle bytes %s", signHex, want)
	}
	if _, err := os.Stat(skb + "." + signHex + ".author.sig"); err != nil {
		t.Errorf("signature file is not named by the sign digest: %v", err)
	}
	if packHex == signHex {
		t.Fatalf("pack and sign print the same value; the labels would be moot (fixture changed?)")
	}

	// The labels themselves. pack: it is the manifest digest and NOT the value
	// the later steps take. sign: it IS that value, for all three steps.
	if !strings.Contains(packNote, "manifest digest") || !strings.Contains(packNote, "NOT") {
		t.Errorf("pack does not say its value is the manifest digest and not the one to use:\n%s", packOut)
	}
	label := ""
	for _, l := range strings.Split(signOut, "\n") {
		if strings.Contains(l, "bundle digest") {
			label = l
		}
	}
	if label == "" {
		t.Fatalf("sign does not label its value as the bundle digest:\n%s", signOut)
	}
	for _, want := range []string{"attest", "publish --digest", "revoke --digest"} {
		if !strings.Contains(label, want) {
			t.Errorf("sign's label does not name %q:\n%s", want, label)
		}
	}
}
