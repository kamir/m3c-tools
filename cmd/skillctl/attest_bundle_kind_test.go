package main

// Challenge-gate F3 + F5 (PR #319).
//
// F3: the §5.1 attest minimum must judge the kind from a reliable source. The
// manifest inside the .skb is that source whenever the bytes are at hand;
// omitting --kind while attesting an agent bundle green must refuse.
//
// F5: pull --kind with an unknown value must refuse (exit 2), not silently
// widen to both shelves.

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

// packedAgentBundle builds a real agent .skb via ensureBundle and returns its
// path. The cwd is a temp dir, so nothing litters the repo.
func packedAgentBundle(t *testing.T, name string) string {
	t.Helper()
	src := t.TempDir()
	writeAgentDef(t, src, name)
	t.Chdir(t.TempDir())
	out, _, err := ensureBundle(publishAdmitArgs{
		name:      name,
		version:   "1.0.0",
		kind:      skillbundle.KindAgent,
		agentFile: filepath.Join(src, name+".md"),
	}, io.Discard)
	if err != nil {
		t.Fatalf("ensureBundle: %v", err)
	}
	return out
}

// TestAttestBundleGreenAgentRefusedWithoutKindFlag: the bundle is at hand, so
// the manifest decides. No --kind, level green, agent bundle: refused before
// any key is touched. Counter-probe: yellow on the same bundle passes the
// level gate and fails later for an unrelated reason (no key), which is
// exactly the difference asserted.
func TestAttestBundleGreenAgentRefusedWithoutKindFlag(t *testing.T) {
	skb := packedAgentBundle(t, "gate-agent")

	var out, errBuf bytes.Buffer
	rc := runPublishAttest(&out, &errBuf, publishAttestArgs{
		name: "gate-agent", version: "1.0.0",
		bundlePath: skb, level: "green", // NO kind flag
	})
	if rc == 0 {
		t.Fatal("attesting an agent bundle green without --kind returned 0")
	}
	msg := errBuf.String()
	for _, want := range []string{"yellow", "green", "nothing attested"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q does not name %q", msg, want)
		}
	}
	if strings.Contains(msg, "load key") {
		t.Errorf("the refusal ran too late, it already touched the key: %q", msg)
	}

	// Counter-probe: yellow reaches past the level gate.
	var out2, errBuf2 bytes.Buffer
	runPublishAttest(&out2, &errBuf2, publishAttestArgs{
		name: "gate-agent", version: "1.0.0",
		bundlePath: skb, level: "yellow",
	})
	if strings.Contains(errBuf2.String(), "nothing attested") {
		t.Errorf("a yellow agent attest was stopped by the minimum: %q", errBuf2.String())
	}
}

// TestAttestKindFlagContradictsManifest: a flag that disagrees with the
// manifest is refused outright, in both directions of the lie.
func TestAttestKindFlagContradictsManifest(t *testing.T) {
	skb := packedAgentBundle(t, "liar-agent")

	var out, errBuf bytes.Buffer
	rc := runPublishAttest(&out, &errBuf, publishAttestArgs{
		name: "liar-agent", version: "1.0.0",
		bundlePath: skb, kind: skillbundle.KindSkill, level: "green",
	})
	if rc == 0 {
		t.Fatal("a --kind contradicting the manifest was accepted")
	}
	if !strings.Contains(errBuf.String(), "contradicts") {
		t.Errorf("message %q does not say the flag contradicts the manifest", errBuf.String())
	}
}

// TestEnsureBundleReusedBundleKindMismatch (F2, publish half): reusing a
// pre-built agent .skb with --kind skill is refused; the manifest inside the
// bundle is the source, the flag only a claim. Counter-probe: the agreeing
// flag and the omitted flag both accept the same bundle.
func TestEnsureBundleReusedBundleKindMismatch(t *testing.T) {
	skb := packedAgentBundle(t, "reused-agent")

	_, _, err := ensureBundle(publishAdmitArgs{
		name: "reused-agent", version: "1.0.0",
		bundlePath: skb, kind: skillbundle.KindSkill,
	}, io.Discard)
	if err == nil {
		t.Fatal("ensureBundle accepted --kind skill for an agent bundle")
	}
	if !strings.Contains(err.Error(), "contradicts") {
		t.Errorf("error %q does not say the flag contradicts the manifest", err)
	}

	for _, kind := range []string{"", skillbundle.KindAgent} {
		if _, _, err := ensureBundle(publishAdmitArgs{
			name: "reused-agent", version: "1.0.0",
			bundlePath: skb, kind: kind,
		}, io.Discard); err != nil {
			t.Fatalf("ensureBundle(kind=%q) must accept the agent bundle: %v", kind, err)
		}
	}
}

// TestPullRejectsUnknownKind (F5): a typo like "agnet" must refuse with exit
// 2, because shelvesFor treats every unknown value as "both shelves" and the
// pull would silently widen. Counter-probe: a VALID kind passes the kind gate
// and fails later at the trust-roots step (hermetic: M3C_TRUST_ROOTS points
// into an empty temp dir), proving the gate distinguishes rather than
// refusing everything.
func TestPullRejectsUnknownKind(t *testing.T) {
	t.Setenv("M3C_TRUST_ROOTS", filepath.Join(t.TempDir(), "absent.yaml"))

	var out, errBuf bytes.Buffer
	rc := runPull([]string{"--kind", "banana"}, &out, &errBuf)
	if rc != 2 {
		t.Fatalf("pull --kind banana exit = %d, want 2 (stderr: %q)", rc, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "banana") {
		t.Errorf("message %q does not name the bad value", errBuf.String())
	}

	var out2, errBuf2 bytes.Buffer
	rc2 := runPull([]string{"--kind", skillbundle.KindAgent}, &out2, &errBuf2)
	if rc2 == 0 || !strings.Contains(errBuf2.String(), "trust-roots") {
		t.Fatalf("valid --kind must pass the kind gate and stop at trust-roots; exit=%d stderr=%q",
			rc2, errBuf2.String())
	}
}
