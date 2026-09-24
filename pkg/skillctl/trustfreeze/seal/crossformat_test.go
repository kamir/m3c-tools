package seal

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/device"
	"github.com/kamir/m3c-tools/pkg/skillctl/envreport"
	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillgate"
)

// foreignSignature is a real signature produced by an existing m3c-tools
// signing path with the trusted test key, together with the message it
// covers under its own format.
type foreignSignature struct {
	name string
	msg  []byte
	sig  []byte
}

// packAndSign packs a synthetic skill or agent bundle with skillbundle.Pack
// and author-signs it with signing.SignBundle (SPEC-0188 detached signature
// over the raw 32-byte bundle digest). It returns the real signature bytes
// and the signed digest, after checking them with signing.VerifyDetached.
func packAndSign(t *testing.T, root, keyPath, pubPath string, m skillbundle.BundleManifest, anchor string) foreignSignature {
	t.Helper()
	src := filepath.Join(root, "src-"+m.Name)
	writeRaw(t, src, anchor, []byte("# "+m.Name+"\n\nSynthetic fixture for the Trust Freeze cross-format test.\n"))
	out := filepath.Join(root, m.Name+".skb")
	if _, err := skillbundle.Pack(src, out, skillbundle.PackOptions{Manifest: m, BuiltAt: testTime, BuiltBy: "tf-test"}); err != nil {
		t.Fatal(err)
	}
	sigPath, _, err := signing.SignBundle(out, keyPath, "id:alice@example")
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.VerifyDetached(out, pubPath); err != nil {
		t.Fatalf("setup: the %s author signature does not verify in its own format: %v", m.Name, err)
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := signing.ComputeBundleDigest(out)
	if err != nil {
		t.Fatal(err)
	}
	return foreignSignature{msg: digest[:], sig: sig}
}

// realForeignSignatures produces one real signature per existing signed
// m3c-tools format, all with the key of seedTrusted.
func realForeignSignatures(t *testing.T, root string) []foreignSignature {
	t.Helper()
	keyDir := filepath.Join(root, "keys")
	keyPath, pubPath := writeKeyFiles(t, keyDir, "author", seedTrusted)
	priv, err := signing.LoadPrivateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	var out []foreignSignature

	// Skill bundle author signature (SPEC-0188).
	skill := packAndSign(t, root, keyPath, pubPath, skillbundle.BundleManifest{
		Name: "tf-fixture-skill", Version: "0.0.1", Summary: "fixture",
		AuthorGovernanceIntent: "green", Compatibility: "any",
	}, "SKILL.md")
	skill.name = "skill-bundle-author-signature"
	out = append(out, skill)

	// Agent bundle author signature: schema v2, own anchor file.
	agent := packAndSign(t, root, keyPath, pubPath, skillbundle.BundleManifest{
		Kind: skillbundle.KindAgent, Name: "tf-fixture-agent", Version: "0.0.1", Summary: "fixture",
		AuthorGovernanceIntent: "green", Compatibility: "any",
	}, "tf-fixture-agent.md")
	agent.name = "agent-bundle-author-signature"
	out = append(out, agent)

	// Governance attestation (SPEC-0188 Phase 5).
	attMsg, err := signing.CanonicalizeAttestationMessage(fixedDigest("c"), "green", signing.FormatAttestationTimestamp(testTime), "id:alice@example")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, foreignSignature{name: "governance-attestation", msg: attMsg, sig: signing.SignAttestation(priv, attMsg)})

	// Revocation (SPEC-0188).
	revMsg, err := signing.CanonicalizeRevocationMessage(fixedDigest("c"), signing.FormatAttestationTimestamp(testTime), "original_author")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, foreignSignature{name: "revocation", msg: revMsg, sig: signing.SignRevocation(priv, revMsg)})

	// Environment report (SPEC-0428): envreport.Signiere with the same key.
	rep := envreport.Report{
		ENV: "tf-fixture", Principal: "alice", Seq: 1, TakenAt: testTime,
		Posture: envreport.PostureOK, AufbewahrungBis: testTime.Add(24 * time.Hour),
		Zeilen: []envreport.Zeile{{Skill: envreport.SkillRef{Name: "tf-fixture-skill"}, Trust: envreport.Trust{State: "trusted"}}},
	}
	if err := envreport.Signiere(envreport.RohSchluessel(priv), &rep, KeyIDFor(pub)); err != nil {
		t.Fatal(err)
	}
	if err := envreport.PruefeSignatur(pub, rep); err != nil {
		t.Fatalf("setup: the envreport signature does not verify in its own format: %v", err)
	}
	repSig, err := base64.StdEncoding.DecodeString(rep.Signatur)
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, foreignSignature{name: "envreport-signature", sig: repSig})

	// Device key signature over an invocation record (SPEC-0202), with the
	// key loaded through pkg/skillctl/device from a temporary home.
	home := filepath.Join(root, "home")
	writeKeyFiles(t, filepath.Join(home, ".claude", "skillctl"), "device-key", seedTrusted)
	dk, err := device.Load(home)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimPrefix(dk.KeyID(), "device:") != strings.TrimPrefix(KeyIDFor(pub), KeyIDPrefix) {
		t.Fatalf("key id convention drifted from the device key: %s vs %s", dk.KeyID(), KeyIDFor(pub))
	}
	rec := skillgate.InvocationRecord{
		Schema: skillgate.InvocationSchema, EventID: "01J0000000000000000000TEST", EventType: "skill.invocation",
		SkillDigest: fixedDigest("c"), SkillName: "tf-fixture-skill", SkillVersion: "0.0.1",
		Action: "invoke", Tool: "none", OccurredAt: signing.FormatAttestationTimestamp(testTime), DeviceKeyID: dk.KeyID(),
	}
	if err := skillgate.SignInvocationRecord(&rec, dk.Sign, base64.StdEncoding.EncodeToString); err != nil {
		t.Fatal(err)
	}
	if !skillgate.VerifyInvocationRecord(&rec, pub, base64.StdEncoding.DecodeString) {
		t.Fatal("setup: the device signature does not verify in its own format")
	}
	devMsg, _ := skillgate.CanonicalizeInvocationRecord(&rec)
	devSig, _ := base64.StdEncoding.DecodeString(rec.DeviceSignatureB64)
	out = append(out, foreignSignature{name: "device-key-invocation-record", msg: devMsg, sig: devSig})

	for _, f := range out {
		if len(f.sig) != ed25519.SignatureSize {
			t.Fatalf("%s: signature has %d bytes", f.name, len(f.sig))
		}
		if f.msg != nil && !ed25519.Verify(pub, f.msg, f.sig) {
			t.Fatalf("setup: %s signature is not a real signature over its message", f.name)
		}
	}
	return out
}

// TF05-AC4, TF05-R9: a real signature from every other m3c-tools signed
// format, made with the same trusted key, never verifies when placed as the
// Trust Freeze baseline signature. Each case is tried with the honest
// statement hash of the baseline and with the hash of the foreign message.
func TestCrossFormatSignaturesDoNotVerifyAsBaseline(t *testing.T) {
	b := newBaseline(t, nil)
	p := testPolicy(b.signer)
	requireOK(t, Verify(t.Context(), b.dir, p))
	original := readSig(t, b.dir)
	pub := b.signer.PublicKey()
	tfSig, err := base64.StdEncoding.DecodeString(original.Signature)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range realForeignSignatures(t, b.root) {
		t.Run(f.name, func(t *testing.T) {
			hashes := map[string]string{"baseline-statement-hash": original.StatementSHA256}
			if f.msg != nil {
				hashes["foreign-message-hash"] = StatementSHA256(f.msg)
			}
			for hname, h := range hashes {
				d := original
				d.Signature = base64.StdEncoding.EncodeToString(f.sig)
				d.StatementSHA256 = h
				writeSig(t, b.dir, d)
				res := Verify(t.Context(), b.dir, p)
				if res.OK || res.SignatureValid || !res.Has(ReasonBadSignature) {
					t.Fatalf("%s: foreign signature accepted: %s", hname, describe(res))
				}
				if !res.KeyTrusted {
					t.Fatalf("%s: the key is trusted; only the signature may fail", hname)
				}
			}
			// And the other way round: the Trust Freeze signature is not a
			// signature of the foreign message.
			if f.msg != nil && ed25519.Verify(pub, f.msg, tfSig) {
				t.Fatal("the baseline signature verifies as a foreign message")
			}
		})
	}
	writeSig(t, b.dir, original)
	requireOK(t, Verify(t.Context(), b.dir, p))
}

// TF05-R9: the Trust Freeze domain line differs from, and is not a prefix
// relation with, the domain lines of the existing signed formats.
func TestDomainIsSeparateFromExistingFormats(t *testing.T) {
	msg, err := BuildStatement(fixedDigest("a"), fixedDigest("b"), fixedApproval()).Message()
	if err != nil {
		t.Fatal(err)
	}
	first, _, _ := strings.Cut(string(msg), "\n")
	for _, other := range []string{signing.AttestationDomain, signing.RevokeDomain, skillgate.InvocationDomainSeparator, skillgate.CanonicalDomainSeparator} {
		if first == other || strings.HasPrefix(first, other) || strings.HasPrefix(other, first) {
			t.Fatalf("domain %q collides with existing domain %q", first, other)
		}
	}
	if trustfreeze.SchemaSignature == "" || !strings.HasPrefix(Domain, "m3c-tools/trust-freeze/") {
		t.Fatal("domain is not in the Trust Freeze namespace")
	}
}
