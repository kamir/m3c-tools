package seal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// TF05-AC1: a valid baseline verifies offline with trust material loaded from
// local files (a PEM public key and a YAML trust policy). The seal package
// has no network code path (see TestSealPackageHasNoNetworkImports).
func TestVerifyOfflinePass(t *testing.T) {
	b := newBaseline(t, nil)
	keyDir := filepath.Join(b.root, "keys")
	_, pubPath := writeKeyFiles(t, keyDir, "reviewer", seedTrusted)

	tk, err := LoadTrustedKeyPEM(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	p := testPolicy()
	p.TrustedKeys = []TrustedKey{tk}
	res := Verify(t.Context(), b.dir, p)
	requireOK(t, res)
	if res.Kind != trustfreeze.KindBaseline || res.KeyID != b.signer.KeyID() || res.ContentDigest != b.result.ContentDigest || res.CaptureDigest != b.result.CaptureDigest {
		t.Fatalf("result does not describe the baseline: %+v", res)
	}
	if res.Approval == nil || *res.Approval != b.result.Approval {
		t.Fatalf("approval %+v", res.Approval)
	}

	policyFile := filepath.Join(keyDir, "trust-policy.yaml")
	yamlDoc := "schema_version: trust-freeze/trust-policy/v1\nself_approval: warn\ntrusted_keys:\n  - key_id: " +
		tk.KeyID + "\n    public_key: " + base64.StdEncoding.EncodeToString(tk.PublicKey) + "\n"
	if err := os.WriteFile(policyFile, []byte(yamlDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	fp, err := LoadTrustPolicy(policyFile)
	if err != nil {
		t.Fatal(err)
	}
	fp.Now = trustfreeze.FixedClock{T: verifyTime}
	requireOK(t, Verify(t.Context(), b.dir, fp))

	// The JSON form of the result is deterministic.
	j1, err := trustfreeze.MarshalCanonical(res)
	if err != nil {
		t.Fatal(err)
	}
	j2, _ := trustfreeze.MarshalCanonical(Verify(t.Context(), b.dir, p))
	if !bytes.Equal(j1, j2) {
		t.Fatal("verification result JSON is not deterministic")
	}
}

// middleFile returns the manifested path in the middle of the sorted list.
func middleFile(t *testing.T, m trustfreeze.Manifest) string {
	t.Helper()
	if len(m.Files) < 3 {
		t.Fatalf("need at least 3 files, have %d", len(m.Files))
	}
	return m.Files[len(m.Files)/2].Path
}

func removeEntry(m *trustfreeze.Manifest, rel string) {
	out := m.Files[:0]
	for _, f := range m.Files {
		if f.Path != rel {
			out = append(out, f)
		}
	}
	m.Files = out
}

// rewriteIdentityResult plays a forger who keeps the capture documents
// consistent: it rewrites probes/common.identity.json and refreshes its
// manifest entry in m (the caller writes the manifest).
func rewriteIdentityResult(t *testing.T, dir string, m *trustfreeze.Manifest, mutate func(*trustfreeze.ProbeResult)) {
	t.Helper()
	const rel = "probes/common.identity.json"
	var r trustfreeze.ProbeResult
	if err := trustfreeze.UnmarshalCanonicalFile(readRaw(t, dir, rel), &r); err != nil {
		t.Fatal(err)
	}
	mutate(&r)
	writeJSONFile(t, dir, rel, r)
	refreshEntry(t, dir, m, rel)
}

// resign plays an attacker holding signer s: it rebuilds the statement from
// the (tampered) bundle on disk and writes a fresh signature document.
func resign(t *testing.T, dir string, s Signer) {
	t.Helper()
	m := readManifest(t, dir)
	a := readApproval(t, dir)
	d, err := SignStatement(s, BuildStatement(a.CaptureDigest, m.ContentDigest, a))
	if err != nil {
		t.Fatal(err)
	}
	writeSig(t, dir, d)
}

// TF05-R5, TF05-AC2, TF05-AC3: every tamper class fails verification with a
// typed reason. "recomputed" variants play an attacker who also rewrites the
// unsigned manifest consistently; the signature still catches them.
func TestVerifyTamperMatrix(t *testing.T) {
	const evidence = "evidence/common.identity/uname-r"
	cases := []struct {
		name          string
		tamper        func(t *testing.T, b sealed)
		want          []Reason
		wantIntegrity []trustfreeze.IntegrityReason
		exact         bool
	}{
		{
			name: "byte-flip-in-manifested-evidence", // TF05-AC2
			tamper: func(t *testing.T, b sealed) {
				raw := readRaw(t, b.dir, evidence)
				raw[0] ^= 0x01
				writeRaw(t, b.dir, evidence, raw)
			},
			want: []Reason{ReasonIntegrity}, wantIntegrity: []trustfreeze.IntegrityReason{trustfreeze.IntegrityDigestMismatch}, exact: true,
		},
		{
			// The forger also keeps the capture documents consistent (the
			// evidence reference in the probe result); only the signature
			// catches it.
			name: "byte-flip-with-manifest-recomputed",
			tamper: func(t *testing.T, b sealed) {
				raw := readRaw(t, b.dir, evidence)
				raw[len(raw)-2] ^= 0x01
				writeRaw(t, b.dir, evidence, raw)
				m := readManifest(t, b.dir)
				refreshEntry(t, b.dir, &m, evidence)
				rewriteIdentityResult(t, b.dir, &m, func(r *trustfreeze.ProbeResult) {
					for i := range r.RawEvidence {
						if r.RawEvidence[i].Path == evidence {
							r.RawEvidence[i].Size, r.RawEvidence[i].SHA256 = int64(len(raw)), trustfreeze.SHA256Hex(raw)
						}
					}
				})
				writeManifest(t, b.dir, m, true)
			},
			// A capture file changed after approval: the capture rebuilt from
			// the baseline is no longer the approved one either.
			want: []Reason{ReasonStatementMismatch, ReasonBadSignature, ReasonCaptureDigestMismatch}, exact: true,
		},
		{
			// The same flip without touching the probe result: the capture
			// documents contradict each other before any signature is read.
			name: "byte-flip-with-manifest-recomputed-reference-stale",
			tamper: func(t *testing.T, b sealed) {
				raw := readRaw(t, b.dir, evidence)
				raw[len(raw)-2] ^= 0x01
				writeRaw(t, b.dir, evidence, raw)
				m := readManifest(t, b.dir)
				refreshEntry(t, b.dir, &m, evidence)
				writeManifest(t, b.dir, m, true)
			},
			want: []Reason{ReasonCaptureInvalid}, exact: true,
		},
		{
			name: "byte-appended-to-state",
			tamper: func(t *testing.T, b sealed) {
				raw := readRaw(t, b.dir, trustfreeze.StateDeviceFile)
				writeRaw(t, b.dir, trustfreeze.StateDeviceFile, append(raw, ' '))
			},
			want: []Reason{ReasonIntegrity}, wantIntegrity: []trustfreeze.IntegrityReason{trustfreeze.IntegritySizeMismatch},
		},
		{
			name: "middle-file-removed", // TF05-AC3
			tamper: func(t *testing.T, b sealed) {
				mid := middleFile(t, readManifest(t, b.dir))
				if err := os.Remove(filepath.Join(b.dir, filepath.FromSlash(mid))); err != nil {
					t.Fatal(err)
				}
			},
			want: []Reason{ReasonIntegrity}, wantIntegrity: []trustfreeze.IntegrityReason{trustfreeze.IntegrityMissing}, exact: true,
		},
		{
			name: "middle-file-and-record-removed-manifest-recomputed", // TF05-AC3
			tamper: func(t *testing.T, b sealed) {
				m := readManifest(t, b.dir)
				mid := middleFile(t, m)
				if err := os.Remove(filepath.Join(b.dir, filepath.FromSlash(mid))); err != nil {
					t.Fatal(err)
				}
				removeEntry(&m, mid)
				rewriteIdentityResult(t, b.dir, &m, func(r *trustfreeze.ProbeResult) {
					kept := r.RawEvidence[:0]
					for _, ref := range r.RawEvidence {
						if ref.Path != mid {
							kept = append(kept, ref)
						}
					}
					r.RawEvidence = kept
				})
				writeManifest(t, b.dir, m, true)
			},
			// A capture file changed after approval: the capture rebuilt from
			// the baseline is no longer the approved one either.
			want: []Reason{ReasonStatementMismatch, ReasonBadSignature, ReasonCaptureDigestMismatch}, exact: true,
		},
		{
			name: "middle-record-removed-file-kept",
			tamper: func(t *testing.T, b sealed) {
				m := readManifest(t, b.dir)
				removeEntry(&m, middleFile(t, m))
				writeManifest(t, b.dir, m, true)
			},
			want: []Reason{ReasonIntegrity}, wantIntegrity: []trustfreeze.IntegrityReason{trustfreeze.IntegrityExtra},
		},
		{
			name: "extra-unmanifested-file",
			tamper: func(t *testing.T, b sealed) {
				writeRaw(t, b.dir, "evidence/common.identity/extra", []byte("injected"))
			},
			want: []Reason{ReasonIntegrity}, wantIntegrity: []trustfreeze.IntegrityReason{trustfreeze.IntegrityExtra}, exact: true,
		},
		{
			name: "extra-file-under-signatures",
			tamper: func(t *testing.T, b sealed) {
				writeRaw(t, b.dir, "signatures/second.ed25519.json", readRaw(t, b.dir, trustfreeze.SignatureFile))
			},
			want: []Reason{ReasonIntegrity}, wantIntegrity: []trustfreeze.IntegrityReason{trustfreeze.IntegrityExtra}, exact: true,
		},
		{
			// SPEC-0470 section 4.4 step 3: a second signature-shaped file under
			// signatures/, manifested and signed by a trusted key, still fails.
			name: "file-under-signatures-manifested-and-resigned",
			tamper: func(t *testing.T, b sealed) {
				const extra = "signatures/manifest.ed25519.json.bak"
				writeRaw(t, b.dir, extra, readRaw(t, b.dir, trustfreeze.SignatureFile))
				m := readManifest(t, b.dir)
				m.Files = append(m.Files, trustfreeze.FileEntry{Path: extra})
				sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
				refreshEntry(t, b.dir, &m, extra)
				writeManifest(t, b.dir, m, true)
				resign(t, b.dir, b.signer)
			},
			want: []Reason{ReasonIntegrity}, wantIntegrity: []trustfreeze.IntegrityReason{trustfreeze.IntegrityKindLayoutViolation}, exact: true,
		},
		{
			name: "evidence-file-renamed",
			tamper: func(t *testing.T, b sealed) {
				from := filepath.Join(b.dir, filepath.FromSlash(evidence))
				if err := os.Rename(from, from+".txt"); err != nil {
					t.Fatal(err)
				}
			},
			want: []Reason{ReasonIntegrity}, wantIntegrity: []trustfreeze.IntegrityReason{trustfreeze.IntegrityMissing, trustfreeze.IntegrityExtra},
		},
		{
			name: "path-substitution-manifest-recomputed",
			tamper: func(t *testing.T, b sealed) {
				to := "evidence/common.identity/uname-x"
				from := filepath.Join(b.dir, filepath.FromSlash(evidence))
				if err := os.Rename(from, filepath.Join(b.dir, filepath.FromSlash(to))); err != nil {
					t.Fatal(err)
				}
				m := readManifest(t, b.dir)
				for i := range m.Files {
					if m.Files[i].Path == evidence {
						m.Files[i].Path = to
					}
				}
				sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
				rewriteIdentityResult(t, b.dir, &m, func(r *trustfreeze.ProbeResult) {
					for i := range r.RawEvidence {
						if r.RawEvidence[i].Path == evidence {
							r.RawEvidence[i].Path = to
						}
					}
				})
				writeManifest(t, b.dir, m, true)
			},
			// A capture file changed after approval: the capture rebuilt from
			// the baseline is no longer the approved one either.
			want: []Reason{ReasonStatementMismatch, ReasonBadSignature, ReasonCaptureDigestMismatch}, exact: true,
		},
		{
			name: "manifest-entry-substitution-digests-swapped",
			tamper: func(t *testing.T, b sealed) {
				m := readManifest(t, b.dir)
				m.Files[1].SHA256, m.Files[2].SHA256 = m.Files[2].SHA256, m.Files[1].SHA256
				writeManifest(t, b.dir, m, true)
			},
			want: []Reason{ReasonIntegrity}, wantIntegrity: []trustfreeze.IntegrityReason{trustfreeze.IntegrityDigestMismatch}, exact: true,
		},
		{
			name: "manifest-entry-substitution-size-and-digest-swapped",
			tamper: func(t *testing.T, b sealed) {
				m := readManifest(t, b.dir)
				m.Files[1].SHA256, m.Files[2].SHA256 = m.Files[2].SHA256, m.Files[1].SHA256
				m.Files[1].Size, m.Files[2].Size = m.Files[2].Size, m.Files[1].Size
				writeManifest(t, b.dir, m, true)
			},
			want: []Reason{ReasonIntegrity}, wantIntegrity: []trustfreeze.IntegrityReason{trustfreeze.IntegritySizeMismatch}, exact: true,
		},
		{
			name: "manifest-entry-substitution-not-recomputed",
			tamper: func(t *testing.T, b sealed) {
				m := readManifest(t, b.dir)
				m.Files[1].SHA256, m.Files[2].SHA256 = m.Files[2].SHA256, m.Files[1].SHA256
				writeManifest(t, b.dir, m, false)
			},
			want: []Reason{ReasonIntegrity}, wantIntegrity: []trustfreeze.IntegrityReason{trustfreeze.IntegrityContentDigestMismatch, trustfreeze.IntegrityDigestMismatch},
		},
		{
			name: "duplicate-manifest-path",
			tamper: func(t *testing.T, b sealed) {
				m := readManifest(t, b.dir)
				m.Files = append(m.Files, m.Files[1])
				sort.SliceStable(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
				writeManifest(t, b.dir, m, true)
			},
			want: []Reason{ReasonIntegrity}, wantIntegrity: []trustfreeze.IntegrityReason{trustfreeze.IntegrityDuplicatePath},
		},
		{
			name: "dotdot-manifest-path",
			tamper: func(t *testing.T, b sealed) {
				m := readManifest(t, b.dir)
				m.Files = append([]trustfreeze.FileEntry{{Path: "../outside.json", Size: 2, SHA256: trustfreeze.SHA256Hex([]byte("{}"))}}, m.Files...)
				writeManifest(t, b.dir, m, true)
			},
			want: []Reason{ReasonIntegrity}, wantIntegrity: []trustfreeze.IntegrityReason{trustfreeze.IntegrityBadPath},
		},
		{
			name: "absolute-manifest-path",
			tamper: func(t *testing.T, b sealed) {
				m := readManifest(t, b.dir)
				m.Files = append([]trustfreeze.FileEntry{{Path: "/etc/hosts", Size: 2, SHA256: trustfreeze.SHA256Hex([]byte("{}"))}}, m.Files...)
				writeManifest(t, b.dir, m, true)
			},
			want: []Reason{ReasonIntegrity}, wantIntegrity: []trustfreeze.IntegrityReason{trustfreeze.IntegrityBadPath},
		},
		{
			name: "drive-letter-manifest-path",
			tamper: func(t *testing.T, b sealed) {
				m := readManifest(t, b.dir)
				m.Files = append([]trustfreeze.FileEntry{{Path: "C:/Windows/win.ini", Size: 2, SHA256: trustfreeze.SHA256Hex([]byte("{}"))}}, m.Files...)
				writeManifest(t, b.dir, m, true)
			},
			want: []Reason{ReasonIntegrity}, wantIntegrity: []trustfreeze.IntegrityReason{trustfreeze.IntegrityBadPath},
		},
		{
			name: "approval-modified-after-signing",
			tamper: func(t *testing.T, b sealed) {
				// Same length, so the change shows as a digest mismatch.
				a := readApproval(t, b.dir)
				a.Reason = "Reviewed the walking skeleton capture of host-b."
				writeJSONFile(t, b.dir, trustfreeze.ApprovalFile, a)
			},
			want: []Reason{ReasonIntegrity}, wantIntegrity: []trustfreeze.IntegrityReason{trustfreeze.IntegrityDigestMismatch}, exact: true,
		},
		{
			name: "approval-modified-manifest-recomputed",
			tamper: func(t *testing.T, b sealed) {
				a := readApproval(t, b.dir)
				a.ChangeID = "CHG-9999"
				writeJSONFile(t, b.dir, trustfreeze.ApprovalFile, a)
				m := readManifest(t, b.dir)
				refreshEntry(t, b.dir, &m, trustfreeze.ApprovalFile)
				writeManifest(t, b.dir, m, true)
			},
			want: []Reason{ReasonStatementMismatch, ReasonBadSignature}, exact: true,
		},
		{
			name: "approval-rewritten-with-crlf-manifest-recomputed",
			tamper: func(t *testing.T, b sealed) {
				raw := readRaw(t, b.dir, trustfreeze.ApprovalFile)
				writeRaw(t, b.dir, trustfreeze.ApprovalFile, bytes.ReplaceAll(raw, []byte("\n"), []byte("\r\n")))
				m := readManifest(t, b.dir)
				refreshEntry(t, b.dir, &m, trustfreeze.ApprovalFile)
				writeManifest(t, b.dir, m, true)
			},
			want: []Reason{ReasonApprovalInvalid}, exact: true,
		},
		{
			name: "approval-modified-and-resigned-by-untrusted-key",
			tamper: func(t *testing.T, b sealed) {
				attacker := seedSigner(t, seedAttacker)
				a := readApproval(t, b.dir)
				a.Reason = "Approved by someone else."
				a.Identities.SigningKeyID = attacker.KeyID()
				writeJSONFile(t, b.dir, trustfreeze.ApprovalFile, a)
				m := readManifest(t, b.dir)
				refreshEntry(t, b.dir, &m, trustfreeze.ApprovalFile)
				writeManifest(t, b.dir, m, true)
				resign(t, b.dir, attacker)
			},
			want: []Reason{ReasonKeyNotTrusted}, exact: true,
		},
		{
			name: "approval-file-and-record-removed",
			tamper: func(t *testing.T, b sealed) {
				if err := os.Remove(filepath.Join(b.dir, trustfreeze.ApprovalFile)); err != nil {
					t.Fatal(err)
				}
				m := readManifest(t, b.dir)
				removeEntry(&m, trustfreeze.ApprovalFile)
				writeManifest(t, b.dir, m, true)
			},
			want: []Reason{ReasonIntegrity, ReasonMissingApproval}, wantIntegrity: []trustfreeze.IntegrityReason{trustfreeze.IntegrityKindLayoutViolation},
		},
		{
			name: "signature-file-removed",
			tamper: func(t *testing.T, b sealed) {
				if err := os.RemoveAll(filepath.Join(b.dir, trustfreeze.SignaturesDir)); err != nil {
					t.Fatal(err)
				}
			},
			want: []Reason{ReasonIntegrity, ReasonMissingSignature}, wantIntegrity: []trustfreeze.IntegrityReason{trustfreeze.IntegrityKindLayoutViolation},
		},
		{
			name: "signature-replaced-by-random-bytes",
			tamper: func(t *testing.T, b sealed) {
				d := readSig(t, b.dir)
				junk := sha256.Sum256([]byte("junk"))
				d.Signature = base64.StdEncoding.EncodeToString(append(junk[:], junk[:]...))
				writeSig(t, b.dir, d)
			},
			want: []Reason{ReasonBadSignature}, exact: true,
		},
		{
			name: "signature-replaced-by-trusted-signature-over-other-statement",
			tamper: func(t *testing.T, b sealed) {
				m := readManifest(t, b.dir)
				a := readApproval(t, b.dir)
				a.Reason = "A different approval text."
				d, err := SignStatement(b.signer, BuildStatement(a.CaptureDigest, m.ContentDigest, a))
				if err != nil {
					t.Fatal(err)
				}
				writeSig(t, b.dir, d)
			},
			want: []Reason{ReasonStatementMismatch, ReasonBadSignature}, exact: true,
		},
		{
			name: "signature-by-attacker-with-trusted-public-key-claimed",
			tamper: func(t *testing.T, b sealed) {
				attacker := seedSigner(t, seedAttacker)
				m := readManifest(t, b.dir)
				a := readApproval(t, b.dir)
				msg, err := BuildStatement(a.CaptureDigest, m.ContentDigest, a).Message()
				if err != nil {
					t.Fatal(err)
				}
				sig, _ := attacker.Sign(msg)
				d := readSig(t, b.dir)
				d.Signature = base64.StdEncoding.EncodeToString(sig)
				writeSig(t, b.dir, d)
			},
			want: []Reason{ReasonBadSignature}, exact: true,
		},
		{
			name: "signature-doc-domain-changed",
			tamper: func(t *testing.T, b sealed) {
				d := readSig(t, b.dir)
				d.Domain = "attestation"
				writeSig(t, b.dir, d)
			},
			want: []Reason{ReasonDomainMismatch}, exact: true,
		},
		{
			name: "signature-doc-key-id-not-of-public-key",
			tamper: func(t *testing.T, b sealed) {
				d := readSig(t, b.dir)
				d.KeyID = seedSigner(t, seedAttacker).KeyID()
				writeSig(t, b.dir, d)
			},
			want: []Reason{ReasonSignatureMalformed}, exact: true,
		},
		{
			name: "signature-doc-wrong-algorithm",
			tamper: func(t *testing.T, b sealed) {
				d := readSig(t, b.dir)
				d.Algorithm = "rsa"
				writeSig(t, b.dir, d)
			},
			want: []Reason{ReasonSignatureMalformed}, exact: true,
		},
		{
			name: "signature-doc-wrong-schema",
			tamper: func(t *testing.T, b sealed) {
				d := readSig(t, b.dir)
				d.SchemaVersion = trustfreeze.SchemaApproval
				writeSig(t, b.dir, d)
			},
			want: []Reason{ReasonSignatureMalformed}, exact: true,
		},
		{
			name: "signature-doc-not-canonical",
			tamper: func(t *testing.T, b sealed) {
				raw := readRaw(t, b.dir, trustfreeze.SignatureFile)
				writeRaw(t, b.dir, trustfreeze.SignatureFile, bytes.ReplaceAll(raw, []byte("\n"), []byte("\r\n")))
			},
			want: []Reason{ReasonSignatureMalformed}, exact: true,
		},
		{
			name: "signature-doc-base64-with-newline",
			tamper: func(t *testing.T, b sealed) {
				d := readSig(t, b.dir)
				d.Signature = d.Signature[:40] + "\n" + d.Signature[40:]
				writeSig(t, b.dir, d)
			},
			want: []Reason{ReasonSignatureMalformed}, exact: true,
		},
		{
			name: "signature-file-oversized",
			tamper: func(t *testing.T, b sealed) {
				writeRaw(t, b.dir, trustfreeze.SignatureFile, bytes.Repeat([]byte(" "), 1<<20+1))
			},
			want: []Reason{ReasonSignatureMalformed}, exact: true,
		},
		{
			name: "statement-sha-edited-to-match-other-statement",
			tamper: func(t *testing.T, b sealed) {
				d := readSig(t, b.dir)
				d.StatementSHA256 = trustfreeze.SHA256Hex([]byte("another statement"))
				writeSig(t, b.dir, d)
			},
			want: []Reason{ReasonStatementMismatch}, exact: true,
		},
		{
			name: "manifest-kind-changed-to-capture",
			tamper: func(t *testing.T, b sealed) {
				m := readManifest(t, b.dir)
				m.Kind = trustfreeze.KindCapture
				writeManifest(t, b.dir, m, true)
			},
			want: []Reason{ReasonWrongKind, ReasonIntegrity}, wantIntegrity: []trustfreeze.IntegrityReason{trustfreeze.IntegrityKindLayoutViolation},
		},
		{
			name: "manifest-kind-unknown",
			tamper: func(t *testing.T, b sealed) {
				raw := readRaw(t, b.dir, trustfreeze.ManifestFile)
				writeRaw(t, b.dir, trustfreeze.ManifestFile, bytes.Replace(raw, []byte(`"kind": "baseline"`), []byte(`"kind": "baseline2"`), 1))
			},
			want: []Reason{ReasonIntegrity}, wantIntegrity: []trustfreeze.IntegrityReason{trustfreeze.IntegrityUnknownKind},
		},
		{
			name: "state-not-canonical-manifest-recomputed-and-resigned",
			tamper: func(t *testing.T, b sealed) {
				raw := readRaw(t, b.dir, trustfreeze.StateDeviceFile)
				writeRaw(t, b.dir, trustfreeze.StateDeviceFile, bytes.ReplaceAll(raw, []byte("\n"), []byte("\r\n")))
				m := readManifest(t, b.dir)
				refreshEntry(t, b.dir, &m, trustfreeze.StateDeviceFile)
				writeManifest(t, b.dir, m, true)
				resign(t, b.dir, b.signer)
			},
			want: []Reason{ReasonCaptureInvalid}, exact: true,
		},
		{
			name: "capture-actor-changed-manifest-recomputed-and-resigned",
			tamper: func(t *testing.T, b sealed) {
				// The approval still names alice as capture actor, capture.json
				// now says mallory. Even a trusted re-signer cannot hide the
				// contradiction.
				raw := readRaw(t, b.dir, trustfreeze.CaptureFile)
				writeRaw(t, b.dir, trustfreeze.CaptureFile, bytes.Replace(raw, []byte(`"actor": "alice"`), []byte(`"actor": "mallory"`), 1))
				m := readManifest(t, b.dir)
				refreshEntry(t, b.dir, &m, trustfreeze.CaptureFile)
				writeManifest(t, b.dir, m, true)
				resign(t, b.dir, b.signer)
			},
			// capture.json changed after approval, so the approved capture
			// digest no longer matches the capture the baseline holds.
			want: []Reason{ReasonApprovalInvalid, ReasonCaptureDigestMismatch}, exact: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newBaseline(t, nil)
			requireOK(t, Verify(t.Context(), b.dir, testPolicy(b.signer)))
			tc.tamper(t, b)
			res := Verify(t.Context(), b.dir, testPolicy(b.signer))
			requireReasons(t, res, tc.want, tc.wantIntegrity...)
			if tc.exact {
				requireExactReasons(t, res, tc.want...)
			}
		})
	}
}

// SPEC-0470 section 4.6: a signature by a key outside the trust policy fails
// with key_not_trusted, while the cryptographic check is reported separately.
func TestVerifyUntrustedSigningKey(t *testing.T) {
	root := t.TempDir()
	capDir, _ := newCapture(t, root, "capture", defaultFixture())
	other := seedSigner(t, seedSecond)
	out := filepath.Join(root, "baseline")
	if _, err := Seal(t.Context(), defaultRequest(capDir, out, other)); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]TrustPolicy{
		"other-key-trusted": testPolicy(seedSigner(t, seedTrusted)),
		"no-key-trusted":    testPolicy(),
	} {
		t.Run(name, func(t *testing.T) {
			res := Verify(t.Context(), out, p)
			requireExactReasons(t, res, ReasonKeyNotTrusted)
			if !res.SignatureChecked || !res.SignatureValid || res.KeyTrusted {
				t.Fatalf("signature_checked=%v signature_valid=%v key_trusted=%v", res.SignatureChecked, res.SignatureValid, res.KeyTrusted)
			}
		})
	}
	requireOK(t, Verify(t.Context(), out, testPolicy(other)))
}

// TF05-R5, TF05-AC4: a signature copied from another Trust Freeze baseline,
// signed by the same trusted key, does not verify.
func TestVerifySignatureCopiedFromAnotherBaseline(t *testing.T) {
	root := t.TempDir()
	s := seedSigner(t, seedTrusted)
	capA, _ := newCapture(t, root, "capture-a", defaultFixture())
	fxB := defaultFixture()
	fxB.kernel = "6.8.0-other"
	capB, _ := newCapture(t, root, "capture-b", fxB)
	outA, outB := filepath.Join(root, "baseline-a"), filepath.Join(root, "baseline-b")
	if _, err := Seal(t.Context(), defaultRequest(capA, outA, s)); err != nil {
		t.Fatal(err)
	}
	reqB := defaultRequest(capB, outB, s)
	reqB.Approval.ChangeID = "CHG-0002"
	if _, err := Seal(t.Context(), reqB); err != nil {
		t.Fatal(err)
	}
	requireOK(t, Verify(t.Context(), outB, testPolicy(s)))

	writeRaw(t, outA, trustfreeze.SignatureFile, readRaw(t, outB, trustfreeze.SignatureFile))
	res := Verify(t.Context(), outA, testPolicy(s))
	requireExactReasons(t, res, ReasonStatementMismatch, ReasonBadSignature)

	// Same capture, second approval: still not interchangeable.
	outA2 := filepath.Join(root, "baseline-a2")
	reqA2 := defaultRequest(capA, outA2, s)
	reqA2.Approval.ChangeID = "CHG-0003"
	if _, err := Seal(t.Context(), reqA2); err != nil {
		t.Fatal(err)
	}
	writeRaw(t, outA2, trustfreeze.SignatureFile, readRaw(t, outB, trustfreeze.SignatureFile))
	requireExactReasons(t, Verify(t.Context(), outA2, testPolicy(s)), ReasonStatementMismatch, ReasonBadSignature)
}

// TF05-R1, TF05-R5, TF05-AC4: a capture that carries a copied baseline
// signature (and even approval.json) never verifies as a baseline.
func TestVerifySignatureCopiedIntoCapture(t *testing.T) {
	b := newBaseline(t, nil)
	p := testPolicy(b.signer)

	t.Run("signature-only", func(t *testing.T) {
		capDir, _ := newCapture(t, t.TempDir(), "capture", defaultFixture())
		writeRaw(t, capDir, trustfreeze.SignatureFile, readRaw(t, b.dir, trustfreeze.SignatureFile))
		if integ := trustfreeze.VerifyDir(capDir); integ.OK || !integ.Has(trustfreeze.IntegrityKindLayoutViolation) {
			t.Fatalf("core accepted a capture with signatures/: %+v", integ.Failures)
		}
		res := Verify(t.Context(), capDir, p)
		requireReasons(t, res, []Reason{ReasonWrongKind, ReasonIntegrity}, trustfreeze.IntegrityKindLayoutViolation)
		if res.SignatureChecked {
			t.Fatal("a capture's signature was checked")
		}
	})
	t.Run("signature-and-approval", func(t *testing.T) {
		capDir, _ := newCapture(t, t.TempDir(), "capture", defaultFixture())
		writeRaw(t, capDir, trustfreeze.SignatureFile, readRaw(t, b.dir, trustfreeze.SignatureFile))
		writeRaw(t, capDir, trustfreeze.ApprovalFile, readRaw(t, b.dir, trustfreeze.ApprovalFile))
		requireReasons(t, Verify(t.Context(), capDir, p), []Reason{ReasonWrongKind, ReasonIntegrity}, trustfreeze.IntegrityKindLayoutViolation)
	})
	t.Run("capture-relabeled-as-baseline", func(t *testing.T) {
		// The attacker turns the capture into a baseline-shaped bundle: copies
		// approval.json and the signature, relabels the manifest kind, lists
		// approval.json and recomputes the content digest. Integrity passes,
		// the statement does not.
		capDir, _ := newCapture(t, t.TempDir(), "capture", defaultFixture())
		writeRaw(t, capDir, trustfreeze.SignatureFile, readRaw(t, b.dir, trustfreeze.SignatureFile))
		writeRaw(t, capDir, trustfreeze.ApprovalFile, readRaw(t, b.dir, trustfreeze.ApprovalFile))
		m := readManifest(t, capDir)
		m.Kind = trustfreeze.KindBaseline
		approval := readRaw(t, capDir, trustfreeze.ApprovalFile)
		m.Files = append(m.Files, trustfreeze.FileEntry{Path: trustfreeze.ApprovalFile, Size: int64(len(approval)), SHA256: trustfreeze.SHA256Hex(approval)})
		sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
		writeManifest(t, capDir, m, true)
		if integ := trustfreeze.VerifyDir(capDir); !integ.OK {
			t.Fatalf("setup: relabeled bundle should pass integrity: %v", integ.Err())
		}
		requireExactReasons(t, Verify(t.Context(), capDir, p), ReasonStatementMismatch, ReasonBadSignature)
	})
}

// TF05-R1, TF05-AC4: a statement of kind capture, signed by a trusted key
// under the Trust Freeze domain, does not verify as a baseline.
func TestVerifyCaptureKindStatementDoesNotVerifyAsBaseline(t *testing.T) {
	b := newBaseline(t, nil)
	m := readManifest(t, b.dir)
	a := readApproval(t, b.dir)
	for _, variant := range []struct {
		name   string
		schema string
		digest string
	}{
		{"capture-kind-baseline-schema", trustfreeze.SchemaBaseline, m.ContentDigest},
		{"capture-kind-capture-schema", trustfreeze.SchemaCapture, m.ContentDigest},
		{"capture-kind-over-capture-digest", trustfreeze.SchemaCapture, a.CaptureDigest},
	} {
		t.Run(variant.name, func(t *testing.T) {
			st := BuildStatement(a.CaptureDigest, variant.digest, a)
			st.Kind = trustfreeze.KindCapture
			st.SchemaVersion = variant.schema
			msg, err := st.Message()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := SignStatement(b.signer, st); err == nil {
				t.Fatal("SignStatement signed a capture-kind statement")
			}
			sig, err := b.signer.Sign(msg)
			if err != nil {
				t.Fatal(err)
			}
			d := readSig(t, b.dir)
			d.Signature = base64.StdEncoding.EncodeToString(sig)
			d.StatementSHA256 = StatementSHA256(msg)
			writeSig(t, b.dir, d)
			requireExactReasons(t, Verify(t.Context(), b.dir, testPolicy(b.signer)), ReasonStatementMismatch, ReasonBadSignature)
		})
	}
}

// TF05-AC7: expiry is decided by the injected clock; no wall clock, no
// sleep. A baseline is valid up to and including expires_at.
func TestVerifyExpiryWithInjectedClock(t *testing.T) {
	expires := approveTime.Add(24 * time.Hour).Add(123 * time.Nanosecond)
	b := newBaseline(t, func(r *SealRequest) { r.Approval.ExpiresAt = expires })
	if got := b.result.Approval.ExpiresAt; got != trustfreeze.FormatTime(expires) {
		t.Fatalf("expires_at %q", got)
	}
	cases := []struct {
		name    string
		now     time.Time
		expired bool
	}{
		{"one-nanosecond-before", expires.Add(-time.Nanosecond), false},
		{"exactly-at", expires, false},
		{"one-nanosecond-after", expires.Add(time.Nanosecond), true},
		{"a-year-after", expires.AddDate(1, 0, 0), true},
		{"at-approval", approveTime, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testPolicy(b.signer)
			p.Now = trustfreeze.FixedClock{T: tc.now}
			res := Verify(t.Context(), b.dir, p)
			if !tc.expired {
				requireOK(t, res)
				return
			}
			requireExactReasons(t, res, ReasonExpired)
			if !res.SignatureValid || !res.KeyTrusted {
				t.Fatal("expiry must not hide the signature result")
			}
		})
	}

	t.Run("no-expiry-never-expires", func(t *testing.T) {
		nb := newBaseline(t, nil)
		p := testPolicy(nb.signer)
		p.Now = trustfreeze.FixedClock{T: approveTime.AddDate(50, 0, 0)}
		requireOK(t, Verify(t.Context(), nb.dir, p))
	})
}

// TF05-AC6 at verification time: the verifier's policy decides.
func TestVerifySelfApprovalPolicy(t *testing.T) {
	b := newBaseline(t, func(r *SealRequest) {
		r.SelfApproval = SelfApprovalAllow
		r.Approval.Reviewer = "alice" // the capture actor
		r.Approval.ApproverSubjectID = defaultFixture().subject().ID
	})
	cases := []struct {
		mode      SelfApprovalMode
		blocked   bool
		wantWarns int
	}{
		{SelfApprovalAllow, false, 0},
		{SelfApprovalWarn, false, 2},
		{"", false, 2},
		{SelfApprovalBlock, true, 0},
	}
	for _, tc := range cases {
		t.Run("mode-"+string(tc.mode), func(t *testing.T) {
			p := testPolicy(b.signer)
			p.SelfApproval = tc.mode
			res := Verify(t.Context(), b.dir, p)
			if tc.blocked {
				requireExactReasons(t, res, ReasonSelfApprovalBlocked)
				return
			}
			requireOK(t, res)
			if len(res.Warnings) != tc.wantWarns {
				t.Fatalf("warnings %+v, want %d", res.Warnings, tc.wantWarns)
			}
		})
	}
	// An independent approval passes block mode.
	ind := newBaseline(t, nil)
	p := testPolicy(ind.signer)
	p.SelfApproval = SelfApprovalBlock
	requireOK(t, Verify(t.Context(), ind.dir, p))

	// A baseline without identities.signing_device_id (approved in allow
	// mode, or on a host whose name could not be read) cannot pass the
	// same-device check: block fails closed, warn says so, allow is silent.
	nodev := newBaseline(t, func(r *SealRequest) {
		r.SelfApproval = SelfApprovalAllow
		r.Approval.ApproverSubjectID = ""
	})
	if nodev.result.Approval.Identities.SigningDeviceID != "" {
		t.Fatal("fixture: signing_device_id is set")
	}
	for _, tc := range []struct {
		mode    SelfApprovalMode
		blocked bool
		warns   []string
	}{
		{SelfApprovalBlock, true, nil},
		{SelfApprovalWarn, false, []string{CodeSelfApprovalDeviceUnknown}},
		{SelfApprovalAllow, false, nil},
	} {
		p := testPolicy(nodev.signer)
		p.SelfApproval = tc.mode
		res := Verify(t.Context(), nodev.dir, p)
		if tc.blocked {
			requireExactReasons(t, res, ReasonSelfApprovalBlocked)
			if !strings.Contains(res.Failures[0].Detail, CodeSelfApprovalDeviceUnknown) {
				t.Fatalf("block detail %q, want %s", res.Failures[0].Detail, CodeSelfApprovalDeviceUnknown)
			}
			continue
		}
		requireOK(t, res)
		var codes []string
		for _, w := range res.Warnings {
			codes = append(codes, w.Code)
		}
		if strings.Join(codes, ",") != strings.Join(tc.warns, ",") {
			t.Fatalf("mode %s: warnings %v, want %v", tc.mode, codes, tc.warns)
		}
	}
}

func TestVerifyEdgeCases(t *testing.T) {
	b := newBaseline(t, nil)
	t.Run("invalid-trust-policy", func(t *testing.T) {
		p := testPolicy(b.signer)
		p.TrustedKeys[0].PublicKey = p.TrustedKeys[0].PublicKey[:31]
		requireExactReasons(t, Verify(t.Context(), b.dir, p), ReasonTrustPolicyInvalid)
		p = testPolicy(b.signer)
		p.SelfApproval = "maybe"
		requireExactReasons(t, Verify(t.Context(), b.dir, p), ReasonTrustPolicyInvalid)
	})
	t.Run("canceled-context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		requireExactReasons(t, Verify(ctx, b.dir, testPolicy(b.signer)), ReasonCanceled)
	})
	t.Run("missing-directory", func(t *testing.T) {
		res := Verify(t.Context(), filepath.Join(b.root, "nope"), testPolicy(b.signer))
		requireReasons(t, res, []Reason{ReasonIntegrity}, trustfreeze.IntegrityUnreadable)
	})
	t.Run("capture-bundle", func(t *testing.T) {
		res := Verify(t.Context(), b.captureDir, testPolicy(b.signer))
		requireExactReasons(t, res, ReasonWrongKind)
		if !res.Integrity.OK {
			t.Fatal("an untouched capture should pass integrity")
		}
	})
}
