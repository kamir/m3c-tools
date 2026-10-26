package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

func nativeSkillEvidenceEntries(t *testing.T) []skillbundle.Entry {
	t.Helper()
	manifest := []byte(`{"schema":"m3c-skill-bundle/v1","name":"retained-skill","version":"1.0.0","depends_on":[],"bundle_digest":"canonical-pass-informational"}`)
	entries := []skillbundle.Entry{{Rel: "bundle.json", Content: manifest}, {Rel: "SKILL.md", Content: []byte("# retained inert skill\n")}, {Rel: "references/a.txt", Content: []byte("retained reference\n")}, {Rel: "scripts/check.sh", Content: []byte("#!/bin/sh\nexit 99\n")}}
	return nativeSkillEvidenceChecksumEntries(entries)
}
func nativeSkillEvidenceChecksumEntries(entries []skillbundle.Entry) []skillbundle.Entry {
	var out []skillbundle.Entry
	var names []string
	payload := map[string][]byte{}
	for _, e := range entries {
		if e.Rel == "CHECKSUMS" {
			continue
		}
		out = append(out, e)
		if !e.IsDir && e.Rel != "bundle.json" {
			names = append(names, e.Rel)
			payload[e.Rel] = e.Content
		}
	}
	sort.Strings(names)
	var text strings.Builder
	for _, name := range names {
		sum := sha256.Sum256(payload[name])
		text.WriteString(hex.EncodeToString(sum[:]))
		text.WriteString("  ")
		text.WriteString(name)
		text.WriteByte('\n')
	}
	return append(out, skillbundle.Entry{Rel: "CHECKSUMS", Content: []byte(text.String())})
}
func nativeSkillEvidenceFixture(t *testing.T, archive []byte) *qaAgentFixture {
	t.Helper()
	f := qaAgentSignedNamed(t, "retained-skill", archive)
	f.staged.Kind = skillbundle.KindSkill
	f.staged.StagedSkbPath = ""
	f.staged.ProvenancePath = ""
	return f
}
func nativeSkillEvidenceSet(entries []skillbundle.Entry, rel string, content []byte) []skillbundle.Entry {
	out := append([]skillbundle.Entry(nil), entries...)
	for i := range out {
		if out[i].Rel == rel {
			out[i].Content = content
			return out
		}
	}
	return append(out, skillbundle.Entry{Rel: rel, Content: content})
}

func TestNativeSkillRetainedEvidence(t *testing.T) {
	t.Run("realPackSignedFullQuorumAndImmutable", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# real Pack skill\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(dir, "references"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "references", "data.txt"), []byte("inert bytes\n"), 0600); err != nil {
			t.Fatal(err)
		}
		var packed bytes.Buffer
		if _, err := skillbundle.PackToWriter(dir, &packed, skillbundle.PackOptions{Manifest: skillbundle.BundleManifest{Name: "retained-skill", Version: "1.0.0", DependsOn: []skillbundle.Dependency{}}}); err != nil {
			t.Fatal(err)
		}
		raw := packed.Bytes()
		f := nativeSkillEvidenceFixture(t, raw)
		prepared, err := prepareNativeSkillEvidence(f.staged, raw, f.opts())
		if err != nil {
			t.Fatal(err)
		}
		if prepared.bundle.Kind != skillbundle.KindSkill || prepared.manifest.EffectiveKind() != skillbundle.KindSkill || !bytes.Equal(prepared.archive, raw) || len(prepared.bundle.Attestation.GovernanceAttestations) != 2 {
			t.Fatal("lost retained archive/kind/full quorum")
		}
		if prepared.manifest.BundleDigest == f.staged.Digest {
			t.Fatal("fixture must distinguish canonical-pass and outer digest")
		}
		if err = verifyAgentContext(prepared.roots, prepared.bundle.Attestation, f.staged.Digest, f.name, "1.0.0", f.now); err != nil {
			t.Fatal(err)
		}
		frozen := bytes.Clone(prepared.archive)
		contextRaw := bytes.Clone(prepared.contextRaw)
		root := bytes.Clone(prepared.roots.pub)
		raw[0] ^= 1
		f.staged.Attestation.AdmitEvent["name"] = "mutated"
		f.staged.Attestation.GovernanceAttestations[1]["reviewer_id"] = "mutated"
		f.roots.pub[0] ^= 1
		if !bytes.Equal(prepared.archive, frozen) || !bytes.Equal(prepared.contextRaw, contextRaw) || !bytes.Equal(prepared.roots.pub, root) || prepared.bundle.Attestation.AdmitEvent["name"] != "retained-skill" {
			t.Fatal("caller mutation changed private retained snapshot")
		}
	})
	t.Run("sourceSignerBudgetBeforeVerification", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		a := f.agent
		entries := nativeSkillEvidenceEntries(t)
		manifest := []byte(fmt.Sprintf(`{"schema":"m3c-skill-bundle/v1","name":%q,"version":"1.0.0","depends_on":[]}`, a.name))
		archive := qaAgentArchive(t, nativeSkillEvidenceSet(entries, "bundle.json", manifest))
		item, digest := mintAdmitItem(t, a.registryKey, a.name, "1.0.0", string(archive))
		event, err := extractEvent(itemBody(item))
		if err != nil {
			t.Fatal(err)
		}
		att := &AttestationContext{AdmitEvent: event}
		for i, key := range a.signerKeys {
			att.GovernanceAttestations = append(att.GovernanceAttestations, signedAttest(t, key, a.roots.Signers[i].ReviewerID, digest, "green", a.now.Add(-time.Minute).Format(time.RFC3339), nil))
		}
		att.GovernanceAttestation = att.GovernanceAttestations[0]
		wire := func(context *AttestationContext) []byte {
			t.Helper()
			events := append([]map[string]any{context.AdmitEvent}, context.GovernanceAttestations...)
			var items []any
			for i, event := range events {
				raw, e := json.Marshal(event)
				if e != nil {
					t.Fatal(e)
				}
				body := "```json\n" + string(raw) + "\n```\n"
				if i == 0 {
					body += "```skb-base64\n" + base64.StdEncoding.EncodeToString(archive) + "\n```\n"
				}
				items = append(items, map[string]any{"id": fmt.Sprint(i), "transcript": body})
			}
			return nativeLiveTestWire(t, items)
		}
		positive := &nativeLiveWork{}
		candidate, err := nativeLiveParseSelected(wire(att), "", f.journal, digest, skillbundle.KindSkill, positive)
		if err != nil || candidate == nil || candidate.Bundle.Kind != skillbundle.KindSkill || positive.verificationCalls != 1 || !bytes.Equal(candidate.Archive, archive) {
			t.Fatalf("genuine full-quorum source positive failed: %v", err)
		}
		invalid, _, err := snapshotAgentContext(att)
		if err != nil {
			t.Fatal(err)
		}
		invalid.AdmitEvent["envelope_signature"] = base64.StdEncoding.EncodeToString(make([]byte, 64))
		_, contextRaw, err := snapshotAgentContext(invalid)
		if err != nil {
			t.Fatal(err)
		}
		raw := wire(invalid)
		ample := &nativeLiveWork{}
		candidate, err = nativeLiveParseSelected(raw, "", f.journal, digest, skillbundle.KindSkill, ample)
		if candidate != nil || !errors.Is(err, ErrNativeEvidenceInvalid) || ample.verificationCalls != 1 {
			t.Fatal("invalid signature did not reach verification")
		}
		reserve := 4 * int64(len(contextRaw)) * int64(len(f.journal.selection.artifactRoots.Signers)+1)
		overhead := ample.bytes - reserve
		if reserve <= 0 || overhead < 0 || ample.bytes >= nativeLiveWorkMax {
			t.Fatal("invalid resource fixture accounting")
		}
		low := &nativeLiveWork{bytes: nativeLiveWorkMax - overhead - reserve + 1}
		candidate, err = nativeLiveParseSelected(raw, "", f.journal, digest, skillbundle.KindSkill, low)
		if candidate != nil || !errors.Is(err, ErrNativeEvidenceInvalid) || low.verificationCalls != 0 || low.bytes != nativeLiveWorkMax-reserve+1 {
			t.Fatalf("one-byte-short reservation must deny BEFORE verification: calls=%d bytes=%d err=%v", low.verificationCalls, low.bytes, err)
		}
		exact := &nativeLiveWork{bytes: nativeLiveWorkMax - overhead - reserve}
		candidate, err = nativeLiveParseSelected(raw, "", f.journal, digest, skillbundle.KindSkill, exact)
		if candidate != nil || !errors.Is(err, ErrNativeEvidenceInvalid) || exact.verificationCalls != 1 || exact.bytes != nativeLiveWorkMax {
			t.Fatal("exact-fit reservation did not reach signature denial")
		}
		agent := &nativeLiveWork{}
		candidate, err = nativeLiveParseSelected(raw, "", f.journal, digest, skillbundle.KindAgent, agent)
		if candidate != nil || !errors.Is(err, ErrNativeEvidenceInvalid) || agent.verificationCalls != 1 || agent.bytes != overhead {
			t.Fatal("agent accounting changed")
		}
	})

	t.Run("numericReleaseSignedVersions", func(t *testing.T) {
		valid := []string{"0", "1", "1.0", "1.0.0", "1.0.0.0", "18446744073709551615.18446744073709551615.18446744073709551615.18446744073709551615"}
		invalid := []string{"", "v1.0.0", "1.0.0-rc", "1.0.0+meta", " 1.0.0", "01.0", "-1", "1..0", "1.2.3.4.5", "18446744073709551616"}
		for _, group := range []struct {
			versions []string
			accepted bool
		}{{valid, true}, {invalid, false}} {
			for _, version := range group.versions {
				t.Run(fmt.Sprintf("%t-%q", group.accepted, version), func(t *testing.T) {
					entries := nativeSkillEvidenceEntries(t)
					var manifest map[string]any
					if err := json.Unmarshal(entries[0].Content, &manifest); err != nil {
						t.Fatal(err)
					}
					manifest["version"] = version
					rawManifest, err := json.Marshal(manifest)
					if err != nil {
						t.Fatal(err)
					}
					archive := qaAgentArchive(t, nativeSkillEvidenceSet(entries, "bundle.json", rawManifest))
					// The ordinary event builder correctly refuses an empty version.
					// Start with a valid fixture, then independently sign the
					// exact unsupported version map to exercise the consumer.
					f := nativeSkillEvidenceFixture(t, qaAgentArchive(t, nativeSkillEvidenceEntries(t)))
					f.blob = archive
					f.staged.Digest = agentDigest(archive)
					item, digest := mintAdmitItem(t, f.registryKey, f.name, "1.0.0", string(archive))
					event, err := extractEvent(itemBody(item))
					if err != nil {
						t.Fatal(err)
					}
					event["version"] = version
					if _, err = SignEnvelopeSignature(f.registryKey, event); err != nil {
						t.Fatal(err)
					}
					f.staged.Version = version
					f.staged.Attestation.AdmitEvent = event
					f.staged.Attestation.GovernanceAttestations = nil
					for i, key := range f.signerKeys {
						f.staged.Attestation.GovernanceAttestations = append(f.staged.Attestation.GovernanceAttestations, signedAttest(t, key, f.roots.Signers[i].ReviewerID, digest, "green", f.now.Add(-time.Minute).Format(time.RFC3339), nil))
					}
					f.staged.Attestation.GovernanceAttestation = f.staged.Attestation.GovernanceAttestations[0]
					// Ensure an invalid-version denial cannot pass merely because the
					// fixture has forged signatures or a different outer digest.
					if digest != f.staged.Digest || VerifyEnvelopeSignature(f.roots.pub, event) != nil || verifyBundleSignatures(event, f.roots.pub, digest) != nil {
						t.Fatal("version fixture lost genuine signed archive authority")
					}
					for _, attest := range f.staged.Attestation.GovernanceAttestations {
						if verifyGovernanceSigner(f.roots.pub, f.roots.Signers, attest) != nil {
							t.Fatal("version fixture lost genuine reviewer signatures")
						}
					}
					prepared, err := prepareNativeSkillEvidence(f.staged, archive, f.opts())
					if group.accepted {
						if err != nil || prepared == nil {
							t.Fatalf("valid numeric release rejected: %v", err)
						}
					} else if !errors.Is(err, ErrNativeEvidenceInvalid) || prepared != nil {
						t.Fatal("unsupported signed version was accepted or misclassified")
					}
				})
			}
		}
	})
	t.Run("canonicalEntries", func(t *testing.T) {
		entries := nativeSkillEvidenceEntries(t)
		b := &StagedBundle{Name: "retained-skill", Version: "1.0.0", Kind: skillbundle.KindSkill}
		if _, err := strictNativeSkillEntries(entries, b); err != nil {
			t.Fatal(err)
		}
		for _, kind := range []string{"", "skill"} {
			fields := map[string]any{"schema": skillbundle.Schema, "name": b.Name, "version": b.Version, "kind": kind, "depends_on": []any{}}
			raw, _ := json.Marshal(fields)
			if _, err := strictNativeSkillEntries(nativeSkillEvidenceSet(entries, "bundle.json", raw), b); err != nil {
				t.Fatalf("supported kind %q: %v", kind, err)
			}
		}
	})
	t.Run("strictManifestAndDependencyDenials", func(t *testing.T) {
		b := &StagedBundle{Name: "retained-skill", Version: "1.0.0", Kind: skillbundle.KindSkill}
		base := nativeSkillEvidenceEntries(t)
		cases := []struct {
			name, raw  string
			dependency bool
		}{
			{"kindAgent", `{"schema":"m3c-skill-bundle/v1","kind":"agent","name":"retained-skill","version":"1.0.0","depends_on":[]}`, false},
			{"identityBeforeDeps", `{"schema":42,"name":"retained-skill","version":"1.0.0","depends_on":null}`, false},
			{"kindBeforeDeps", `{"schema":"m3c-skill-bundle/v1","kind":"agent","name":"retained-skill","version":"1.0.0","depends_on":[{"kind":"skill","name":"x"}]}`, false},
			{"kindNull", `{"schema":"m3c-skill-bundle/v1","kind":null,"name":"retained-skill","version":"1.0.0","depends_on":[]}`, false},
			{"aliasKind", `{"schema":"m3c-skill-bundle/v1","Kind":"skill","name":"retained-skill","version":"1.0.0","depends_on":[]}`, false},
			{"duplicateName", `{"schema":"m3c-skill-bundle/v1","name":"x","name":"retained-skill","version":"1.0.0","depends_on":[]}`, false},
			{"wrongName", `{"schema":"m3c-skill-bundle/v1","name":"other","version":"1.0.0","depends_on":[]}`, false},
			{"dependencyNull", `{"schema":"m3c-skill-bundle/v1","name":"retained-skill","version":"1.0.0","depends_on":null}`, true},
			{"dependencyMissing", `{"schema":"m3c-skill-bundle/v1","name":"retained-skill","version":"1.0.0"}`, true},
			{"dependencyAlias", `{"schema":"m3c-skill-bundle/v1","name":"retained-skill","version":"1.0.0","depends_on":[],"DependsOn":[]}`, true},
			{"unicodeDependencyAlias", `{"schema":"m3c-skill-bundle/v1","name":"retained-skill","version":"1.0.0","depends_on":[],"dependſ_on":[]}`, true},
			{"unicodeSchemaAlias", `{"schema":"m3c-skill-bundle/v1","ſchema":"m3c-skill-bundle/v1","name":"retained-skill","version":"1.0.0","depends_on":[]}`, false},
			{"packageEmpty", `{"schema":"m3c-skill-bundle/v1","name":"retained-skill","version":"1.0.0","depends_on":[],"package_dependencies":[]}`, true},
			{"dataNull", `{"schema":"m3c-skill-bundle/v1","name":"retained-skill","version":"1.0.0","depends_on":[],"data_dependencies":null}`, true},
			{"dependencyNonempty", `{"schema":"m3c-skill-bundle/v1","name":"retained-skill","version":"1.0.0","depends_on":[{"kind":"skill","name":"x"}]}`, true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := strictNativeSkillEntries(nativeSkillEvidenceSet(base, "bundle.json", []byte(tc.raw)), b)
				if err == nil {
					t.Fatal("invalid signed declaration accepted")
				}
				if tc.dependency && !errors.Is(err, ErrNativeDependenciesUnavailable) {
					t.Fatalf("lost dependency denial: %v", err)
				}
				if !tc.dependency && !errors.Is(err, ErrNativeEvidenceInvalid) {
					t.Fatalf("lost identity/evidence denial priority: %v", err)
				}
			})
		}
	})
	t.Run("entryAndChecksumDenials", func(t *testing.T) {
		b := &StagedBundle{Name: "retained-skill", Version: "1.0.0", Kind: skillbundle.KindSkill}
		base := nativeSkillEvidenceEntries(t)
		mutations := map[string]func([]skillbundle.Entry) []skillbundle.Entry{
			"missingAnchor": func(e []skillbundle.Entry) []skillbundle.Entry {
				for i := range e {
					if e[i].Rel == "SKILL.md" {
						e[i].Rel = "skill.md"
					}
				}
				return e
			},
			"duplicate": func(e []skillbundle.Entry) []skillbundle.Entry { return append(e, e[0]) },
			"proofContext": func(e []skillbundle.Entry) []skillbundle.Entry {
				return append(e, skillbundle.Entry{Rel: AttestationStashName})
			},
			"proofArchive": func(e []skillbundle.Entry) []skillbundle.Entry { return append(e, skillbundle.Entry{Rel: "OTHER.SKB"}) },
			"traversal":    func(e []skillbundle.Entry) []skillbundle.Entry { return append(e, skillbundle.Entry{Rel: "../escape"}) },
			"device": func(e []skillbundle.Entry) []skillbundle.Entry {
				return append(e, skillbundle.Entry{Rel: "references/CON"})
			},
			"fileParent": func(e []skillbundle.Entry) []skillbundle.Entry {
				return append(e, skillbundle.Entry{Rel: "references"})
			},
			"implicitAlias": func(e []skillbundle.Entry) []skillbundle.Entry {
				return append(e, skillbundle.Entry{Rel: "References/b.txt"})
			},
			"unicodeAlias": func(e []skillbundle.Entry) []skillbundle.Entry {
				return append(e, skillbundle.Entry{Rel: "Σ/a"}, skillbundle.Entry{Rel: "ς/b"})
			},
			"checksumMissing": func(e []skillbundle.Entry) []skillbundle.Entry { return nativeSkillEvidenceSet(e, "CHECKSUMS", nil) },
			"checksumUpper": func(e []skillbundle.Entry) []skillbundle.Entry {
				for i := range e {
					if e[i].Rel == "CHECKSUMS" {
						e[i].Content = bytes.ToUpper(e[i].Content)
					}
				}
				return e
			},
			"checksumIncomplete": func(e []skillbundle.Entry) []skillbundle.Entry {
				for i := range e {
					if e[i].Rel == "CHECKSUMS" {
						_, rest, _ := bytes.Cut(e[i].Content, []byte{'\n'})
						e[i].Content = rest
					}
				}
				return e
			},
			"payloadModified": func(e []skillbundle.Entry) []skillbundle.Entry {
				return nativeSkillEvidenceSet(e, "SKILL.md", []byte("changed"))
			},
		}
		for name, mutate := range mutations {
			t.Run(name, func(t *testing.T) {
				e := mutate(append([]skillbundle.Entry(nil), base...))
				if _, err := strictNativeSkillEntries(e, b); err == nil {
					t.Fatal("invalid entries/checksums accepted")
				}
			})
		}
		// Positive after negatives prevents a blanket rejecting validator passing.
		if _, err := strictNativeSkillEntries(base, b); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("effectivePrefixInventoryBoundAndUnicodeLength", func(t *testing.T) {
		base := nativeSkillEvidenceEntries(t)
		// Seven existing explicit/implicit prefixes plus781*128+25=100000.
		for i := 0; i < 781; i++ {
			rel := fmt.Sprintf("p%04d/", i) + strings.Repeat("x/", 126) + "leaf"
			base = append(base, skillbundle.Entry{Rel: rel})
		}
		base = append(base, skillbundle.Entry{Rel: "last/" + strings.Repeat("x/", 23) + "leaf"})
		base = nativeSkillEvidenceChecksumEntries(base)
		b := &StagedBundle{Name: "retained-skill", Version: "1.0.0", Kind: skillbundle.KindSkill}
		if _, err := strictNativeSkillEntries(base, b); err != nil {
			t.Fatalf("100000 effective-prefix positive: %v", err)
		}
		exceeded := nativeSkillEvidenceChecksumEntries(append(append([]skillbundle.Entry(nil), base...), skillbundle.Entry{Rel: "excess"}))
		if _, err := strictNativeSkillEntries(exceeded, b); !errors.Is(err, ErrNativeEvidenceInvalid) {
			t.Fatal("100001 effective prefixes accepted")
		}
		unicodeEntries := nativeSkillEvidenceChecksumEntries(append(nativeSkillEvidenceEntries(t), skillbundle.Entry{Rel: "K/a"}, skillbundle.Entry{Rel: "k/b"}))
		if _, err := strictNativeSkillEntries(unicodeEntries, b); !errors.Is(err, ErrNativeEvidenceInvalid) {
			t.Fatal("UTF8-length-changing case alias accepted")
		}
	})
	t.Run("signedArchiveMismatchAndMissingContext", func(t *testing.T) {
		archive := qaAgentArchive(t, nativeSkillEvidenceEntries(t))
		f := nativeSkillEvidenceFixture(t, archive)
		if p, err := prepareNativeSkillEvidence(f.staged, archive, f.opts()); err != nil || p == nil {
			t.Fatalf("positive: %v", err)
		}
		bad := bytes.Clone(archive)
		bad[0] ^= 1
		if p, err := prepareNativeSkillEvidence(f.staged, bad, f.opts()); err == nil || p != nil {
			t.Fatal("digest mismatch returned prepared input")
		}
		f.staged.Attestation = nil
		if p, err := prepareNativeSkillEvidence(f.staged, archive, f.opts()); err == nil || p != nil {
			t.Fatal("missing context returned prepared input")
		}
	})
	t.Run("signedUnsupportedAndQuorum", func(t *testing.T) {
		entries := nativeSkillEvidenceEntries(t)
		raw := qaAgentArchive(t, entries)
		f := nativeSkillEvidenceFixture(t, raw)
		if p, err := prepareNativeSkillEvidence(f.staged, raw, f.opts()); err != nil || p == nil {
			t.Fatalf("genuine control: %v", err)
		}
		f.staged.Attestation.GovernanceAttestations = f.staged.Attestation.GovernanceAttestations[:1]
		if p, err := prepareNativeSkillEvidence(f.staged, raw, f.opts()); !errors.Is(err, ErrNativeEvidenceInvalid) || p != nil {
			t.Fatal("one reviewer incorrectly met quorum two")
		}
		badManifest := []byte(`{"schema":"m3c-skill-bundle/v1","kind":"agent","name":"retained-skill","version":"1.0.0","depends_on":[]}`)
		badArchive := qaAgentArchive(t, nativeSkillEvidenceSet(entries, "bundle.json", badManifest))
		other := nativeSkillEvidenceFixture(t, badArchive)
		if p, err := prepareNativeSkillEvidence(other.staged, badArchive, other.opts()); !errors.Is(err, ErrNativeEvidenceInvalid) || p != nil {
			t.Fatal("real signatures granted mismatching skill kind")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		opts := other.opts()
		opts.Ctx = ctx
		if p, err := prepareNativeSkillEvidence(other.staged, badArchive, opts); !errors.Is(err, context.Canceled) || p != nil {
			t.Fatal("cancellation cause or nil result lost")
		}
	})
	t.Run("failedFetchIsTerminalBeforeRepeatedCredentialIO", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		ctx := context.Background()
		lease, err := f.journal.acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := lease.Close(); err != nil {
				t.Error(err)
			}
		}()
		session := &NativeLiveSkillSession{journal: f.journal, lease: lease, rootDigest: f.agent.staged.Digest}
		source, err := NewNativeLiveSkillSource(NativeLiveSkillSourceOptions{BaseURL: "https://example.invalid/selected", ContextID: "fixture", AuthMode: "external-env", AuthFamily: "api-key", AuthOrigin: "https://example.invalid:443", TLSMode: "system"})
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		source.reader.readEnv = func(name string) (string, bool) {
			calls++
			if name != "ER1_API_KEY" {
				t.Fatal("wrong selected credential family")
			}
			return "", false
		}
		if candidate, err := source.Fetch(ctx, session); !errors.Is(err, ErrNativeLiveSourceIO) || candidate != nil || calls != 1 || !session.poisoned {
			t.Fatalf("first source failure not checked/terminal: %v calls=%d", err, calls)
		}
		if candidate, err := source.Fetch(ctx, session); !errors.Is(err, ErrNativeSessionUnavailable) || candidate != nil || calls != 1 {
			t.Fatal("repeat source failure retried credential/network IO")
		}
	})
	t.Run("constructorNoCredentialOrSessionGrant", func(t *testing.T) {
		source, err := NewNativeLiveSkillSource(NativeLiveSkillSourceOptions{BaseURL: "https://example.invalid/selected", ContextID: "fixture", AuthMode: "none", TLSMode: "system"})
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		source.reader.readEnv = func(string) (string, bool) { calls++; return "", false }
		if candidate, err := source.Fetch(context.Background(), nil); !errors.Is(err, ErrNativeSessionUnavailable) || candidate != nil || calls != 0 {
			t.Fatal("source without concrete lease performed credential IO or granted candidate")
		}
		agent, err := NewNativeLiveAgentSource(NativeLiveAgentSourceOptions{BaseURL: "https://example.invalid/selected", ContextID: "fixture", AuthMode: "none", TLSMode: "system"})
		if err != nil {
			t.Fatal(err)
		}
		if reflect.DeepEqual(source.bindingID(), agent.bindingID()) {
			t.Fatal("skill binding lost separate kind domain")
		}
	})
}
