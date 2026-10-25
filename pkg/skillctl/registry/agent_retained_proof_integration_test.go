package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

type qaAgentFixture struct {
	name        string
	registryKey ed25519.PrivateKey
	blob        []byte
	staged      *StagedBundle
	roots       *SelfTrustRoots
	skills      string
	now         time.Time
	admit       map[string]any
	attest      []map[string]any
	signerKeys  []ed25519.PrivateKey
}

func qaAgentSigned(t *testing.T, raw []byte) *qaAgentFixture {
	return qaAgentSignedNamed(t, "retained-agent", raw)
}
func qaAgentSignedNamed(t *testing.T, name string, raw []byte) *qaAgentFixture {
	t.Helper()
	home := registrySnapshotHome(t)
	t.Setenv("M3C_ER1_KEYCHAIN", "off")
	if raw == nil {
		raw = makeAgentSkb(t, name, nil, skillbundle.SchemaAgent, skillbundle.KindAgent)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	admit, digest := mintAdmitItem(t, priv, name, "1.0.0", string(raw))
	event, err := extractEvent(itemBody(admit))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	var signers []Signer
	var attest []map[string]any
	var signerKeys []ed25519.PrivateKey
	for _, id := range []string{"reviewer-a", "reviewer-b"} {
		pk, sk, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		signerKeys = append(signerKeys, sk)
		signers = append(signers, Signer{ReviewerID: id, PubKeyB64: b64(pk), pub: pk})
		attest = append(attest, signedAttest(t, sk, id, digest, "green", now.Add(-time.Minute).Format(time.RFC3339), nil))
	}
	staged := stagedAgent(t, name, raw)
	staged.Kind = skillbundle.KindAgent
	staged.Attestation = &AttestationContext{AdmitEvent: event, GovernanceAttestation: attest[0], GovernanceAttestations: attest}
	return &qaAgentFixture{name: name, registryKey: priv, blob: raw, staged: staged, roots: &SelfTrustRoots{Registry: "self", PubKeyB64: b64(pub), Fingerprint: selfFingerprint(pub), pub: pub, GovernanceMinimum: "green", GovernanceQuorum: 2, Signers: signers}, skills: filepath.Join(home, ".claude", "skills"), now: now, admit: admit, attest: attest, signerKeys: signerKeys}
}

func (f *qaAgentFixture) opts() InstallOpts {
	return InstallOpts{SkillsDir: f.skills, NativeTrustRoots: f.roots, Ctx: context.Background(), agentNow: func() time.Time { return f.now }}
}
func (f *qaAgentFixture) active() string {
	return filepath.Join(agentsDirFor(f.skills), f.name+".md")
}
func (f *qaAgentFixture) record() string {
	return filepath.Join(agentsDirFor(f.skills), ".skillctl-evidence", f.name+".record")
}
func (f *qaAgentFixture) confirm(t *testing.T, opts InstallOpts) ([]*InstallResult, error) {
	t.Helper()
	p, err := PlanInstall([]*StagedBundle{f.staged}, f.skills)
	if err != nil {
		t.Fatal(err)
	}
	return ConfirmInstall([]*StagedBundle{f.staged}, p.Token, opts)
}

type qaAgentRecord struct {
	header     map[string]any
	blob       []byte
	ctx        AttestationContext
	rawContext []byte
}

func qaAgentReadRecord(t *testing.T, path string) qaAgentRecord {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 12 || string(b[:8]) != "M3CAGT1\n" {
		t.Fatal("record framing magic missing")
	}
	n := int(binary.BigEndian.Uint32(b[8:12]))
	if n < 1 || n > 8192 || 12+n > len(b) {
		t.Fatal("invalid record header length")
	}
	var h map[string]any
	if err := json.Unmarshal(b[12:12+n], &h); err != nil {
		t.Fatal(err)
	}
	keys := []string{"schema", "kind", "name", "version", "bundle_digest", "archive_bytes", "context_bytes", "context_sha256"}
	if len(h) != len(keys) {
		t.Fatal("unexpected record header shape")
	}
	for _, k := range keys {
		if _, ok := h[k]; !ok {
			t.Fatalf("missing record selector %s", k)
		}
	}
	if h["schema"] != "m3c.agent-retained/v1" || h["kind"] != "agent" || h["version"] != "1.0.0" {
		t.Fatal("record identity differs")
	}
	a, ok := h["archive_bytes"].(float64)
	if !ok || a <= 0 || a > 256*1024*1024 || a != float64(int64(a)) {
		t.Fatal("archive bound invalid")
	}
	c, ok := h["context_bytes"].(float64)
	if !ok || c <= 0 || c > 1024*1024 || c != float64(int64(c)) {
		t.Fatal("context bound invalid")
	}
	end := 12 + n + int(a)
	if end+int(c) != len(b) {
		t.Fatal("record has truncated or trailing bytes")
	}
	blob := b[12+n : end]
	raw := b[end:]
	sum := sha256.Sum256(blob)
	cs := sha256.Sum256(raw)
	if h["bundle_digest"] != "sha256:"+hex.EncodeToString(sum[:]) || h["context_sha256"] != hex.EncodeToString(cs[:]) {
		t.Fatal("record content hashes differ")
	}
	var ac AttestationContext
	if err := json.Unmarshal(raw, &ac); err != nil {
		t.Fatal(err)
	}
	return qaAgentRecord{h, blob, ac, raw}
}
func qaAgentVerifyRecord(t *testing.T, f *qaAgentFixture) {
	t.Helper()
	r := qaAgentReadRecord(t, f.record())
	if r.header["name"] != f.name {
		t.Fatal("record selected name differs")
	}
	if !bytes.Equal(r.blob, f.blob) {
		t.Fatal("retained archive is not the exact signed input")
	}
	normalizedRaw, err := json.Marshal(f.staged.Attestation)
	if err != nil {
		t.Fatal(err)
	}
	var normalized AttestationContext
	if err := json.Unmarshal(normalizedRaw, &normalized); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.ctx, normalized) {
		t.Fatal("complete native signed context changed or lost an attestation")
	}
	if _, err := r.ctx.ReverifyWithRootsAt(f.roots, r.blob, f.now); err != nil {
		t.Fatalf("retained native signatures fail: %v", err)
	}
	acc := NewAttestAccumulator(f.roots, f.now)
	for _, ev := range r.ctx.GovernanceAttestations {
		acc.OfferAttest(ev)
	}
	q := acc.Qualifying(f.staged.Digest)
	// Exact independent signer count is required in addition to representative verification.
	if len(q) != 2 {
		t.Fatalf("full retained quorum lost: %d", len(q))
	}
	entries, err := skillbundle.Unpack(r.blob, skillbundle.UnpackOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var expected []byte
	for _, e := range entries {
		if e.Rel == f.name+".md" {
			expected = e.Content
		}
	}
	active, err := os.ReadFile(f.active())
	if err != nil || !bytes.Equal(active, expected) {
		t.Fatalf("active body not bound to retained archive: %v", err)
	}
}

func TestAgentRetainedProofSameBytesAndContext(t *testing.T) {
	t.Run("signed-pull-sdk-quorum-retained", func(t *testing.T) {
		f := qaAgentSigned(t, nil)
		fake := newPullFake(t)
		fake.addItem(onAgentShelf(f.admit))
		for i, ev := range f.attest {
			fake.addItem(onAgentShelf(map[string]any{"doc_id": fmt.Sprintf("qa-attest-%d", i), "tags": "m3c-skill-bundle,skill-registry:self,skill-event:attested,skill:retained-agent", "transcript": renderTestEventBody(ev, "attested")}))
		}
		t.Setenv("M3C_SKILL_CACHE_DIR", t.TempDir())
		pulled, err := PullBundles(fake.cfg(), "skills", f.roots, PullOpts{OnlyKind: "agent", Now: f.now})
		if err != nil || len(pulled.Staged) != 1 || len(pulled.Skipped) != 0 {
			t.Fatalf("genuine signed agent pull: %v %+v", err, pulled)
		}
		f.staged = pulled.Staged[0]
		sibling := filepath.Join(f.skills, "retained-agent", "SKILL.md")
		if err := os.MkdirAll(filepath.Dir(sibling), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sibling, []byte("same-name skill unchanged"), 0600); err != nil {
			t.Fatal(err)
		}
		result, err := f.confirm(t, f.opts())
		if err != nil || len(result) != 1 {
			t.Fatalf("signed SDK install: %v", err)
		}
		qaAgentVerifyRecord(t, f)
		if err := os.Remove(f.staged.StagedSkbPath); err != nil {
			t.Fatal(err)
		}
		qaAgentVerifyRecord(t, f)
		b, err := os.ReadFile(sibling)
		if err != nil || string(b) != "same-name skill unchanged" {
			t.Fatal("agent retention changed same-name skill")
		}
		matches, err := filepath.Glob(filepath.Join(agentsDirFor(f.skills), "*.md"))
		if err != nil || len(matches) != 1 || matches[0] != f.active() {
			t.Fatal("loader sees extra markdown staging files")
		}
	})
	t.Run("snapshot-inputs-before-publication", func(t *testing.T) {
		f := qaAgentSigned(t, nil)
		opts := f.opts()
		calls := 0
		ops := defaultAgentFileOps()
		opts.agentOps = &ops
		ops.write = func(file *os.File, b []byte) (int, error) {
			calls++
			if calls == 1 {
				f.roots.PubKeyB64 = "invalid-after-snapshot"
				f.roots.pub = nil
				f.staged.Attestation.GovernanceAttestations = nil
				if err := os.Remove(f.staged.StagedSkbPath); err != nil {
					t.Error(err)
				}
			}
			return file.Write(b)
		}
		originalRoots := *f.roots
		originalCtx := *f.staged.Attestation
		originalCtx.GovernanceAttestations = append([]map[string]any(nil), originalCtx.GovernanceAttestations...)
		result, err := f.confirm(t, opts)
		if err != nil || len(result) != 1 {
			t.Fatalf("captured inputs changed midpublication: %v", err)
		}
		if calls == 0 {
			t.Fatal("mutation seam not reached")
		}
		f.roots = &originalRoots
		f.staged.Attestation = &originalCtx
		qaAgentVerifyRecord(t, f)
	})
}

func TestAgentRetainedProofIdentityAndBounds(t *testing.T) {
	for _, mode := range []string{"missing-roots", "missing-context", "foreign-roots", "partial-quorum", "forged-governance", "foreign-digest", "expired", "kind-consent", "empty-kind", "version-mismatch", "context-depth", "custom-marshaler", "cyclic-context", "context-bytes", "root-signers"} {
		t.Run(mode, func(t *testing.T) {
			f := qaAgentSigned(t, nil)
			opts := f.opts()
			switch mode {
			case "missing-roots":
				opts.NativeTrustRoots = nil
			case "missing-context":
				f.staged.Attestation = nil
			case "foreign-roots":
				pub, _, err := ed25519.GenerateKey(nil)
				if err != nil {
					t.Fatal(err)
				}
				f.roots.pub = pub
				f.roots.PubKeyB64 = b64(pub)
				f.roots.Fingerprint = selfFingerprint(pub)
			case "partial-quorum":
				f.staged.Attestation.GovernanceAttestations = f.attest[:1]
			case "forged-governance":
				f.attest[1]["rationale"] = "changed after signature"
			case "foreign-digest":
				f.staged.Attestation.AdmitEvent["bundle_digest"] = "sha256:" + strings.Repeat("0", 64)
			case "expired":
				f.attest[0]["expires_at"] = f.now.Add(-time.Second).Format(time.RFC3339)
				if _, err := SignEnvelopeSignature(f.signerKeys[0], f.attest[0]); err != nil {
					t.Fatal(err)
				}
			case "kind-consent":
				f.staged.Kind = "skill"
			case "empty-kind":
				f.staged.Kind = ""
			case "version-mismatch":
				f.staged.Version = "9.0.0"
			case "context-depth":
				var v any = "leaf"
				for range 129 {
					v = []any{v}
				}
				f.staged.Attestation.AdmitEvent["deep"] = v
			case "custom-marshaler":
				f.staged.Attestation.AdmitEvent["custom"] = qaAgentForbiddenMarshal{t}
			case "cyclic-context":
				f.staged.Attestation.AdmitEvent["self"] = f.staged.Attestation.AdmitEvent
			case "context-bytes":
				f.staged.Attestation.AdmitEvent["oversize"] = strings.Repeat("x", 1024*1024+1)
			case "root-signers":
				f.roots.Signers = make([]Signer, 257)
			}
			result, err := f.confirm(t, opts)
			if err == nil || len(result) != 0 {
				t.Fatal("invalid native proof published")
			}
			if mode == "missing-roots" || mode == "missing-context" {
				if !errors.Is(err, ErrAgentEvidenceRequired) || !strings.Contains(strings.ToLower(err.Error()), "re") {
					t.Fatalf("missing proof lacks migration classification: %v", err)
				}
			}
			for _, path := range []string{f.active(), f.record(), filepath.Join(agentsDirFor(f.skills), ".provenance", "retained-agent.json")} {
				if _, e := os.Lstat(path); !os.IsNotExist(e) {
					t.Fatalf("denied proof wrote selected destination %s: %v", filepath.Base(path), e)
				}
			}
		})
	}
	for _, mode := range []string{"evidence-directory-file", "provenance-directory-file", "active-hardlink", "record-hardlink", "provenance-hardlink"} {
		t.Run(mode, func(t *testing.T) {
			f := qaAgentSigned(t, nil)
			agents := agentsDirFor(f.skills)
			if err := os.MkdirAll(agents, 0700); err != nil {
				t.Fatal(err)
			}
			external := filepath.Join(t.TempDir(), "unchanged.txt")
			original := []byte("outside marker remains unchanged")
			if err := os.WriteFile(external, original, 0600); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "evidence-directory-file":
				if err := os.WriteFile(filepath.Join(agents, ".skillctl-evidence"), original, 0600); err != nil {
					t.Fatal(err)
				}
			case "provenance-directory-file":
				if err := os.WriteFile(filepath.Join(agents, ".provenance"), original, 0600); err != nil {
					t.Fatal(err)
				}
			case "active-hardlink":
				if err := os.Link(external, f.active()); err != nil {
					t.Fatal(err)
				}
			case "provenance-hardlink":
				prov := filepath.Join(agents, ".provenance", "retained-agent.json")
				if err := os.MkdirAll(filepath.Dir(prov), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(external, prov); err != nil {
					t.Fatal(err)
				}
			case "record-hardlink":
				if err := os.MkdirAll(filepath.Dir(f.record()), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(external, f.record()); err != nil {
					t.Fatal(err)
				}
			}
			result, err := f.confirm(t, f.opts())
			if err == nil || len(result) != 0 {
				t.Fatal("linked or non-directory publication target accepted")
			}
			b, e := os.ReadFile(external)
			if e != nil || !bytes.Equal(b, original) {
				t.Fatal("refusal changed unrelated link target")
			}
		})
	}
	for _, mode := range []string{"alias-kind", "alias-name", "alias-version", "alias-schema", "alias-depends", "invalid-utf8", "extra-file", "manifest-cap", "duplicate-checksums", "directory-collision"} {
		t.Run(mode, func(t *testing.T) {
			raw := makeAgentSkb(t, "retained-agent", nil, skillbundle.SchemaAgent, skillbundle.KindAgent)
			entries, err := skillbundle.Unpack(raw, skillbundle.UnpackOptions{})
			if err != nil {
				t.Fatal(err)
			}
			for i := range entries {
				if entries[i].Rel == "bundle.json" {
					switch mode {
					case "alias-kind":
						entries[i].Content = []byte(`{"schema":"m3c-skill-bundle/v2","kind":"agent","Kind":"agent","name":"retained-agent","version":"1.0.0"}`)
					case "alias-name":
						entries[i].Content = []byte(`{"schema":"m3c-skill-bundle/v2","kind":"agent","name":"retained-agent","Name":"retained-agent","version":"1.0.0"}`)
					case "alias-version", "alias-schema", "alias-depends":
						alias := map[string]string{"alias-version": "Version", "alias-schema": "Schema", "alias-depends": "Depends_On"}[mode]
						entries[i].Content = []byte(`{"schema":"m3c-skill-bundle/v2","kind":"agent","name":"retained-agent","version":"1.0.0","` + alias + `":"ambiguous"}`)
						if mode == "alias-depends" {
							entries[i].Content = []byte(`{"schema":"m3c-skill-bundle/v2","kind":"agent","name":"retained-agent","version":"1.0.0","depends_on":[],"Depends_On":[]}`)
						}
					case "manifest-cap":
						entries[i].Content = []byte(`{"schema":"m3c-skill-bundle/v2","kind":"agent","name":"retained-agent","version":"1.0.0","padding":"` + strings.Repeat("x", 1024*1024) + `"}`)
					case "invalid-utf8":
						entries[i].Content = append([]byte(`{"schema":"m3c-skill-bundle/v2","kind":"agent","name":"retained-agent","version":"1.0.0","x":"`), append([]byte{0xff}, []byte(`"}`)...)...)
					}
				}
			}
			if mode == "duplicate-checksums" {
				entries = append(entries, skillbundle.Entry{Rel: "CHECKSUMS"}, skillbundle.Entry{Rel: "CHECKSUMS"})
			}
			if mode == "directory-collision" {
				entries = append(entries, skillbundle.Entry{Rel: "retained-agent.md", IsDir: true})
			}
			if mode == "extra-file" {
				raw = makeAgentSkb(t, "retained-agent", map[string]string{"extra.md": "not allowed"}, skillbundle.SchemaAgent, skillbundle.KindAgent)
			} else {
				raw = qaAgentArchive(t, entries)
			}
			f := qaAgentSigned(t, raw)
			result, err := ConfirmInstall([]*StagedBundle{f.staged}, "", f.opts())
			if err == nil || len(result) != 0 {
				t.Fatal("ambiguous signed manifest published")
			}
			if _, e := os.Lstat(f.active()); !os.IsNotExist(e) {
				t.Fatal("ambiguous manifest changed active body")
			}
		})
	}
}

type qaAgentForbiddenMarshal struct{ t *testing.T }

func (x qaAgentForbiddenMarshal) MarshalJSON() ([]byte, error) {
	x.t.Error("custom marshaler executed before primitive validation")
	return []byte(`null`), nil
}

func TestAgentRetainedProofPublicationFailures(t *testing.T) {
	for _, fault := range []string{"short-write", "write", "sync", "close", "snapshot-close", "replace-first", "replace-second", "replace-third", "sync-parent", "cleanup", "provenance-close"} {
		t.Run(fault, func(t *testing.T) {
			f := qaAgentSigned(t, nil)
			if result, err := f.confirm(t, f.opts()); err != nil || len(result) != 1 {
				t.Fatalf("positive prerequisite: %v", err)
			}
			oldRecord, err := os.ReadFile(f.record())
			if err != nil {
				t.Fatal(err)
			}
			oldBody, err := os.ReadFile(f.active())
			if err != nil {
				t.Fatal(err)
			}
			entries, err := skillbundle.Unpack(f.blob, skillbundle.UnpackOptions{})
			if err != nil {
				t.Fatal(err)
			}
			for i := range entries {
				if entries[i].Rel == "retained-agent.md" {
					entries[i].Content = []byte("New signed publication body.\n")
				}
			}
			next := qaAgentSigned(t, qaAgentArchive(t, entries))
			next.skills = f.skills
			f = next
			opts := f.opts()
			injected := errors.New("synthetic agent I/O failure")
			fired := false
			replaces := 0
			defaults := defaultAgentFileOps()
			ops := &defaults
			switch fault {
			case "short-write":
				ops.write = func(_ *os.File, b []byte) (int, error) { fired = true; return len(b) - 1, nil }
			case "write":
				ops.write = func(*os.File, []byte) (int, error) { fired = true; return 0, injected }
			case "sync":
				ops.sync = func(*os.File) error { fired = true; return injected }
			case "close":
				ops.close = func(file *os.File) error { fired = true; return errors.Join(file.Close(), injected) }
			case "snapshot-close":
				ops.snapshotClose = func(file *os.File) error { fired = true; return errors.Join(file.Close(), injected) }
			case "replace-first", "replace-second", "replace-third":
				which := map[string]int{"replace-first": 1, "replace-second": 2, "replace-third": 3}[fault]
				ops.replace = func(a, b string) error {
					replaces++
					if replaces == which {
						fired = true
						return injected
					}
					return replaceAgentFile(a, b)
				}
			case "sync-parent":
				ops.replace = func(a, b string) error { replaces++; return replaceAgentFile(a, b) }
				ops.syncParent = func(path string) error {
					if replaces > 0 {
						fired = true
						return injected
					}
					return syncAgentParent(path)
				}
			case "provenance-close":
				ops.closeDir = func(root *os.Root) error {
					err := root.Close()
					if filepath.Base(root.Name()) == ".provenance" {
						fired = true
						return errors.Join(err, injected)
					}
					return err
				}
			case "cleanup":
				ops.removeAll = func(path string) error { fired = true; return errors.Join(os.RemoveAll(path), injected) }
			}
			opts.agentOps = ops
			result, err := f.confirm(t, opts)
			if !fired {
				t.Fatal("fault seam not exercised")
			}
			if err == nil || len(result) != 0 {
				t.Fatal("failed checked publication reported success")
			}
			if fault == "short-write" {
				if !errors.Is(err, io.ErrShortWrite) {
					t.Fatalf("shortwrite classification lost: %v", err)
				}
			} else if !errors.Is(err, injected) {
				t.Fatalf("I/O cause lost: %v", err)
			}
			if fault == "short-write" || fault == "write" || fault == "sync" || fault == "close" || fault == "snapshot-close" || fault == "replace-first" {
				b, e := os.ReadFile(f.active())
				r, re := os.ReadFile(f.record())
				if e != nil || re != nil || !bytes.Equal(b, oldBody) || !bytes.Equal(r, oldRecord) {
					t.Fatal("prepublication fault changed old complete pair")
				}
			}
			if fault == "replace-second" || fault == "replace-third" || fault == "sync-parent" || fault == "cleanup" || fault == "provenance-close" {
				if !errors.Is(err, ErrAgentPublicationIncomplete) {
					t.Fatalf("postpublication outcome not classified uncertain: %v", err)
				}
			}
			// A failed operation must release the real lock; another cooperating install can complete.
			if _, err := f.confirm(t, f.opts()); err != nil {
				t.Fatalf("failure leaked held publication lock: %v", err)
			}
		})
	}
	for _, timing := range []string{"before-write", "after-first-replace"} {
		t.Run("cancellation-"+timing, func(t *testing.T) {
			f := qaAgentSigned(t, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			opts := f.opts()
			opts.Ctx = ctx
			ops := defaultAgentFileOps()
			opts.agentOps = &ops
			replaces := 0
			if timing == "before-write" {
				cancel()
			} else {
				ops.replace = func(a, b string) error {
					err := replaceAgentFile(a, b)
					if err == nil {
						replaces++
						cancel()
					}
					return err
				}
			}
			result, err := f.confirm(t, opts)
			if err == nil || len(result) != 0 || !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled publication result: %v", err)
			}
			if timing == "before-write" {
				if _, e := os.Lstat(f.active()); !os.IsNotExist(e) {
					t.Fatal("pre-cancelled invocation published")
				}
			} else if replaces != 1 || !errors.Is(err, ErrAgentPublicationIncomplete) {
				t.Fatalf("postreplace cancellation not uncertain: %v", err)
			}
		})
	}
	for _, pair := range [][2]string{{"Σ", "ς"}, {"café", "cafe\u0301"}} {
		t.Run("actual-filesystem-alias-"+pair[0], func(t *testing.T) {
			first := qaAgentSignedNamed(t, pair[0], nil)
			secondBlob := makeAgentSkb(t, pair[1], map[string]string{}, skillbundle.SchemaAgent, skillbundle.KindAgent)
			admitItem, digest := mintAdmitItem(t, first.registryKey, pair[1], "1.0.0", string(secondBlob))
			admit, err := extractEvent(itemBody(admitItem))
			if err != nil {
				t.Fatal(err)
			}
			var attest []map[string]any
			for i, key := range first.signerKeys {
				attest = append(attest, signedAttest(t, key, first.roots.Signers[i].ReviewerID, digest, "green", first.now.Add(-time.Minute).Format(time.RFC3339), nil))
			}
			second := stagedAgent(t, pair[1], secondBlob)
			second.Kind = "agent"
			second.Attestation = &AttestationContext{AdmitEvent: admit, GovernanceAttestation: attest[0], GovernanceAttestations: attest}
			// Measure the actual destination filesystem; GOOS alone is not an alias oracle.
			if err := os.MkdirAll(filepath.Dir(agentsDirFor(first.skills)), 0700); err != nil {
				t.Fatal(err)
			}
			probe, err := os.MkdirTemp(filepath.Dir(agentsDirFor(first.skills)), "qa-alias-")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.RemoveAll(probe); err != nil {
					t.Error(err)
				}
			}()
			p1, p2 := filepath.Join(probe, pair[0]+".md"), filepath.Join(probe, pair[1]+".md")
			if err := os.WriteFile(p1, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			handle, createErr := os.OpenFile(p2, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			aliased := errors.Is(createErr, os.ErrExist)
			if createErr != nil && !aliased {
				t.Fatalf("filesystem alias prerequisite failed: %v", createErr)
			}
			if handle != nil {
				if err := handle.Close(); err != nil {
					t.Fatal(err)
				}
			}
			i1, e1 := os.Stat(p1)
			i2, e2 := os.Stat(p2)
			if e1 != nil || e2 != nil || os.SameFile(i1, i2) != aliased {
				t.Fatal("alias measurement lacks exact file identity")
			}
			batch := []*StagedBundle{first.staged, second}
			plan, err := PlanInstall(batch, first.skills)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Creates) != 2 {
				t.Fatal("initial fixture plan is not two creates")
			}
			result, err := ConfirmInstall(batch, plan.Token, first.opts())
			if aliased {
				if !errors.Is(err, ErrPlanDrift) || !errors.Is(err, ErrAgentPublicationIncomplete) {
					t.Fatalf("actual filesystem alias did not preserve partial-state refusal: %v", err)
				}
				qaAgentVerifyRecord(t, first)
				actual, readErr := os.ReadFile(first.active())
				if readErr != nil || !bytes.Contains(actual, []byte(pair[0])) {
					t.Fatal("later alias overwrote first active body")
				}
				t.Log("Actual filesystem aliases names: second publication refused; first retained signed proof remains valid")
			} else {
				if err != nil || len(result) != 2 {
					t.Fatalf("distinct filesystem names should both publish: %v", err)
				}
				qaAgentVerifyRecord(t, first)
				f2 := &qaAgentFixture{name: pair[1], blob: secondBlob, staged: second, roots: first.roots, skills: first.skills, now: first.now}
				qaAgentVerifyRecord(t, f2)
				t.Log("Actual filesystem distinguishes names: both genuine signed publications verified")
			}
		})
	}
	t.Run("concurrent-same-name-consent", func(t *testing.T) {
		f := qaAgentSigned(t, nil)
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := ConfirmInstall([]*StagedBundle{f.staged}, "", f.opts())
				results <- err
			}()
		}
		wg.Wait()
		close(results)
		success, denied := 0, 0
		for err := range results {
			if err == nil {
				success++
			} else if errors.Is(err, ErrTokenRequired) {
				denied++
			} else {
				t.Fatalf("unexpected concurrent result: %v", err)
			}
		}
		if success != 1 || denied != 1 {
			t.Fatalf("cooperating concurrent creates bypassed consent: success%d denied%d", success, denied)
		}
		qaAgentVerifyRecord(t, f)
	})
}

func qaAgentArchive(t *testing.T, entries []skillbundle.Entry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		kind := byte(tar.TypeReg)
		if e.IsDir {
			kind = tar.TypeDir
		}
		if err := tw.WriteHeader(&tar.Header{Name: e.Rel, Size: int64(len(e.Content)), Mode: 0600, Typeflag: kind}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.Content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
