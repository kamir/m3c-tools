package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

func TestAgentEvidenceRecordFraming(t *testing.T) {
	archive, contextRaw := []byte("archive"), []byte(`{"a":1}`)
	sum := sha256.Sum256(archive)
	csum := sha256.Sum256(contextRaw)
	h := agentRecordHeader{agentRecordSchema, "agent", "example", "1.0.0", "sha256:" + hex.EncodeToString(sum[:]), 7, 7, hex.EncodeToString(csum[:])}
	var out bytes.Buffer
	if e := writeAgentRecord(&out, h, archive, contextRaw); e != nil {
		t.Fatal(e)
	}
	header := `{"schema":"m3c.agent-retained/v1","kind":"agent","name":"example","version":"1.0.0","bundle_digest":"` + h.BundleDigest + `","archive_bytes":7,"context_bytes":7,"context_sha256":"` + h.ContextSHA256 + `"}`
	expected := append([]byte("M3CAGT1\n"), 0, 0, byte(len(header)>>8), byte(len(header)))
	expected = append(expected, []byte(header+"archive"+string(contextRaw))...)
	if !bytes.Equal(out.Bytes(), expected) {
		t.Fatal("frame differs from independent literal layout")
	}
	r := bytes.NewReader(out.Bytes())
	parsed, e := readAgentRecordHeader(r)
	if e != nil || parsed != h {
		t.Fatalf("read header: %v", e)
	}
	tail, e := io.ReadAll(r)
	if e != nil || !bytes.Equal(tail, append(archive, contextRaw...)) {
		t.Fatal("raw record segments changed")
	}
	for _, bad := range []string{`{"Schema":"m3c.agent-retained/v1"}`, `{"schema":"one","schema":"two"}`, `null`} {
		var prefix [12]byte
		copy(prefix[:8], "M3CAGT1\n")
		binary.BigEndian.PutUint32(prefix[8:], uint32(len(bad)))
		if _, e = readAgentRecordHeader(bytes.NewReader(append(prefix[:], bad...))); e == nil {
			t.Fatal("invalid record header accepted")
		}
	}
	var short bytes.Buffer
	if e = writeAgentRecord(shortAgentWriter{&short}, h, archive, contextRaw); !errors.Is(e, io.ErrShortWrite) {
		t.Fatal("short frame write accepted")
	}
}

type shortAgentWriter struct{ io.Writer }

func (w shortAgentWriter) Write(b []byte) (int, error) {
	if len(b) > 0 {
		return w.Writer.Write(b[:len(b)-1])
	}
	return 0, nil
}

type forbiddenAgentMarshaler struct{ called *bool }

func (m forbiddenAgentMarshaler) MarshalJSON() ([]byte, error) {
	*m.called = true
	return []byte(`null`), nil
}
func TestAgentEvidenceContextSnapshotBounds(t *testing.T) {

	t.Run("malformed-signed-governance", func(t *testing.T) {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
		for _, field := range []string{"reviewer_id", "governance_level", "occurred_at", "expires_at"} {
			b := stagedAgent(t, "shape", makeAgentSkb(t, "shape", nil, skillbundle.SchemaAgent, skillbundle.KindAgent))
			event := b.Attestation.GovernanceAttestation
			if field == "expires_at" {
				event[field] = "invalid"
			} else {
				delete(event, field)
			}
			if _, e := SignEnvelopeSignature(key, event); e != nil {
				t.Fatal(e)
			}
			if e := verifyAgentContext(agentFixtureRoots(), b.Attestation, b.Digest, b.Name, b.Version, time.Now()); e == nil {
				t.Fatal("malformed signed event accepted", field)
			}
		}
	})
	t.Run("unique-effective-names", func(t *testing.T) {
		b := &StagedBundle{Name: "example", Version: "1.0.0", Kind: skillbundle.KindAgent}
		base := []skillbundle.Entry{{Rel: "bundle.json", Content: []byte(`{"schema":"m3c-skill-bundle/v2","kind":"agent","name":"example","version":"1.0.0"}`)}, {Rel: "example.md", Content: []byte("body")}}
		if _, _, e := strictAgentManifest(base, b); e != nil {
			t.Fatal("valid control", e)
		}
		for _, extra := range [][]skillbundle.Entry{
			{{Rel: "CHECKSUMS"}, {Rel: "CHECKSUMS"}},
			{{Rel: "example.md", IsDir: true}},
			{{Rel: "foreign", IsDir: true}},
		} {
			if _, _, e := strictAgentManifest(append(append([]skillbundle.Entry{}, base...), extra...), b); e == nil {
				t.Fatal("duplicate or directory collision accepted")
			}
		}
	})
	if !validAgentName(strings.Repeat("x", 248)) {
		t.Fatal("bounded name edge refused")
	}
	for _, name := range []string{".hidden", strings.Repeat("x", 249), "bad\xff"} {
		if validAgentName(name) {
			t.Fatal("invalid agent name accepted")
		}
	}

	b := stagedAgent(t, "bounded", makeAgentSkb(t, "bounded", nil, skillbundle.SchemaAgent, skillbundle.KindAgent))
	snapshot, raw, e := snapshotAgentContext(b.Attestation)
	if e != nil || len(raw) == 0 {
		t.Fatal(e)
	}
	b.Attestation.AdmitEvent["name"] = "mutated"
	if snapshot.AdmitEvent["name"] != "bounded" {
		t.Fatal("context copy shares mutable map")
	}
	called := false
	b.Attestation.AdmitEvent["bad"] = forbiddenAgentMarshaler{&called}
	if _, _, e = snapshotAgentContext(b.Attestation); e == nil || called {
		t.Fatal("custom marshaler was accepted or executed")
	}
	delete(b.Attestation.AdmitEvent, "bad")
	b.Attestation.AdmitEvent["large"] = strings.Repeat("x", maxAgentContext+1)
	if _, _, e = snapshotAgentContext(b.Attestation); e == nil {
		t.Fatal("large caller context accepted")
	}
	delete(b.Attestation.AdmitEvent, "large")
	cycle := map[string]any{}
	cycle["self"] = cycle
	b.Attestation.AdmitEvent["cycle"] = cycle
	if _, _, e = snapshotAgentContext(b.Attestation); e == nil {
		t.Fatal("cyclic context accepted")
	}
	root := agentFixtureRoots()
	root.GovernanceQuorum = -1
	if _, e = snapshotAgentRoots(root); e == nil {
		t.Fatal("negative quorum accepted")
	}
	root = agentFixtureRoots()
	root.Registry = strings.Repeat("x", 8193)
	if _, e = snapshotAgentRoots(root); e == nil {
		t.Fatal("large root field accepted")
	}
}
func TestAgentEvidencePlatformPublication(t *testing.T) {

	t.Run("portable-filesystem-alias-create", func(t *testing.T) {
		for _, names := range [][]string{{"Σ", "ς"}, {"café", "cafe\u0301"}} {
			skills, agents := homeWith(t)
			probe := t.TempDir()
			first := filepath.Join(probe, names[0]+".md")
			second := filepath.Join(probe, names[1]+".md")
			if e := os.WriteFile(first, []byte("probe"), 0600); e != nil {
				t.Fatal(e)
			}
			_, e := os.Lstat(second)
			aliases := e == nil
			if e != nil && !errors.Is(e, os.ErrNotExist) {
				t.Fatal(e)
			}
			var bundles []*StagedBundle
			for _, name := range names {
				bundles = append(bundles, stagedAgent(t, name, makeAgentSkb(t, name, nil, skillbundle.SchemaAgent, skillbundle.KindAgent)))
			}
			results, e := ConfirmInstall(bundles, "", InstallOpts{SkillsDir: skills, NativeTrustRoots: agentFixtureRoots()})
			if aliases {
				if len(results) != 1 || !errors.Is(e, ErrPlanDrift) || !errors.Is(e, ErrAgentPublicationIncomplete) {
					t.Fatalf("filesystem alias overwrote initial create: %v", e)
				}
				body, err := os.ReadFile(filepath.Join(agents, names[0]+".md"))
				if err != nil || !bytes.Contains(body, []byte("name: "+names[0]+"\n")) {
					t.Fatal("first body lost", err)
				}
			} else if e != nil || len(results) != 2 {
				t.Fatalf("distinct native targets refused: %v", e)
			}
		}
	})
	t.Run("duplicate-batch-target", func(t *testing.T) {
		for _, names := range [][]string{{"duplicate", "duplicate"}, {"Portable", "portable"}} {
			skills, agents := homeWith(t)
			var bundles []*StagedBundle
			for _, name := range names {
				bundles = append(bundles, stagedAgent(t, name, makeAgentSkb(t, name, nil, skillbundle.SchemaAgent, skillbundle.KindAgent)))
			}
			if _, e := ConfirmInstall(bundles, "", InstallOpts{SkillsDir: skills, NativeTrustRoots: agentFixtureRoots()}); !errors.Is(e, ErrAgentEvidenceInvalid) {
				t.Fatal("duplicate batch target accepted", e)
			}
			for _, name := range names {
				if _, e := os.Stat(filepath.Join(agents, name+".md")); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("duplicate batch published before denial", e)
				}
			}
		}
	})

	t.Run("post-publication-directory-close", func(t *testing.T) {
		skills, agents := homeWith(t)
		b := stagedAgent(t, "close-case", makeAgentSkb(t, "close-case", nil, skillbundle.SchemaAgent, skillbundle.KindAgent))
		ops := defaultAgentFileOps()
		realClose := ops.closeDir
		marker := errors.New("synthetic directory close error")
		reached := false
		ops.closeDir = func(r *os.Root) error {
			name := r.Name()
			e := realClose(r)
			if strings.HasSuffix(name, ".provenance") {
				reached = true
				return errors.Join(e, marker)
			}
			return e
		}
		_, e := ConfirmInstall([]*StagedBundle{b}, "", InstallOpts{SkillsDir: skills, NativeTrustRoots: agentFixtureRoots(), agentOps: &ops})
		if !reached || !errors.Is(e, marker) || !errors.Is(e, ErrAgentPublicationIncomplete) {
			t.Fatalf("post-publication close lost uncertainty: %v", e)
		}
		if _, e = os.Stat(filepath.Join(agents, b.Name+".md")); e != nil {
			t.Fatal("control did not actually publish", e)
		}
	})
	t.Run("later-batch-failure", func(t *testing.T) {
		skills, agents := homeWith(t)
		b := stagedAgent(t, "batch-first", makeAgentSkb(t, "batch-first", nil, skillbundle.SchemaAgent, skillbundle.KindAgent))
		bad := &StagedBundle{Name: "batch-second", Version: "1.0.0", Kind: skillbundle.KindSkill, StagedSkbPath: filepath.Join(t.TempDir(), "absent")}
		results, e := ConfirmInstall([]*StagedBundle{b, bad}, "", InstallOpts{SkillsDir: skills, NativeTrustRoots: agentFixtureRoots()})
		if len(results) != 1 || !errors.Is(e, os.ErrNotExist) || !errors.Is(e, ErrAgentPublicationIncomplete) {
			t.Fatalf("later batch failure lost prior publication: %v", e)
		}
		if _, e = os.Stat(filepath.Join(agents, b.Name+".md")); e != nil {
			t.Fatal("control did not actually publish", e)
		}
	})

	for _, fault := range []bool{false, true} {
		t.Run(map[bool]string{false: "positive", true: "short-write"}[fault], func(t *testing.T) {
			skills, agents := homeWith(t)
			b := stagedAgent(t, "publication", makeAgentSkb(t, "publication", nil, skillbundle.SchemaAgent, skillbundle.KindAgent))
			ops := defaultAgentFileOps()
			if fault {
				ops.write = func(*os.File, []byte) (int, error) { return 0, nil }
			}
			result, e := ConfirmInstall([]*StagedBundle{b}, "", InstallOpts{SkillsDir: skills, NativeTrustRoots: agentFixtureRoots(), agentOps: &ops})
			if fault {
				if !errors.Is(e, io.ErrShortWrite) || result != nil {
					t.Fatalf("short write result: %v", e)
				}
				if _, e = os.Stat(filepath.Join(agents, b.Name+".md")); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("active agent appeared after write failure")
				}
				return
			}
			if e != nil || len(result) != 1 {
				t.Fatal(e)
			}
			f, e := os.Open(filepath.Join(agents, agentEvidenceDir, agentRecordName(b.Name)))
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			h, e := readAgentRecordHeader(f)
			if e != nil || h.BundleDigest != b.Digest {
				t.Fatal("published record unreadable")
			}
			raw := make([]byte, h.ArchiveBytes)
			if _, e = io.ReadFull(f, raw); e != nil {
				t.Fatal(e)
			}
			input, e := os.ReadFile(b.StagedSkbPath)
			if e != nil || !bytes.Equal(input, raw) {
				t.Fatal("retained archive bytes changed")
			}
		})
	}
}
func TestAgentEvidenceProcessLock(t *testing.T) {
	if mode := os.Getenv("M3C_AGENT_LOCK_TEST"); mode != "" {
		duration := 5 * time.Second
		if mode == "blocked" {
			duration = 200 * time.Millisecond
		}
		ctx, cancel := context.WithTimeout(context.Background(), duration)
		defer cancel()
		lease, e := acquireAgentPublication(ctx, os.Getenv("M3C_AGENT_LOCK_PATH"), defaultAgentFileOps())
		if mode == "blocked" {
			if !errors.Is(e, context.DeadlineExceeded) {
				t.Fatalf("real child lock not blocked: %v", e)
			}
			return
		}
		if e != nil {
			t.Fatal(e)
		}
		if e = lease.Close(); e != nil {
			t.Fatal(e)
		}
		return
	}
	_, agents := homeWith(t)
	lease, e := acquireAgentPublication(context.Background(), agents, defaultAgentFileOps())
	if e != nil {
		t.Fatal(e)
	}
	defer lease.Close()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	run := func(mode string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestAgentEvidenceProcessLock$")
		cmd.WaitDelay = time.Second
		cmd.Env = append(os.Environ(), "M3C_AGENT_LOCK_TEST="+mode, "M3C_AGENT_LOCK_PATH="+agents)
		if output, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("child %s: %v %s", mode, e, output)
		}
	}
	run("blocked")
	if e = lease.Close(); e != nil {
		t.Fatal(e)
	}
	run("released")
}
