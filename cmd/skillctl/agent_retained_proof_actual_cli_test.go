package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

func TestPullInstallAgentRetainedProofActualCLI(t *testing.T) {
	binaryPath := skillctlBin(t)
	for _, mode := range []string{"signed-full-quorum", "missing-quorum", "forged-admit", "unknown-kind"} {
		t.Run(mode, func(t *testing.T) {
			credentialBytes := make([]byte, 64)
			if _, err := rand.Read(credentialBytes); err != nil {
				t.Fatal("generate synthetic credentials")
			}
			apiKey := hex.EncodeToString(credentialBytes[:32])
			bearer := hex.EncodeToString(credentialBytes[32:])
			home := t.TempDir()
			cwd := t.TempDir()
			cache := t.TempDir()
			skills := filepath.Join(home, ".claude", "skills")
			name := "retained-cli-agent"
			source := t.TempDir()
			body := []byte("---\nname: retained-cli-agent\n---\nSynthetic retained agent.\n")
			if err := os.WriteFile(filepath.Join(source, name+".md"), body, 0600); err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(t.TempDir(), "agent.skb")
			_, err := skillbundle.Pack(source, archive, skillbundle.PackOptions{Manifest: skillbundle.BundleManifest{Schema: skillbundle.SchemaAgent, Kind: skillbundle.KindAgent, Name: name, Version: "1.0.0"}})
			if err != nil {
				t.Fatal(err)
			}
			blob, err := os.ReadFile(archive)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(blob)
			digest := "sha256:" + hex.EncodeToString(sum[:])
			pub, key, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			fp := sha256.Sum256(pub)
			fingerprint := "sha256:" + hex.EncodeToString(fp[:])
			sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, sum[:]))
			now := time.Now().UTC()
			admit, err := registry.BuildBundleAdmittedEvent(registry.AdmittedEventInput{BundleDigest: digest, Name: name, Version: "1.0.0", AuthorIntent: "green", AdmittedByIdentity: "id:fixture@m3c", AdmittedAt: now.Add(-time.Minute), Signatures: []registry.SignatureRef{{Role: "author", IdentityID: "id:fixture@m3c", SignatureB64: sig, PubKeyFingerprint: fingerprint}, {Role: "registry", IdentityID: "id:fixture@m3c", SignatureB64: sig, PubKeyFingerprint: fingerprint}}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := registry.SignEnvelopeSignature(key, admit); err != nil {
				t.Fatal(err)
			}
			roots := fmt.Sprintf("registry: self\npubkey_b64: %s\nfingerprint: %s\ngovernance_minimum: green\ngovernance_quorum: 2\nsigners:\n", base64.StdEncoding.EncodeToString(pub), fingerprint)
			items := []map[string]any{}
			tags := "m3c-skill-bundle,skb-transport-version:1,skill-registry:self,agent-registry:self,kind:agent,skill:" + name + ",skill-version:" + name + "@1.0.0,skill-digest:" + digest
			if mode == "forged-admit" {
				admit["name"] = "after-signature-change"
			}
			raw, err := json.Marshal(admit)
			if err != nil {
				t.Fatal(err)
			}
			items = append(items, map[string]any{"doc_id": "qa-agent-admit", "tags": tags + ",skill-event:admitted,governance:green,transport:er1-inline", "transcript": "# admit\n```json\n" + string(raw) + "\n```\n```skb-base64\n" + base64.StdEncoding.EncodeToString(blob) + "\n```\n"})
			for i, id := range []string{"cli-reviewer-a", "cli-reviewer-b"} {
				pk, sk, e := ed25519.GenerateKey(nil)
				if e != nil {
					t.Fatal(e)
				}
				roots += fmt.Sprintf("  - reviewer_id: %s\n    pubkey_b64: %s\n", id, base64.StdEncoding.EncodeToString(pk))
				ev, e := registry.BuildAttestationPublishedEvent(registry.AttestedEventInput{BundleDigest: digest, ReviewerID: id, GovernanceLevel: "green", Rationale: "synthetic signed fixture", OccurredAt: now.Add(-time.Minute)})
				if e != nil {
					t.Fatal(e)
				}
				if _, e = registry.SignEnvelopeSignature(sk, ev); e != nil {
					t.Fatal(e)
				}
				b, e := json.Marshal(ev)
				if e != nil {
					t.Fatal(e)
				}
				if mode != "missing-quorum" || i == 0 {
					items = append(items, map[string]any{"doc_id": fmt.Sprintf("qa-agent-attest-%d", i), "tags": tags + ",skill-event:attested,governance:green", "transcript": "# attested\n```json\n" + string(b) + "\n```\n"})
				}
			}
			rootPath := filepath.Join(t.TempDir(), "native-roots.yaml")
			if err := os.WriteFile(rootPath, []byte(roots), 0600); err != nil {
				t.Fatal(err)
			}
			tr, err := registry.LoadSelfTrustRoots(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			var requests, wrongHeader atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Header.Get("Authorization") != "Bearer "+bearer || r.Header.Get("X-API-Key") != "" {
					wrongHeader.Add(1)
				}
				if !strings.HasPrefix(r.URL.Path, "/memory/") {
					t.Errorf("unexpected synthetic request %s", r.URL.Path)
					w.WriteHeader(404)
					return
				}
				query := r.URL.Query().Get("tags")
				var out []map[string]any
				for _, item := range items {
					match := true
					for _, tag := range strings.Split(query, ",") {
						if tag != "" && !strings.Contains(item["tags"].(string), tag) {
							match = false
						}
					}
					if match {
						out = append(out, item)
					}
				}
				if err := json.NewEncoder(w).Encode(map[string]any{"items": out}); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			args := []string{"pull", "--registry", "self", "--kind", "agent", "--er1-target", server.URL, "--er1-context", "synthetic-agent-fixture", "--trust-roots", rootPath, "--skill", name, "--skills-dir", skills, "--no-checkpoint"}
			if mode == "unknown-kind" {
				args[4] = "unknown-kind"
			}
			run := func(extra ...string) (int, string, string) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, binaryPath, append(append([]string{}, args...), extra...)...)
				cmd.WaitDelay = time.Second
				cmd.Dir = cwd
				cmd.Env = qaAgentCLIEnv(home, cache, apiKey, bearer)
				var stdout, stderr bytes.Buffer
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr
				err := cmd.Run()
				if ctx.Err() != nil {
					t.Fatal("actual CLI timed out")
				}
				code := 0
				if err != nil {
					exit, ok := err.(*exec.ExitError)
					if !ok {
						t.Fatal(err)
					}
					code = exit.ExitCode()
				}
				if strings.Contains(stdout.String(), apiKey) || strings.Contains(stderr.String(), apiKey) || strings.Contains(stdout.String(), bearer) || strings.Contains(stderr.String(), bearer) {
					t.Fatal("synthetic key reflected")
				}
				return code, stdout.String(), stderr.String()
			}
			code, stdout, stderr := run("--install", "--trust-mode")
			active := filepath.Join(home, ".claude", "agents", name+".md")
			record := filepath.Join(home, ".claude", "agents", ".skillctl-evidence", name+".record")
			if mode != "signed-full-quorum" {
				if code == 0 {
					t.Fatal("invalid actual CLI agent install succeeded")
				}
				if mode == "unknown-kind" && (code != 2 || requests.Load() != 0) {
					t.Fatal("unknown kind reached external source before usage refusal")
				}
				for _, p := range []string{active, record} {
					if _, err := os.Lstat(p); !os.IsNotExist(err) {
						t.Fatal("refused agent created active/evidence")
					}
				}
				return
			}
			if code != 0 {
				t.Fatalf("actual signed agent install exit%d: %s %s", code, stdout, stderr)
			}
			if requests.Load() == 0 || wrongHeader.Load() != 0 {
				t.Fatal("synthetic transport not used with selected fixture key")
			}
			verify := func() {
				b, err := os.ReadFile(active)
				if err != nil || !bytes.Equal(b, body) {
					t.Fatalf("actual CLI body differs: %v", err)
				}
				wire, err := os.ReadFile(record)
				if err != nil || len(wire) < 12 || string(wire[:8]) != "M3CAGT1\n" {
					t.Fatal("actual CLI missing framed retained record")
				}
				n := int(binary.BigEndian.Uint32(wire[8:12]))
				if n < 1 || n > 8192 || 12+n > len(wire) {
					t.Fatal("CLI record header bound")
				}
				var h struct {
					ArchiveBytes int    `json:"archive_bytes"`
					ContextBytes int    `json:"context_bytes"`
					ContextSHA   string `json:"context_sha256"`
				}
				if err := json.Unmarshal(wire[12:12+n], &h); err != nil {
					t.Fatal(err)
				}
				off := 12 + n + h.ArchiveBytes
				if h.ArchiveBytes != len(blob) || h.ContextBytes < 1 || off+h.ContextBytes != len(wire) || !bytes.Equal(wire[12+n:off], blob) {
					t.Fatal("actual CLI did not retain exact archive/context")
				}
				cs := sha256.Sum256(wire[off:])
				if h.ContextSHA != hex.EncodeToString(cs[:]) {
					t.Fatal("context digest mismatch")
				}
				var ac registry.AttestationContext
				if err := json.Unmarshal(wire[off:], &ac); err != nil {
					t.Fatal(err)
				}
				acc := registry.NewAttestAccumulator(tr, now)
				for _, ev := range ac.GovernanceAttestations {
					acc.OfferAttest(ev)
				}
				if len(acc.Qualifying(digest)) != 2 {
					t.Fatal("retained CLI quorum signatures not independently valid")
				}
				if len(ac.GovernanceAttestations) != 2 {
					t.Fatal("actual CLI lost complete NofM set")
				}
				if _, err := ac.ReverifyWithRootsAt(tr, blob, now); err != nil {
					t.Fatalf("retained actual CLI native signature fails: %v", err)
				}
			}
			verify()
			before, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			code, _, _ = run("--confirm-install")
			if code == 0 {
				t.Fatal("overwrite without plan token succeeded")
			}
			after, err := os.ReadFile(record)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("missing overwrite consent changed evidence")
			}
			code, plan, diagnostic := run("--dry-run-install")
			if code != 0 {
				t.Fatalf("actual dryrun exit%d: %s", code, diagnostic)
			}
			match := regexp.MustCompile(`dry-run-install token \(5-minute TTL\): ([^\s]+)`).FindStringSubmatch(plan)
			if len(match) != 2 {
				t.Fatalf("dryrun omitted actual token: %s", plan)
			}
			code, _, stderr = run("--confirm-install", "--dry-run-install-token", match[1])
			if code != 0 {
				t.Fatalf("actual token confirm exit%d: %s", code, stderr)
			}
			verify()
		})
	}
}

func qaAgentCLIEnv(home, cache, apiKey, bearer string) []string {
	var result []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "ER1_") || strings.HasPrefix(key, "M3C_") || key == "HOME" || key == "USERPROFILE" || strings.HasSuffix(strings.ToUpper(key), "_PROXY") {
			continue
		}
		result = append(result, entry)
	}
	return append(result, "HOME="+home, "USERPROFILE="+home, "M3C_SKILL_CACHE_DIR="+cache, "M3C_ER1_KEYCHAIN=off", "M3C_TEST_KEYCHAIN=0", "M3C_TOKEN_STORE=keychain", "ER1_API_KEY="+apiKey, "ER1_DEVICE_TOKEN="+bearer, "ER1_CONTEXT_ID=synthetic-agent-fixture")
}
