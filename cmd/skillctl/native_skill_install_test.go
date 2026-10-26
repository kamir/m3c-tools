package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

type qaNativeSkillCLILive struct {
	source            *qaNativeSourceCLI
	carrier           *httptest.Server
	archive, markdown []byte
	digest            string
	admit             map[string]any
	attest            []map[string]any
	requests          atomic.Int32
	mu                sync.Mutex
	rows              []map[string]any
}

func qaNativeSkillCLINew(t *testing.T) *qaNativeSkillCLILive {
	t.Helper()
	f := &qaNativeSkillCLILive{source: qaNativeSourceCLIFixture(t)}
	if err := os.MkdirAll(filepath.Join(f.source.base.home, ".claude", "skills"), 0700); err != nil {
		t.Fatal(err)
	}
	f.markdown = []byte("---\nname: live-cli-skill\n---\n\nActual retained canonical native skill.\n")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), f.markdown, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "references"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "references", "inert.txt"), []byte("nested inert fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var packed bytes.Buffer
	if _, err := skillbundle.PackToWriter(dir, &packed, skillbundle.PackOptions{Manifest: skillbundle.BundleManifest{Name: "live-cli-skill", Version: "1.0.0", DependsOn: []skillbundle.Dependency{}}}); err != nil {
		t.Fatal(err)
	}
	f.archive = packed.Bytes()
	sum := sha256.Sum256(f.archive)
	f.digest = "sha256:" + hex.EncodeToString(sum[:])
	key := f.source.base.artifactKey
	fp := sha256.Sum256(key.Public().(ed25519.PublicKey))
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, sum[:]))
	var err error
	f.admit, err = registry.BuildBundleAdmittedEvent(registry.AdmittedEventInput{BundleDigest: f.digest, Name: "live-cli-skill", Version: "1.0.0", AuthorIntent: "green", AdmittedByIdentity: "cli-live-author", AdmittedAt: time.Now().UTC().Add(-time.Minute), Signatures: []registry.SignatureRef{{Role: "author", IdentityID: "cli-live-author", SignatureB64: sig, PubKeyFingerprint: "sha256:" + hex.EncodeToString(fp[:])}, {Role: "registry", IdentityID: "cli-live-author", SignatureB64: sig, PubKeyFingerprint: "sha256:" + hex.EncodeToString(fp[:])}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = registry.SignEnvelopeSignature(key, f.admit); err != nil {
		t.Fatal(err)
	}
	roots := "registry: self\npubkey_b64: " + base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)) + "\ngovernance_minimum: green\ngovernance_quorum: 2\nsigners:\n"
	for _, id := range []string{"cli-live-reviewer-a", "cli-live-reviewer-b"} {
		pk, sk, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		roots += fmt.Sprintf(" - reviewer_id: %s\n   pubkey_b64: %s\n", id, base64.StdEncoding.EncodeToString(pk))
		event, e := registry.BuildAttestationPublishedEvent(registry.AttestedEventInput{BundleDigest: f.digest, ReviewerID: id, GovernanceLevel: "green", Rationale: "actual CLI independent fixture", OccurredAt: time.Now().UTC().Add(-time.Minute)})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = registry.SignEnvelopeSignature(sk, event); e != nil {
			t.Fatal(e)
		}
		f.attest = append(f.attest, event)
	}
	ref := f.source.doc["native"].(map[string]any)["artifact_trust"].(map[string]any)
	path := ref["path"].(string)
	if err = os.WriteFile(path, []byte(roots), 0600); err != nil {
		t.Fatal(err)
	}
	sum = sha256.Sum256([]byte(roots))
	ref["sha256"] = hex.EncodeToString(sum[:])
	for i, event := range append([]map[string]any{f.admit}, f.attest...) {
		raw, e := json.Marshal(event)
		if e != nil {
			t.Fatal(e)
		}
		body := "```json\n" + string(raw) + "\n```\n"
		if i == 0 {
			body += "```skb-base64\n" + base64.StdEncoding.EncodeToString(f.archive) + "\n```\n"
		}
		f.rows = append(f.rows, map[string]any{"doc_id": fmt.Sprintf("cli-live-%d", i), "transcript": body})
	}
	var ca []byte
	f.carrier, ca = qaNativeSourceCLITLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.Method != "GET" || r.ProtoMajor != 1 || r.URL.EscapedPath() != "/bound/base/memory/cli___skills" || r.URL.Query().Get("limit") != "500" || r.URL.Query().Get("range") != "year" || r.Header.Get("Authorization") != "" || r.Header.Get("X-API-Key") != "" || r.Header.Get("Cookie") != "" {
			t.Error("actual CLI live carrier escaped explicit public TLS selection")
		}
		f.mu.Lock()
		rows := f.rows
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"items": rows}); err != nil {
			t.Error(err)
		}
	}))
	caPath := filepath.Join(f.source.base.project, "live-ca.pem")
	if err = os.WriteFile(caPath, ca, 0600); err != nil {
		t.Fatal(err)
	}
	sum = sha256.Sum256(ca)
	f.source.doc["schema"] = "m3c.enterprise-project-profile/v4"
	f.source.doc["native"].(map[string]any)["carrier"] = map[string]any{"kind": "er1", "base_url": f.carrier.URL + "/bound/base", "context_id": "cli___skills", "auth": map[string]any{"mode": "none"}, "tls": map[string]any{"mode": "pinned-pem", "ca": map[string]any{"path": caPath, "sha256": hex.EncodeToString(sum[:])}}}
	f.source.save(t)
	return f
}
func (f *qaNativeSkillCLILive) args() []string {
	return []string{"pull", "--enterprise-profile", f.source.base.path, "--enterprise-profile-sha256", f.source.base.pin, "--home", f.source.base.home, "--kind", "skill", "--digest", f.digest, "--install", "--trust-mode", "--native-session"}
}
func (f *qaNativeSkillCLILive) enroll(t *testing.T, binary, flags string) {
	t.Helper()
	path, _ := c33EnrollEvidence(t, f.source)
	if code, out := qaNativeSourceRun(t, binary, flags, f.source, c33EnrollArgs(f.source, path)); code != 0 {
		t.Fatalf("actual local enrollment prerequisite failed: %d %s", code, out)
	}
}

func qaNativeSkillCLIFrame(t *testing.T, f *qaNativeSkillCLILive) {
	t.Helper()
	target := filepath.Join(f.source.base.home, ".claude", "skills", "live-cli-skill")
	raw, err := os.ReadFile(filepath.Join(target, "live-cli-skill.skb"))
	if err != nil || !bytes.Equal(raw, f.archive) {
		t.Fatal("actual skill lost exact original archive", err)
	}
	raw, err = os.ReadFile(filepath.Join(target, "SKILL.md"))
	if err != nil || !bytes.Equal(raw, f.markdown) {
		t.Fatal("actual skill body changed", err)
	}
	raw, err = os.ReadFile(filepath.Join(target, registry.AttestationStashName))
	if err != nil {
		t.Fatal(err)
	}
	var proof registry.AttestationContext
	if err = json.Unmarshal(raw, &proof); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(proof.AdmitEvent, f.admit) || !reflect.DeepEqual(proof.GovernanceAttestations, f.attest) {
		t.Fatal("actual skill lost full signed context")
	}
}
func TestNativeSkillInstallActualCLI(t *testing.T) {
	if mode := os.Getenv("M3C_NATIVE_SKILL_TEST_OUTPUT_CHILD"); mode != "" {
		var params struct{ Profile, Pin, Home, Digest string }
		if err := json.Unmarshal([]byte(os.Getenv("M3C_NATIVE_SKILL_TEST_OUTPUT_ARGS")), &params); err != nil {
			t.Fatal(err)
		}
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		policy, err := projectpolicy.LoadNativePinned(params.Profile, params.Pin, cwd, params.Home)
		if err != nil {
			t.Fatal(err)
		}
		writer := &c33CLIOutput{mode: mode}
		var diag bytes.Buffer
		code := runNativeSkillPull(context.Background(), &writer.input, writer, &diag, policy, params.Digest)
		if code != 1 {
			t.Fatalf("skill output fault false success: %d %s", code, diag.String())
		}
		if strings.HasPrefix(mode, "final-") && !strings.Contains(diag.String(), "may already have changed") {
			t.Fatal("skill postpublication uncertainty hidden", diag.String())
		}
		return
	}

	t.Run("consent-read-errors-preserve-source-IO", func(t *testing.T) {
		sentinel := errors.New("synthetic consent read fault")
		for _, newline := range []bool{false, true} {
			r := &qaNativeSkillConsentFaultReader{newline: newline, err: sentinel}
			if token, err := readNativeConsentLine(context.Background(), r); token != "" || !errors.Is(err, sentinel) || !errors.Is(err, registry.ErrNativeLiveSourceIO) {
				t.Fatal("concrete reader error became consent denial/success", qaNativeSkillConsentFaultCauses(err))
			}
		}
		if _, err := readNativeConsentLine(context.Background(), strings.NewReader("")); !errors.Is(err, registry.ErrNativeConsentInvalid) {
			t.Fatal("EOF without token did not remain consent refusal", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := readNativeConsentLine(ctx, strings.NewReader("")); !errors.Is(err, context.Canceled) {
			t.Fatal("canceled read lost context", err)
		}
	})
	binary, flags, faultChild := qaNativeSourceBinary(t)
	t.Run("invalid-selected-digest-before-carrier", func(t *testing.T) {
		f := qaNativeSkillCLINew(t)
		f.enroll(t, binary, flags)
		f.requests.Store(0)
		f.source.requests.Store(0)
		f.source.base.requests.Store(0)
		before := qaNativeSkillCLIInventory(t, f.source.base.home)
		args := f.args()
		for i := range args {
			if args[i] == "--digest" {
				args[i+1] = "sha256:not-a-selected-digest"
			}
		}
		if code, out := qaNativeSourceRun(t, binary, flags, f.source, args); code != 12 {
			t.Fatalf("malformed selected digest did not receive trust refusal: %d %s", code, out)
		}
		if f.requests.Load() != 0 || f.source.requests.Load() != 0 || f.source.base.requests.Load() != 0 {
			t.Fatal("malformed selected digest reached network")
		}
		if !reflect.DeepEqual(before, qaNativeSkillCLIInventory(t, f.source.base.home)) {
			t.Fatal("malformed selected digest changed artifact inventory")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := f.source.journal(t).Status(ctx); err != nil {
			t.Fatal("malformed selected digest retained journal lease", err)
		}
	})
	t.Run("explicit-kind-required-before-selection", func(t *testing.T) {
		f := qaNativeSkillCLINew(t)
		f.enroll(t, binary, flags)
		f.requests.Store(0)
		f.source.requests.Store(0)
		f.source.base.requests.Store(0)
		before := nativeCLIQAInventory(t, f.source.base.home)
		args := f.args()
		for i := range args {
			if args[i] == "--kind" {
				args = append(args[:i:i], args[i+2:]...)
				break
			}
		}
		if code, out := qaNativeSourceRun(t, binary, flags, f.source, args); code != 2 {
			t.Fatalf("implicit default kind did not receive usage refusal: %d %s", code, out)
		}
		if f.requests.Load() != 0 || f.source.requests.Load() != 0 || f.source.base.requests.Load() != 0 {
			t.Fatal("implicit default kind reached network")
		}
		if !reflect.DeepEqual(before, nativeCLIQAInventory(t, f.source.base.home)) {
			t.Fatal("implicit default kind changed persisted inventory")
		}
	})
	for _, mode := range []string{"confirm", "crlf", "wrong-token", "close"} {
		t.Run(mode, func(t *testing.T) {
			f := qaNativeSkillCLINew(t)
			f.enroll(t, binary, flags)
			before := qaNativeSkillCLIInventory(t, f.source.base.home)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, f.args()...)
			cmd.WaitDelay = time.Second
			cmd.Dir = f.source.base.project
			cmd.Env = qaNativeSourceEnv(nativeCLIQAEnv(f.source.base.home), "GOFLAGS", flags)
			in, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			out, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var diag strings.Builder
			cmd.Stderr = &diag
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if cmd.ProcessState == nil {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			}()
			reader := bufio.NewScanner(out)
			if !reader.Scan() {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatal("actual skill missing Plan", diag.String())
			}
			var plan struct {
				Type  string
				Rows  []registry.NativeSkillInstallPlanRow
				Token string
			}
			if err = json.Unmarshal(reader.Bytes(), &plan); err != nil {
				t.Fatal(err)
			}
			if plan.Type != "native-skill-plan" || len(plan.Rows) != 1 || plan.Rows[0].Kind != "skill" || plan.Rows[0].Digest != f.digest || len(plan.Token) != 43 {
				t.Fatal("actual skill plan does not bind selected kind/digest", string(reader.Bytes()))
			}
			if !reflect.DeepEqual(before, qaNativeSkillCLIInventory(t, f.source.base.home)) {
				t.Fatal("Plan published before explicit token")
			}
			busy, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
			_, err = f.source.journal(t).Status(busy)
			stop()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("actual skill did not hold journal", err)
			}
			token := plan.Token
			if mode == "wrong-token" {
				token = strings.Repeat("A", 43)
				if token == plan.Token {
					token = strings.Repeat("B", 42) + "A"
				}
			}
			if mode == "close" {
				_ = in.Close()
			} else {
				newline := "\n"
				if mode == "crlf" {
					newline = "\r\n"
				}
				if _, err = in.Write([]byte(token + newline)); err != nil {
					t.Fatal(err)
				}
				_ = in.Close()
			}
			installed := false
			for reader.Scan() {
				var final map[string]any
				if err = json.Unmarshal(reader.Bytes(), &final); err != nil {
					t.Fatal(err)
				}
				if final["type"] == "native-skill-installed" {
					installed = true
				}
			}
			if err = reader.Err(); err != nil {
				t.Fatal(err)
			}
			err = cmd.Wait()
			if mode == "confirm" || mode == "crlf" {
				if err != nil || !installed {
					t.Fatal("actual skill confirm failed", err, diag.String())
				}
				qaNativeSkillCLIFrame(t, f)
			} else {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 12 || installed {
					t.Fatal("actual rejected consent wrong exit", err, diag.String())
				}
				if !reflect.DeepEqual(before, qaNativeSkillCLIInventory(t, f.source.base.home)) {
					t.Fatal("unconfirmed skill published")
				}
			}
			released, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if _, err = f.source.journal(t).Status(released); err != nil {
				t.Fatal("skill journal not released", err)
			}
		})
	}

	for _, mode := range []string{"plan-error", "plan-short", "final-error", "final-short"} {
		t.Run(mode, func(t *testing.T) {
			f := qaNativeSkillCLINew(t)
			f.enroll(t, binary, flags)
			before := qaNativeSkillCLIInventory(t, f.source.base.home)
			params, err := json.Marshal(struct{ Profile, Pin, Home, Digest string }{f.source.base.path, f.source.base.pin, f.source.base.home, f.digest})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, faultChild, "-test.run=^TestNativeSkillInstallActualCLI$")
			cmd.WaitDelay = time.Second
			cmd.Dir = f.source.base.project
			cmd.Env = qaNativeSourceEnv(nativeCLIQAEnv(f.source.base.home), "GOFLAGS", flags)
			cmd.Env = qaNativeSourceEnv(cmd.Env, "M3C_NATIVE_SKILL_TEST_OUTPUT_CHILD", mode)
			cmd.Env = qaNativeSourceEnv(cmd.Env, "M3C_NATIVE_SKILL_TEST_OUTPUT_ARGS", string(params))
			output, err := cmd.CombinedOutput()
			if err != nil || ctx.Err() != nil {
				t.Fatalf("active-provider skill fault child failed: %v %s", err, output)
			}
			if strings.HasPrefix(mode, "plan-") {
				if !reflect.DeepEqual(before, qaNativeSkillCLIInventory(t, f.source.base.home)) {
					t.Fatal("failed Plan output published skill")
				}
			} else {
				qaNativeSkillCLIFrame(t, f)
			}
			released, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if _, err = f.source.journal(t).Status(released); err != nil {
				t.Fatal("fault helper left skill lease held", err)
			}
		})
	}
}

func qaNativeSkillCLIInventory(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		for _, prefix := range []string{filepath.Join(".claude", "native-mutation-state"), filepath.Join(".claude", "skills", ".native-skill")} {
			if rel == prefix || strings.HasPrefix(rel, prefix+string(os.PathSeparator)) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if d.IsDir() {
			out[rel] = "dir"
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[rel] = hex.EncodeToString(raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type qaNativeSkillConsentFaultReader struct {
	newline bool
	err     error
}

func (r *qaNativeSkillConsentFaultReader) Read(p []byte) (int, error) {
	if r.newline && len(p) > 0 {
		p[0] = '\n'
		return 1, r.err
	}
	return 0, r.err
}
func qaNativeSkillConsentFaultCauses(err error) string {
	if err == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%T error", err)
}
